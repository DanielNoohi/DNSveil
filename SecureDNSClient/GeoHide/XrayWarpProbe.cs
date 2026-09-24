using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SecureDNSClient.GeoHide;

internal sealed record XrayWarpProbeResult(WarpExitCheck.Report Exit, int LatencyMs, bool UdpOk)
{
    internal bool TunnelOk => (Exit.IPv4.WarpOn == true || Exit.IPv6.WarpOn == true) &&
        Exit.IPv4.WarpOn != false && Exit.IPv6.WarpOn != false;
    internal string Summary => $"HTTPS {LatencyMs} ms; UDP DNS {(UdpOk ? "passed" : "not verified")}. {Exit.Summary}";
}

internal static class XrayWarpProbe
{
    internal static HttpClient CreateClient(int port, string user, string password)
    {
        var proxy = new WebProxy($"socks5://127.0.0.1:{port}") { Credentials = new NetworkCredential(user, password) };
        return new HttpClient(new SocketsHttpHandler { Proxy = proxy, UseProxy = true, AllowAutoRedirect = false,
            UseCookies = false, ConnectTimeout = TimeSpan.FromSeconds(5) }) { Timeout = TimeSpan.FromSeconds(8) };
    }

    internal static async Task<XrayWarpProbeResult> FetchAsync(int port, string user, string password, CancellationToken ct)
    {
        using var http = CreateClient(port, user, password);
        var timer = Stopwatch.StartNew();
        var ipv4 = TraceAsync(http, "https://1.1.1.1/cdn-cgi/trace", AddressFamily.InterNetwork, ct);
        var ipv6 = TraceAsync(http, "https://[2606:4700:4700::1111]/cdn-cgi/trace", AddressFamily.InterNetworkV6, ct);
        var udp = ProbeUdpAsync(port, user, password, ct);
        await ipv4.ConfigureAwait(false);
        int latency = (int)timer.ElapsedMilliseconds;
        await Task.WhenAll(ipv6, udp).ConfigureAwait(false);
        return new(new(await ipv4, await ipv6), latency, await udp);
    }

    private static async Task<WarpExitCheck.Observation> TraceAsync(HttpClient http, string url, AddressFamily family, CancellationToken ct)
    {
        string label = family == AddressFamily.InterNetwork ? "IPv4" : "IPv6";
        try
        {
            using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(8));
            using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            byte[] buffer = new byte[8192];
            int length = 0;
            while (length < buffer.Length)
            {
                int n = await stream.ReadAsync(buffer.AsMemory(length), timeout.Token).ConfigureAwait(false);
                if (n == 0) break;
                length += n;
            }
            return WarpExitCheck.Parse(Encoding.UTF8.GetString(buffer, 0, length), family);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return new(label, null, null, null, "timeout"); }
        catch (HttpRequestException) { return new(label, null, null, null, "HTTPS could not be verified"); }
    }

    // Exercise the same SOCKS UDP path that the full-device adapter uses. No successful-send shortcut.
    internal static async Task<bool> ProbeUdpAsync(int port, string user, string password, CancellationToken ct, IPEndPoint? target = null)
    {
        target ??= new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53);
        if (target.AddressFamily != AddressFamily.InterNetwork) throw new ArgumentException("UDP probe uses IPv4.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(6));
        var token = timeout.Token;
        try
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(false);
            using var stream = tcp.GetStream();
            await stream.WriteAsync(new byte[] { 5, 1, 2 }, token).ConfigureAwait(false);
            var reply = await ReadAsync(stream, 2, token).ConfigureAwait(false);
            if (reply[0] != 5 || reply[1] != 2) return false;
            byte[] u = Encoding.UTF8.GetBytes(user), p = Encoding.UTF8.GetBytes(password);
            if (u.Length > 255 || p.Length > 255) return false;
            var auth = new byte[] { 1, (byte)u.Length }.Concat(u).Concat(new[] { (byte)p.Length }).Concat(p).ToArray();
            await stream.WriteAsync(auth, token).ConfigureAwait(false);
            reply = await ReadAsync(stream, 2, token).ConfigureAwait(false);
            if (reply[0] != 1 || reply[1] != 0) return false;
            await stream.WriteAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, token).ConfigureAwait(false);
            reply = await ReadAsync(stream, 4, token).ConfigureAwait(false);
            if (reply[0] != 5 || reply[1] != 0 || reply[3] != 1) return false;
            byte[] bound = await ReadAsync(stream, 6, token).ConfigureAwait(false);
            var address = new IPAddress(bound.AsSpan(0, 4));
            if (address.Equals(IPAddress.Any)) address = IPAddress.Loopback;
            if (!IPAddress.IsLoopback(address)) return false;
            int relayPort = bound[4] * 256 + bound[5];
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Connect(address, relayPort);
            byte[] query = new byte[] { 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1 };
            RandomNumberGenerator.Fill(query.AsSpan(0, 2));
            byte[] packet = new byte[] { 0, 0, 0, 1 }.Concat(target.Address.GetAddressBytes())
                .Concat(new[] { (byte)(target.Port >> 8), (byte)target.Port }).Concat(query).ToArray();
            await udp.SendAsync(packet, token).ConfigureAwait(false);
            var received = await udp.ReceiveAsync(token).ConfigureAwait(false);
            return ValidUdpReply(received.Buffer, query, target);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return false; }
        catch (SocketException) { return false; }
        catch (IOException) { return false; }
    }

    internal static bool ValidUdpReply(byte[] packet, byte[] query, IPEndPoint? target = null)
    {
        target ??= new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53);
        return packet.Length >= 22 && query.Length >= 2 &&
            packet[0] == 0 && packet[1] == 0 && packet[2] == 0 && packet[3] == 1 &&
            packet.AsSpan(4, 4).SequenceEqual(target.Address.GetAddressBytes()) && packet[8] * 256 + packet[9] == target.Port &&
            packet[10] == query[0] && packet[11] == query[1] && (packet[12] & 0x80) != 0 && (packet[13] & 0x0F) == 0;
    }

    private static async Task<byte[]> ReadAsync(Stream stream, int length, CancellationToken ct)
    {
        byte[] bytes = new byte[length];
        int offset = 0;
        while (offset < length)
        {
            int n = await stream.ReadAsync(bytes.AsMemory(offset), ct).ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException();
            offset += n;
        }
        return bytes;
    }
}
