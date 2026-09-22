using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SecureDNSClient.GeoHide;

/// <summary>Country observations from direct IPv4/IPv6 traffic, not a service-access guarantee.</summary>
internal static class WarpExitCheck
{
    internal sealed record Observation(string Family, string? Ip, string? Country, bool? WarpOn, string? Error = null);
    internal sealed record Report(Observation IPv4, Observation IPv6)
    {
        internal bool IsOutside(string country) => Accept(IPv4, country) && Accept(IPv6, country);
        internal string Summary => $"IPv4: {Describe(IPv4)}; IPv6: {Describe(IPv6)}. Data-center location is not exit country.";
        private static bool Accept(Observation value, string country) => value.WarpOn == true &&
            IPAddress.TryParse(value.Ip, out _) && ValidCountry(value.Country) &&
            !value.Country!.Equals(country, StringComparison.OrdinalIgnoreCase);
        private static string Describe(Observation value) =>
            $"country={value.Country ?? "unknown"}, WARP={(value.WarpOn == true ? "on" : value.WarpOn == false ? "off" : "unknown")}" +
            (value.Error == null ? "" : $" ({value.Error})");
    }

    private static bool ValidCountry(string? country) => country is { Length: 2 } &&
        country.All(c => c is >= 'A' and <= 'Z') && country != "XX";

    internal static Observation Parse(string text, AddressFamily family)
    {
        var fields = text.Split('\n').Select(line => line.Trim().Split('=', 2))
            .Where(parts => parts.Length == 2).GroupBy(parts => parts[0], StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Last()[1].Trim(), StringComparer.OrdinalIgnoreCase);
        fields.TryGetValue("ip", out string? ip);
        fields.TryGetValue("loc", out string? country);
        fields.TryGetValue("warp", out string? warp);
        string label = family == AddressFamily.InterNetwork ? "IPv4" : "IPv6";
        if (!IPAddress.TryParse(ip, out var address) || address.AddressFamily != family)
            return new(label, null, null, null, "Missing or mismatched address family");
        country = country?.ToUpperInvariant();
        return new(label, address.ToString(), ValidCountry(country) ? country : null,
            warp == "on" ? true : warp == "off" ? false : null);
    }

    internal static async Task<Report> FetchAsync(CancellationToken ct)
    {
        var v4 = FetchFamilyAsync(AddressFamily.InterNetwork, ct);
        var v6 = FetchFamilyAsync(AddressFamily.InterNetworkV6, ct);
        await Task.WhenAll(v4, v6).ConfigureAwait(false);
        return new(await v4.ConfigureAwait(false), await v6.ConfigureAwait(false));
    }

    private static async Task<Observation> FetchFamilyAsync(AddressFamily family, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(8));
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectCallback = async (context, token) =>
            {
                var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host).WaitAsync(token).ConfigureAwait(false);
                Exception? last = null;
                foreach (var address in addresses.Where(address => address.AddressFamily == family))
                {
                    var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), token).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception ex) { socket.Dispose(); token.ThrowIfCancellationRequested(); last = ex; }
                }
                throw new HttpRequestException("No reachable address for " + family, last);
            },
        };
        using var http = new HttpClient(handler);
        try
        {
            using var response = await http.GetAsync("https://www.cloudflare.com/cdn-cgi/trace",
                HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            byte[] buffer = new byte[8192];
            int length = 0;
            while (length < buffer.Length)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(length), timeout.Token).ConfigureAwait(false);
                if (read == 0) break;
                length += read;
            }
            ct.ThrowIfCancellationRequested();
            return Parse(Encoding.UTF8.GetString(buffer, 0, length), family);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException)
        {
            return new(family == AddressFamily.InterNetwork ? "IPv4" : "IPv6", null, null, null,
                "Could not verify this route; no assumption that it is hidden");
        }
    }
}
