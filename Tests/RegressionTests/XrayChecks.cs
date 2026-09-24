using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureDNSClient.GeoHide;

internal static class XrayChecks
{
    internal static async Task RunAsync(Action<bool, string> check)
    {
        Exception? uiError = null;
        var uiThread = new Thread(() => {
            try {
                using var form = new SecureDNSClient.FormGeoHideXray();
                form.ShowInTaskbar = false;
                form.StartPosition = System.Windows.Forms.FormStartPosition.Manual;
                form.Location = new System.Drawing.Point(-30000, -30000);
                form.Show();
                System.Windows.Forms.Application.DoEvents();
                using var bitmap = new System.Drawing.Bitmap(form.Width, form.Height);
                form.DrawToBitmap(bitmap, new System.Drawing.Rectangle(0, 0, form.Width, form.Height));
                bitmap.Save(Path.Combine(AppContext.BaseDirectory, "advanced-warp-ui.png"));
                using var host = new System.Windows.Forms.Form {
                    ShowInTaskbar = false, StartPosition = System.Windows.Forms.FormStartPosition.Manual,
                    Location = new System.Drawing.Point(-30000, -30000), ClientSize = new System.Drawing.Size(920, 800)
                };
                using var geo = new SecureDNSClient.FormGeoHideWarp(false) {
                    TopLevel = false, FormBorderStyle = System.Windows.Forms.FormBorderStyle.None,
                    ShowInTaskbar = false, Dock = System.Windows.Forms.DockStyle.Fill
                };
                host.Controls.Add(geo);
                host.Show(); geo.Show();
                var tabs = geo.Controls.OfType<System.Windows.Forms.TabControl>().Single();
                tabs.SelectedIndex = 1;
                System.Windows.Forms.Application.DoEvents();
                var advanced = tabs.TabPages[1].Controls.OfType<SecureDNSClient.FormGeoHideXray>().Single();
                if (geo.TopLevel || advanced.TopLevel || advanced.ShowInTaskbar || advanced.FindForm() != advanced)
                    throw new Exception("GeoHide must keep both connection views embedded.");
                if (advanced.Parent != tabs.TabPages[1]) throw new Exception("Advanced view is not hosted in its tab.");
                using var combined = new System.Drawing.Bitmap(host.Width, host.Height);
                host.DrawToBitmap(combined, new System.Drawing.Rectangle(0, 0, host.Width, host.Height));
                combined.Save(Path.Combine(AppContext.BaseDirectory, "geohide-embedded-ui.png"));
                var close = geo.CloseViewAsync();
                var until = DateTime.UtcNow.AddSeconds(3);
                while (!close.IsCompleted && DateTime.UtcNow < until) {
                    System.Windows.Forms.Application.DoEvents();
                    Thread.Sleep(10);
                }
                if (!close.IsCompletedSuccessfully || !advanced.IsDisposed)
                    throw new Exception("Embedded GeoHide did not close its advanced view.");
                host.Close();
            } catch (Exception ex) { uiError = ex; }
        });
        uiThread.SetApartmentState(ApartmentState.STA); uiThread.Start();
        if (!uiThread.Join(TimeSpan.FromSeconds(10))) throw new Exception("Advanced UI initialization hung.");
        if (uiError != null) throw new Exception("Advanced UI initialization failed.", uiError);
        check(true, "Advanced controls initialize without starting a tunnel or registration");
        string key1 = Convert.ToBase64String(Enumerable.Range(1, 32).Select(x => (byte)x).ToArray());
        string key2 = Convert.ToBase64String(Enumerable.Range(33, 32).Select(x => (byte)x).ToArray());
        var accounts = new[] { new XrayWarpAccount(key1, key2, "2001:db8::1/128", new[] { 1, 2, 3 }),
            new XrayWarpAccount(key2, key1, "2001:db8::2/128", new[] { 4, 5, 6 }) };
        const string endpoint = "198.51.100.10:2408";
        bool invalid = false;
        try { XrayWarpConfig.ParseEndpoint("example.com:2408"); } catch (FormatException) { invalid = true; }
        check(invalid, "Advanced endpoint validation prevents ambiguous DNS bootstrap");
        check(XrayWarpConfig.ParseEndpoint("[2001:db8::1]:4500").Port == 4500, "Advanced scanner accepts bracketed IPv6 endpoints");
        invalid = false;
        try { new XrayWarpOptions(NoiseMin: 200, NoiseMax: 100).Validate(); } catch (ArgumentException) { invalid = true; }
        check(invalid, "Invalid noise ranges are rejected before any connection");
        using var config = JsonDocument.Parse(XrayWarpConfig.Build(accounts, endpoint, 20808, "dnsveil", "fixture", new()));
        var outbounds = config.RootElement.GetProperty("outbounds");
        check(outbounds.GetArrayLength() == 2 && outbounds[0].GetProperty("streamSettings").GetProperty("sockopt").GetProperty("dialerProxy").GetString() == "warp",
            "Nested WARP routes its second tunnel through the first");
        check(outbounds[0].GetProperty("settings").GetProperty("secretKey").GetString() != outbounds[1].GetProperty("settings").GetProperty("secretKey").GetString(),
            "Nested WARP uses separate profile keys");
        check(outbounds.EnumerateArray().All(x => x.GetProperty("protocol").GetString() == "wireguard"), "User traffic has no direct fallback outbound");
        check(config.RootElement.GetProperty("inbounds")[0].GetProperty("listen").GetString() == "127.0.0.1" &&
            config.RootElement.GetProperty("inbounds")[0].GetProperty("settings").GetProperty("auth").GetString() == "password",
            "Advanced local proxy is loopback-only and authenticated");
        using var tun = JsonDocument.Parse(XrayWarpConfig.BuildTun(endpoint, 20808, "dnsveil", "fixture"));
        var inbound = tun.RootElement.GetProperty("inbounds")[0];
        check(inbound.GetProperty("address").GetArrayLength() == 2 && inbound.GetProperty("strict_route").GetBoolean(), "PC adapter config includes both IP families and strict routing");
        check(inbound.GetProperty("route_exclude_address").GetArrayLength() == 1 &&
            inbound.GetProperty("route_exclude_address")[0].GetString() == "198.51.100.10/32", "Only outer endpoint is excluded to avoid a routing loop");
        check(tun.RootElement.GetProperty("dns").GetProperty("servers")[0].GetProperty("detour").GetString() == "xray",
            "Adapter DNS is sent through Xray instead of a direct resolver");
        using var registration = JsonDocument.Parse("{\"config\":{\"interface\":{\"addresses\":{\"v6\":\"2001:db8::3\"}},\"client_id\":\"AQID\",\"peers\":[{\"public_key\":\"" + key2 + "\"}]}}");
        var parsed = XrayWarpProfiles.ParseRegistration(registration.RootElement, key1);
        check(parsed.Reserved.SequenceEqual(new[] { 1, 2, 3 }) && parsed.IPv6.EndsWith("/128"), "Registration parser keeps account-specific reserved bytes and IPv6");
        byte[] packet = new byte[22]; packet[3] = 1; packet[4] = packet[5] = packet[6] = packet[7] = 1; packet[9] = 53;
        packet[10] = 42; packet[11] = 43; packet[12] = 128;
        check(XrayWarpProbe.ValidUdpReply(packet, new byte[] { 42, 43 }), "UDP probe requires an actual matching DNS reply");
        check(!XrayWarpProbe.ValidUdpReply(packet, new byte[] { 42, 44 }), "UDP probe rejects unrelated transaction IDs");
        packet[2] = 1;
        check(!XrayWarpProbe.ValidUdpReply(packet, new byte[] { 42, 43 }), "UDP probe rejects fragmented or malformed relay packets");
        string root = Path.Combine(AppContext.BaseDirectory, "xray-fixture-" + Guid.NewGuid().ToString("N"));
        XrayWarpProfiles.RestrictDirectory(root);
        try
        {
            byte[] encrypted = ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(accounts), null, DataProtectionScope.CurrentUser);
            await File.WriteAllBytesAsync(Path.Combine(root, "profiles.dpapi"), encrypted);
            var loaded = await XrayWarpProfiles.LoadOrCreateAsync(root, "unused", false, null, default);
            check(loaded.Length == 2 && loaded[0].PrivateKey == key1 && !Encoding.UTF8.GetString(encrypted).Contains(key1),
                "Encrypted profiles reload without re-registering or storing plaintext keys");
            string tools = Path.Combine(AppContext.BaseDirectory, "Backends");
            await XrayWarpTools.VerifyAsync(tools, default);
            check(true, "Bundled backend binaries match pinned hashes");
            foreach (bool wow in new[] { false, true }) foreach (bool noise in new[] { false, true })
            {
                string file = Path.Combine(root, "xray.json");
                await File.WriteAllTextAsync(file, XrayWarpConfig.Build(accounts, endpoint, 20808, "dnsveil", "fixture", new(wow, noise)));
                var result = await WarpCommandRunner.RunAsync(Path.Combine(tools, "xray.exe"), new[] { "run", "-test", "-config", file }, TimeSpan.FromSeconds(8));
                check(result.Ok, $"Pinned Xray validates configuration: nested={wow}, noise={noise}");
                if (!result.Ok) Console.WriteLine(result.Combined);
            }
            string tunFile = Path.Combine(root, "tun.json"); await File.WriteAllTextAsync(tunFile, tun.RootElement.GetRawText());
            var validation = await WarpCommandRunner.RunAsync(Path.Combine(tools, "sing-box.exe"), new[] { "check", "-c", tunFile }, TimeSpan.FromSeconds(8));
            check(validation.Ok, "Pinned adapter core validates full-device TCP/UDP configuration without installing routes");
            if (!validation.Ok) Console.WriteLine(validation.Combined);
            await TestLocalForwardingAsync(tools, root, check);
        }
        finally
        {
            foreach (string file in Directory.GetFiles(root)) File.Delete(file);
            Directory.Delete(root);
        }
    }

    private static async Task TestLocalForwardingAsync(string tools, string root, Action<bool, string> check)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15)); var ct = deadline.Token;
        var reserve = new TcpListener(IPAddress.Loopback, 0); reserve.Start(); int port = ((IPEndPoint)reserve.LocalEndpoint).Port; reserve.Stop();
        string path = Path.Combine(root, "local.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new {
            log = new { loglevel = "none" }, inbounds = new[] { new { listen = "127.0.0.1", port, protocol = "socks", settings = new {
                auth = "password", accounts = new[] { new { user = "dnsveil", pass = "fixture" } }, udp = true, ip = "127.0.0.1" } } },
            outbounds = new[] { new { protocol = "freedom", settings = new { } } }
        }), ct);
        var child = new OwnedBackendProcess(Path.Combine(tools, "xray.exe"), "run", "-config", path);
        try
        {
            await Task.Delay(500, ct);
            var server = new TcpListener(IPAddress.Loopback, 0); server.Start();
            try
            {
                var respond = Task.Run(async () => {
                    using var incoming = await server.AcceptTcpClientAsync(ct); using var stream = incoming.GetStream();
                    byte[] bytes = new byte[4096]; await stream.ReadAsync(bytes, ct);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"), ct);
                }, ct);
                using var http = XrayWarpProbe.CreateClient(port, "dnsveil", "fixture");
                string body = await http.GetStringAsync($"http://127.0.0.1:{((IPEndPoint)server.LocalEndpoint).Port}/", ct);
                await respond;
                check(body == "OK", "Actual pinned Xray forwards authenticated SOCKS TCP to a local fixture");
            }
            finally { server.Stop(); }
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var reply = Task.Run(async () => { var received = await udp.ReceiveAsync(ct); received.Buffer[2] |= 128; await udp.SendAsync(received.Buffer, received.RemoteEndPoint, ct); }, ct);
            bool passed = await XrayWarpProbe.ProbeUdpAsync(port, "dnsveil", "fixture", ct, (IPEndPoint)udp.Client.LocalEndPoint!);
            await reply;
            check(passed, "Actual pinned Xray carries SOCKS UDP requests and replies through a local fixture");
        }
        finally { await child.DisposeAsync(); }
        using var closed = new TcpClient(); bool stopped = false;
        try { await closed.ConnectAsync(IPAddress.Loopback, port, ct); } catch (SocketException) { stopped = true; }
        check(stopped, "Disposing an owned backend closes its listener and process");
    }
}
