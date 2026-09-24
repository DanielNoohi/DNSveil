using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SecureDNSClient.GeoHide;

internal sealed class XrayWarpSession : IAsyncDisposable
{
    private OwnedBackendProcess? xray;
    private OwnedBackendProcess? tun;
    private readonly string directory;
    private readonly string tools;
    private readonly string username = "dnsveil";
    private readonly string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    internal int Port { get; }
    internal string Endpoint { get; }
    internal bool Running => xray?.Running == true && (tun == null || tun.Running);
    internal bool FullDevice => tun != null;

    private XrayWarpSession(string root, string tools, string endpoint)
    {
        directory = Path.Combine(root, "sessions", Guid.NewGuid().ToString("N"));
        XrayWarpProfiles.RestrictDirectory(directory);
        this.tools = tools;
        Endpoint = endpoint;
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
    }

    internal static async Task<XrayWarpSession> StartAsync(string root, string tools, XrayWarpAccount[] accounts,
        string endpoint, XrayWarpOptions options, CancellationToken ct)
    {
        var session = new XrayWarpSession(root, tools, endpoint);
        try
        {
            string config = Path.Combine(session.directory, "xray.json");
            await File.WriteAllTextAsync(config, XrayWarpConfig.Build(accounts, endpoint, session.Port, session.username, session.password, options), ct).ConfigureAwait(false);
            var validation = await WarpCommandRunner.RunAsync(Path.Combine(tools, "xray.exe"), new[] { "run", "-test", "-config", config }, TimeSpan.FromSeconds(8), ct).ConfigureAwait(false);
            if (!validation.Ok) throw new InvalidOperationException("The pinned Xray core rejected the generated configuration.");
            session.xray = new OwnedBackendProcess(Path.Combine(tools, "xray.exe"), "run", "-config", config);
            for (int i = 0; i < 30; i++)
            {
                ct.ThrowIfCancellationRequested();
                if (!session.Running) throw new InvalidOperationException("Xray exited during startup.");
                using var test = new TcpClient();
                try
                {
                    await test.ConnectAsync(IPAddress.Loopback, session.Port, ct).ConfigureAwait(false);
                    File.Delete(config); // core has loaded it; don't leave plaintext keys on disk
                    return session;
                }
                catch (SocketException) { await Task.Delay(100, ct).ConfigureAwait(false); }
            }
            throw new TimeoutException("Xray listener did not start.");
        }
        catch { await session.DisposeAsync().ConfigureAwait(false); throw; }
    }

    internal Task<XrayWarpProbeResult> ProbeAsync(CancellationToken ct) => XrayWarpProbe.FetchAsync(Port, username, password, ct);

    internal async Task StartFullDeviceAsync(CancellationToken ct)
    {
        if (!Running) throw new InvalidOperationException("No running Xray tunnel.");
        string config = Path.Combine(directory, "tun.json");
        await File.WriteAllTextAsync(config, XrayWarpConfig.BuildTun(Endpoint, Port, username, password), ct).ConfigureAwait(false);
        var validation = await WarpCommandRunner.RunAsync(Path.Combine(tools, "sing-box.exe"), new[] { "check", "-c", config }, TimeSpan.FromSeconds(8), ct).ConfigureAwait(false);
        if (!validation.Ok) throw new InvalidOperationException("The pinned adapter core rejected its configuration.");
        tun = new OwnedBackendProcess(Path.Combine(tools, "sing-box.exe"), "run", "-c", config);
        await Task.Delay(2000, ct).ConfigureAwait(false);
        if (!Running) throw new InvalidOperationException("The network adapter did not start. Run DNSveil as Administrator and disconnect other VPNs.");
        // Verify through the system's new route, not just through the local SOCKS listener.
        var exit = await WarpExitCheck.FetchAsync(ct).ConfigureAwait(false);
        if (exit.IPv4.WarpOn != true || exit.IPv6.WarpOn == false)
            throw new InvalidOperationException("Full-device WARP routing could not be verified.");
        File.Delete(config);
    }

    public async ValueTask DisposeAsync()
    {
        // Close both owned jobs even if one process reports a cleanup error.
        try
        {
            if (tun != null) { var owned = tun; tun = null; await owned.DisposeAsync().ConfigureAwait(false); }
        }
        finally
        {
            try
            {
                if (xray != null) { var owned = xray; xray = null; await owned.DisposeAsync().ConfigureAwait(false); }
            }
            finally
            {
                foreach (string name in new[] { "xray.json", "tun.json" })
                    try { File.Delete(Path.Combine(directory, name)); } catch (IOException) { }
                try { Directory.Delete(directory); } catch (IOException) { }
            }
        }
    }
}
