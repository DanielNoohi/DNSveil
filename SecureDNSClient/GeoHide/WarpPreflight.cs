using System.Diagnostics;
using System.Net.NetworkInformation;
using System.ServiceProcess;

namespace SecureDNSClient.GeoHide;

/// <summary>
/// Pre-connect checks: Iran geo, existing WARP/VPN, CloudflareWARP service health.
/// </summary>
public static class WarpPreflight
{
    private static readonly string[] VpnAdapterNeedles =
    {
        "wireguard", "nordlynx", "nordvpn", "openvpn", "tap-windows", "tap adapter",
        "wintun", "proton", "expressvpn", "surfshark", "mullvad", "v2ray", "xray",
        "sing-box", "clash", "outline", "psiphon", "softether", "hamachi", "tun2socks",
    };

    public sealed class Report
    {
        public string? PublicIp { get; set; }
        public string? Loc { get; set; }
        public bool? WarpOn { get; set; }
        public bool LikelyIran { get; set; }
        public bool AlreadyOnWarp { get; set; }
        public bool OtherVpnLikely { get; set; }
        public string? OtherVpnHint { get; set; }
        public bool ServiceWasStopped { get; set; }
        public bool ServiceRunning { get; set; }
        public List<string> Warnings { get; } = new();
        public List<string> Notes { get; } = new();

        public bool HasBlockingWarning =>
            !ServiceRunning || OtherVpnLikely;
    }

    public static async Task<Report> RunAsync(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var report = new Report();

        var (svcOk, svcMsg, wasStopped) = await EnsureWarpServiceAsync(progress, ct).ConfigureAwait(false);
        report.ServiceRunning = svcOk;
        report.ServiceWasStopped = wasStopped;
        if (!svcOk)
            report.Warnings.Add(svcMsg);
        else if (wasStopped)
            report.Notes.Add("CloudflareWARP service was stopped — started it.");
        else
            report.Notes.Add("CloudflareWARP service is running.");

        progress?.Report("Checking public IP / country / existing WARP…");
        WarpCli.PublicIpInfo info = await WarpCli.FetchPublicIpInfoAsync(6000).ConfigureAwait(false);
        report.PublicIp = info.Ip;
        report.Loc = info.Loc;
        report.WarpOn = info.WarpOn;
        report.LikelyIran = string.Equals(info.Loc, "IR", StringComparison.OrdinalIgnoreCase);
        report.AlreadyOnWarp = info.WarpOn == true;

        if (!string.IsNullOrEmpty(info.Ip))
            report.Notes.Add($"Public IP: {info.Ip}" + (string.IsNullOrEmpty(info.Loc) ? "" : $" [{info.Loc}]"));

        if (report.LikelyIran)
            report.Notes.Add("Location looks like Iran — censorship + DPI assist recommended.");
        else if (!string.IsNullOrEmpty(info.Loc) && info.WarpOn != true)
            report.Notes.Add($"Location is {info.Loc} (not IR). Censorship scan can stay off for a faster connect.");
        else if (!string.IsNullOrEmpty(info.Loc) && info.WarpOn == true)
            report.Notes.Add($"Already exiting via WARP in {info.Loc}.");

        if (report.AlreadyOnWarp)
            report.Warnings.Add("WARP already connected (warp=on). GeoHide will disconnect/reconnect — avoid stacking another VPN.");

        var (otherVpn, hint) = DetectOtherVpnAdapters();
        report.OtherVpnLikely = otherVpn;
        report.OtherVpnHint = hint;
        if (otherVpn)
        {
            report.Warnings.Add(
                $"Another VPN/tunnel adapter looks active ({hint}). Disconnect it first — it conflicts with WARP (failed Auto-find / high latency).");
        }

        return report;
    }

    /// <summary>Start Windows service <c>CloudflareWARP</c> if stopped.</summary>
    public static async Task<(bool Ok, string Message, bool WasStopped)> EnsureWarpServiceAsync(
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        try
        {
            if (WarpCli.IsServiceRunning())
                return (true, "WARP service running.", false);

            progress?.Report("CloudflareWARP service not running — starting…");
            await Task.Run(() =>
            {
                using ServiceController sc = new("CloudflareWARP");
                if (sc.Status == ServiceControllerStatus.Running)
                    return;

                if (sc.Status == ServiceControllerStatus.StartPending)
                {
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(25));
                    return;
                }

                if (sc.Status == ServiceControllerStatus.Stopped ||
                    sc.Status == ServiceControllerStatus.Paused)
                {
                    if (sc.Status == ServiceControllerStatus.Paused)
                        sc.Continue();
                    else
                        sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(25));
                }
            }, ct).ConfigureAwait(false);

            // Give warp-svc a moment to accept CLI.
            await Task.Delay(800, ct).ConfigureAwait(false);

            if (WarpCli.IsServiceRunning())
                return (true, "CloudflareWARP service started.", true);

            return (false,
                "Could not start CloudflareWARP service. Start it from services.msc or open the official WARP app once.",
                true);
        }
        catch (InvalidOperationException)
        {
            // Service name missing — fall back to process check / user action
            if (WarpCli.IsServiceRunning())
                return (true, "WARP process running.", false);
            return (false,
                "CloudflareWARP Windows service not found. Reinstall Cloudflare WARP, then retry.",
                false);
        }
        catch (Exception ex)
        {
            Debug.WriteLine("EnsureWarpServiceAsync: " + ex.Message);
            if (WarpCli.IsServiceRunning())
                return (true, "WARP process running.", false);
            return (false,
                "Cannot start CloudflareWARP service (need Admin?): " + ex.Message,
                false);
        }
    }

    private static (bool Found, string? Hint) DetectOtherVpnAdapters()
    {
        try
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                {
                    // Cloudflare WARP uses a tunnel iface — ignore it
                    string n = (nic.Name + " " + nic.Description).ToLowerInvariant();
                    if (n.Contains("cloudflare") || n.Contains("warp"))
                        continue;
                }

                string label = (nic.Name + " " + nic.Description).ToLowerInvariant();
                if (label.Contains("cloudflare") || label.Contains("warp"))
                    continue;

                foreach (string needle in VpnAdapterNeedles)
                {
                    if (label.Contains(needle))
                        return (true, nic.Name);
                }

                // Generic TUN/TAP when up and not Cloudflare
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel &&
                    !label.Contains("cloudflare") && !label.Contains("warp") &&
                    nic.GetIPProperties().UnicastAddresses.Count > 0)
                {
                    return (true, nic.Name);
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("DetectOtherVpnAdapters: " + ex.Message);
        }
        return (false, null);
    }
}
