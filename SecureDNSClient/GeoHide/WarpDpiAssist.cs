using MsmhToolsClass;
using SecureDNSClient.DPIBasic;
using System.Diagnostics;

namespace SecureDNSClient.GeoHide;

/// <summary>
/// Starts GoodbyeDPI (TLS ClientHello fragmentation) before WARP connect.
/// Technique lineage: GFW-knocker gfw_resist_tls_proxy — fragment SNI so DPI
/// cannot reassemble blacklisted names on Cloudflare edges (MASQUE H2 path).
/// </summary>
public static class WarpDpiAssist
{
    private static int _pid = -1;

    public static bool IsActive => _pid > 0 && ProcessManager.FindProcessByPID(_pid);

    /// <summary>
    /// Light/Medium fragment modes — enough to break SNI DPI without being too aggressive for WARP.
    /// </summary>
    public static async Task<(bool Ok, string Message)> StartAsync(
        DPIBasicBypassMode mode = DPIBasicBypassMode.Light,
        IProgress<string>? progress = null)
    {
        try
        {
            if (!File.Exists(SecureDNS.GoodbyeDpi))
                return (false, "goodbyedpi.exe missing — extract binaries first (or run DNSveil once).");

            await StopAsync().ConfigureAwait(false);

            string fallbackDns = SecureDNS.BootstrapDnsIPv4.ToString();
            int fallbackPort = SecureDNS.BootstrapDnsPort;
            var dpi = new DPIBasicBypass(mode, sslFragment: 2, fallbackDns, fallbackPort);

            progress?.Report($"DPI assist: starting GoodbyeDPI ({dpi.Text}) — TLS ClientHello fragment…");
            _pid = ProcessManager.ExecuteOnly(
                SecureDNS.GoodbyeDpi,
                environmentVariables: null,
                args: dpi.Args,
                hideWindow: true,
                runAsAdmin: true,
                workingDirectory: SecureDNS.BinaryDirPath);

            for (int i = 0; i < 30; i++)
            {
                if (ProcessManager.FindProcessByPID(_pid)) break;
                await Task.Delay(100).ConfigureAwait(false);
            }

            if (!ProcessManager.FindProcessByPID(_pid))
            {
                _pid = -1;
                return (false, "GoodbyeDPI failed to start (need admin / WinDivert).");
            }

            // Let WinDivert hooks settle before warp-cli opens TLS/QUIC sockets.
            await Task.Delay(600).ConfigureAwait(false);
            return (true, $"GoodbyeDPI active ({dpi.Text}).");
        }
        catch (Exception ex)
        {
            Debug.WriteLine("WarpDpiAssist.StartAsync: " + ex.Message);
            return (false, "DPI assist error: " + ex.Message);
        }
    }

    public static async Task StopAsync()
    {
        try
        {
            if (_pid > 0)
                await ProcessManager.KillProcessByPidAsync(_pid).ConfigureAwait(false);
        }
        catch { /* ignore */ }
        finally { _pid = -1; }

        try
        {
            // Only kill orphan goodbyedpi if we started one; FormMain may own its own — be conservative:
            // do not KillProcessByNameAsync(goodbyedpi) globally.
        }
        catch { /* ignore */ }
    }
}
