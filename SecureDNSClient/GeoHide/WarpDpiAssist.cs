using MsmhToolsClass;
using SecureDNSClient.DPIBasic;
using System.Diagnostics;
using System.Text;

namespace SecureDNSClient.GeoHide;

/// <summary>
/// MASQUE-oriented GoodbyeDPI profiles.
/// Iran 2026 DPI reassembles TCP fragments, so Light-only ClientHello split is not enough.
/// Fake TTL / wrong-seq packets still desync stateful inspectors; QUIC block forces h2.
/// </summary>
public enum MasqueDpiProfile
{
    /// <summary>Fake packets only — do not fragment the large post-quantum ClientHello.</summary>
    FakeNoFrag,
    WrongChksum,
    FakeTtl,
    WrongSeq,
    FakeSeqTtl,
    LightFrag,
    Mode9,
    FakeSni,
}

/// <summary>
/// GoodbyeDPI for WARP connect. Detached WinDivert process (no redirected stdio).
/// </summary>
public static class WarpDpiAssist
{
    private static int _pid = -1;
    private static bool? _hasQuicBlock;
    private static bool? _hasFragBySni;
    private static bool? _hasFakeWithSni;
    private static bool? _hasFakeResend;

    public static bool IsActive => _pid > 0 && ProcessManager.FindProcessByPID(_pid);
    public static string? LastProfile { get; private set; }

    public static bool HasQuicBlock => ProbeFlag(ref _hasQuicBlock, "block QUIC", "-q ");
    public static bool HasFragBySni => ProbeFlag(ref _hasFragBySni, "frag-by-sni");
    public static bool HasFakeWithSni => ProbeFlag(ref _hasFakeWithSni, "fake-with-sni");
    public static bool HasFakeResend => ProbeFlag(ref _hasFakeResend, "fake-resend");

    /// <summary>
    /// Profiles to try for MASQUE h2. Fake packets first (survive TCP reassembly),
    /// Light fragment last (older DPI), Mode9/FakeSni only if the binary supports them.
    /// </summary>
    public static MasqueDpiProfile[] GetMasqueLadder()
    {
        var list = new List<MasqueDpiProfile>
        {
            MasqueDpiProfile.FakeNoFrag,
            MasqueDpiProfile.WrongChksum,
            MasqueDpiProfile.FakeTtl,
        };
        if (HasFakeWithSni)
            list.Insert(1, MasqueDpiProfile.FakeSni);
        list.Add(MasqueDpiProfile.LightFrag);
        if (HasQuicBlock)
            list.Add(MasqueDpiProfile.Mode9);
        return list.ToArray();
    }

    public static string ProfileLabel(MasqueDpiProfile profile) => profile switch
    {
        MasqueDpiProfile.FakeNoFrag => "FakeNoFrag (ttl+wrong-seq+chksum, no TLS split)",
        MasqueDpiProfile.WrongChksum => "WrongChksum (fake CH, checksum desync)",
        MasqueDpiProfile.FakeTtl => "FakeTTL (auto-ttl, no reverse-frag)",
        MasqueDpiProfile.WrongSeq => "WrongSeq (desync + reverse-frag)",
        MasqueDpiProfile.FakeSeqTtl => "FakeSeqTTL (ttl + wrong-seq)",
        MasqueDpiProfile.LightFrag => "LightFrag (ClientHello split)",
        MasqueDpiProfile.Mode9 => "Mode9 (wrong-seq+chksum+QUIC block)",
        MasqueDpiProfile.FakeSni => "FakeSNI (Firefox CH + cloudflare.com)",
        _ => profile.ToString(),
    };

    public static async Task<(bool Ok, string Message)> StartProfileAsync(
        MasqueDpiProfile profile,
        IProgress<string>? progress = null,
        decimal sslFragment = 2)
    {
        string args = BuildMasqueArgs(profile, sslFragment);
        return await StartRawAsync(args, ProfileLabel(profile), progress).ConfigureAwait(false);
    }

    public static async Task<(bool Ok, string Message)> StartAsync(
        DPIBasicBypassMode mode = DPIBasicBypassMode.Light,
        IProgress<string>? progress = null,
        decimal sslFragment = 2)
    {
        try
        {
            if (!File.Exists(SecureDNS.GoodbyeDpi))
                return (false, "goodbyedpi.exe missing — extract binaries first (or run DNSveil once).");
            if (!File.Exists(SecureDNS.WinDivert))
                return (false, "WinDivert.dll missing next to goodbyedpi — extract binaries first.");

            string fallbackDns = SecureDNS.BootstrapDnsIPv4.ToString();
            int fallbackPort = SecureDNS.BootstrapDnsPort;
            var dpi = new DPIBasicBypass(mode, sslFragment, fallbackDns, fallbackPort);
            return await StartRawAsync(dpi.Args, dpi.Text + $" -e {sslFragment}", progress).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Debug.WriteLine("WarpDpiAssist.StartAsync: " + ex.Message);
            return (false, "DPI assist error: " + ex.Message);
        }
    }

    private static string BuildMasqueArgs(MasqueDpiProfile profile, decimal sslFragment)
    {
        string dns = DnsRedirectArgs();
        string e = sslFragment.ToString(System.Globalization.CultureInfo.InvariantCulture);
        string extra = "";
        if (HasFragBySni) extra += " --frag-by-sni";
        if (HasFakeResend) extra += " --fake-resend 2";

        // -p drops injected RST (passive DPI). --max-payload keeps tricks on handshake packets.
        // --allow-no-sni: WARP often talks to an IP; SNI may be missing or ECH-hidden.
        return profile switch
        {
            MasqueDpiProfile.FakeNoFrag =>
                $"-p --wrong-chksum --wrong-seq --set-ttl 3 --allow-no-sni{extra} {dns}",
            MasqueDpiProfile.WrongChksum =>
                $"-p --wrong-chksum --allow-no-sni{extra} {dns}",
            MasqueDpiProfile.FakeTtl =>
                $"-p --auto-ttl 1-4-10 --min-ttl 3 --allow-no-sni{extra} {dns}",
            MasqueDpiProfile.WrongSeq =>
                $"-p --wrong-seq --allow-no-sni{extra} {dns}",
            MasqueDpiProfile.FakeSeqTtl =>
                $"-p --auto-ttl 1-4-10 --min-ttl 3 --wrong-seq --allow-no-sni{extra} {dns}",
            MasqueDpiProfile.LightFrag =>
                $"-p -e {e} --native-frag --max-payload --allow-no-sni{extra} {dns}",
            MasqueDpiProfile.Mode9 =>
                $"-p -e {e} --wrong-seq --wrong-chksum --reverse-frag --max-payload --allow-no-sni -q{extra} {dns}",
            MasqueDpiProfile.FakeSni =>
                $"-p -e {e} --wrong-seq --auto-ttl 1-4-10 --min-ttl 3 --native-frag --reverse-frag --max-payload --allow-no-sni " +
                $"--fake-with-sni www.cloudflare.com --fake-with-sni www.google.com{extra} {dns}",
            _ => $"-p -e {e} --native-frag {dns}",
        };
    }

    private static string DnsRedirectArgs()
    {
        string fallbackDns = SecureDNS.BootstrapDnsIPv4.ToString();
        int fallbackPort = SecureDNS.BootstrapDnsPort;
        string v6 = SecureDNS.BootstrapDnsIPv6.ToString();
        return $"--dns-addr {fallbackDns} --dns-port {fallbackPort} --dnsv6-addr {v6} --dnsv6-port {fallbackPort}";
    }

    private static async Task<(bool Ok, string Message)> StartRawAsync(
        string args, string label, IProgress<string>? progress)
    {
        try
        {
            if (!File.Exists(SecureDNS.GoodbyeDpi))
                return (false, "goodbyedpi.exe missing — extract binaries first (or run DNSveil once).");
            if (!File.Exists(SecureDNS.WinDivert))
                return (false, "WinDivert.dll missing next to goodbyedpi — extract binaries first.");

            await StopAsync().ConfigureAwait(false);
            try { await ProcessManager.KillProcessByNameAsync("goodbyedpi"); } catch { /* ignore */ }

            progress?.Report($"DPI assist: {label}…");
            WarpSessionLog.Step("dpi", "start " + label,
                new Dictionary<string, object?>
                {
                    ["args"] = args,
                    ["quicBlock"] = HasQuicBlock,
                    ["fragBySni"] = HasFragBySni,
                    ["fakeWithSni"] = HasFakeWithSni,
                });

            _pid = StartDetached(SecureDNS.GoodbyeDpi, args, SecureDNS.BinaryDirPath);
            LastProfile = label;

            for (int i = 0; i < 40; i++)
            {
                if (ProcessManager.FindProcessByPID(_pid)) break;
                await Task.Delay(100).ConfigureAwait(false);
            }

            if (!ProcessManager.FindProcessByPID(_pid))
            {
                _pid = -1;
                LastProfile = null;
                return (false, "GoodbyeDPI failed to start (need Admin / WinDivert drivers).");
            }

            await Task.Delay(900).ConfigureAwait(false);
            return (true, $"GoodbyeDPI active ({label}).");
        }
        catch (Exception ex)
        {
            Debug.WriteLine("WarpDpiAssist.StartRawAsync: " + ex.Message);
            return (false, "DPI assist error: " + ex.Message);
        }
    }

    private static bool ProbeFlag(ref bool? cache, params string[] needles)
    {
        if (cache.HasValue) return cache.Value;
        cache = BinaryContains(needles);
        return cache.Value;
    }

    private static bool BinaryContains(params string[] needles)
    {
        try
        {
            if (!File.Exists(SecureDNS.GoodbyeDpi)) return false;
            byte[] bytes = File.ReadAllBytes(SecureDNS.GoodbyeDpi);
            foreach (string n in needles)
            {
                byte[] needle = Encoding.ASCII.GetBytes(n);
                if (IndexOf(bytes, needle) >= 0) return true;
            }
        }
        catch { /* ignore */ }
        return false;
    }

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        if (needle.Length == 0 || hay.Length < needle.Length) return -1;
        int last = hay.Length - needle.Length;
        for (int i = 0; i <= last; i++)
        {
            int j = 0;
            for (; j < needle.Length; j++)
            {
                if (hay[i + j] != needle[j]) break;
            }
            if (j == needle.Length) return i;
        }
        return -1;
    }

    private static int StartDetached(string exe, string args, string workDir)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                WorkingDirectory = workDir,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardInput = false,
                RedirectStandardOutput = false,
                RedirectStandardError = false,
            };
            var p = Process.Start(psi);
            return p?.Id ?? -1;
        }
        catch (Exception ex)
        {
            Debug.WriteLine("WarpDpiAssist.StartDetached: " + ex.Message);
            return -1;
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
        finally
        {
            _pid = -1;
            LastProfile = null;
        }
    }
}
