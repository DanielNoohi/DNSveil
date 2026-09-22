using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;

namespace SecureDNSClient.GeoHide;

/// <summary>
/// Thin wrapper around Cloudflare's official <c>warp-cli</c>, inspired by
/// https://github.com/saeedmasoudie/pywarp (endpoint set, protocol, connect).
/// Censorship mode: MASQUE h2 + GoodbyeDPI fake-TTL/wrong-seq (TCP reassembly-resistant).
/// </summary>
public static class WarpCli
{
    public static readonly string[] EngageHosts =
    {
        "engage.cloudflareclient.com",
        "162.159.192.1", "162.159.192.2", "162.159.193.1", "162.159.193.3",
        "162.159.195.1", "162.159.195.3", "162.159.198.0", "162.159.198.1",
        "162.159.198.2", "162.159.199.1", "162.159.199.2", "162.159.204.1",
        "188.114.96.1", "188.114.97.1", "188.114.98.1", "188.114.99.1",
        "188.114.100.1", "188.114.101.1",
    };

    /// <summary>Classic WG + IRCF / community alternate ports used under censorship.</summary>
    public static readonly int[] WireGuardPorts =
    {
        2408, 500, 1701, 4500, 443, 854, 878, 864, 890, 894, 903, 908,
        1002, 1070, 1387, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198,
        4233, 4443, 5279, 5956, 7103, 7152, 7281, 7559, 8095, 8319, 8742,
        8854, 8886,
    };

    public static readonly int[] MasquePorts = { 443, 8443, 4443, 8095 };

    /// <summary>WARP/MASQUE-relevant CF ranges (IRCF + Cloudflare engage anycast).</summary>
    public static readonly string[] WarpScanCidrs =
    {
        "162.159.192.0/24",
        "162.159.193.0/24",
        "162.159.195.0/24",
        "162.159.198.0/24",
        "162.159.199.0/24",
        "188.114.96.0/24",
        "188.114.97.0/24",
        "188.114.98.0/24",
        "188.114.99.0/24",
    };

    private static readonly string[] IrcfEndpointUrls =
    {
        "https://raw.githubusercontent.com/ircfspace/endpoint/main/v2.json",
        "https://ircfspace.github.io/endpoint/v2.json",
    };

    private static string? _cachedExe;
    private static DateTime _cachedExeAt = DateTime.MinValue;
    private static readonly HttpClient SharedHttp = CreateHttpClient();
    private static List<string>? _cachedIrcf;
    private static DateTime _cachedIrcfAt = DateTime.MinValue;

    private static HttpClient CreateHttpClient()
    {
        HttpClient c = new() { Timeout = TimeSpan.FromSeconds(12) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("DNSveil-GeoHide/3.6");
        return c;
    }

    public sealed class Result
    {
        public int ExitCode { get; init; }
        public string StdOut { get; init; } = "";
        public string StdErr { get; init; } = "";
        public bool Ok => ExitCode == 0;
        public string Combined => (StdOut + "\n" + StdErr).Trim();
        public string ErrorLine =>
            string.IsNullOrWhiteSpace(StdErr)
                ? StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? ""
                : StdErr.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? "";
    }

    public sealed record CensorshipOptions
    {
        /// <summary>Scan CF CIDRs + IRCF lists; MASQUE-first; longer polls.</summary>
        public bool Enabled { get; init; } = true;
        /// <summary>Start GoodbyeDPI TLS fragment before connect (GFW-knocker style).</summary>
        public bool DpiAssist { get; init; } = true;
        /// <summary>
        /// After connect: stop DPI assist. Keeps WARP DNS (not tunnel_only) so sites resolve.
        /// Iran excludes are separate — applying dozens of ranges often thrash the tunnel under DPI.
        /// </summary>
        public bool LowLatency { get; init; } = true;
        /// <summary>When false, skip WireGuard upgrade (saves ~10–30s under DPI).</summary>
        public bool TryWireGuardUpgrade { get; init; } = false;
        /// <summary>
        /// When true, flood warp-cli with Iran/domestic excludes after connect.
        /// Default false: those excludes often cause weak/jittery sessions under MASQUE+DPI.
        /// </summary>
        public bool ApplyIranExcludes { get; init; } = false;
        public int MaxCandidates { get; init; } = 80;
        public int MaxConnectAttempts { get; init; } = 16;
        public int ProbeTimeoutMs { get; init; } = 400;
        public int CidrSamplePerRange { get; init; } = 16;
        /// <summary>Reject Connected endpoints that fail RTT/download quality (rotate to next).</summary>
        public bool RequireLinkQuality { get; init; } = true;
        /// <summary>Experimental: try both protocols, accepting only verified IPv4/IPv6 exits outside IR.</summary>
        public bool TryExitOutsideIran { get; init; } = false;
    }

    /// <summary>Last probed connect queue — used by health watch to rotate without a full rescan.</summary>
    public static List<string> LastCandidatePool { get; private set; } = new();
    private static readonly object PoolGate = new();

    public static void RememberCandidatePool(IEnumerable<string>? endpoints)
    {
        lock (PoolGate)
        {
            LastCandidatePool = endpoints?
                .Where(e => !string.IsNullOrWhiteSpace(e))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList() ?? new List<string>();
        }
    }

    public static List<string> GetFailoverCandidates(string? excludeEndpoint, int take = 12)
    {
        lock (PoolGate)
        {
            return LastCandidatePool
                .Where(e => !string.Equals(e, excludeEndpoint, StringComparison.OrdinalIgnoreCase))
                .Take(take)
                .ToList();
        }
    }

    public static string? FindExecutable(bool forceRefresh = false)
    {
        try
        {
            if (!forceRefresh && _cachedExe != null && (DateTime.UtcNow - _cachedExeAt).TotalMinutes < 5)
            {
                if (File.Exists(_cachedExe)) return _cachedExe;
            }

            string? which = FindOnPath("warp-cli.exe") ?? FindOnPath("warp-cli");
            if (!string.IsNullOrEmpty(which))
            {
                _cachedExe = which;
                _cachedExeAt = DateTime.UtcNow;
                return which;
            }

            string[] candidates =
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cloudflare", "Cloudflare WARP", "warp-cli.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Cloudflare", "Cloudflare WARP", "warp-cli.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cloudflare", "CloudflareOne", "warp-cli.exe"),
                @"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe",
            };
            foreach (string c in candidates)
            {
                if (File.Exists(c))
                {
                    _cachedExe = c;
                    _cachedExeAt = DateTime.UtcNow;
                    return c;
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("WarpCli.FindExecutable: " + ex.Message);
        }
        _cachedExe = null;
        return null;
    }

    public static bool IsInstalled() => !string.IsNullOrEmpty(FindExecutable());

    public static bool IsServiceRunning()
    {
        try
        {
            return Process.GetProcessesByName("warp-svc").Length > 0
                || Process.GetProcessesByName("Cloudflare WARP").Length > 0;
        }
        catch
        {
            // Fail closed — unknown service state must not look "running"
            return false;
        }
    }

    private static readonly AsyncLocal<CancellationToken> OperationToken = new();

    // The legacy connection engine uses synchronous CLI helpers. Run the engine on
    // a worker and carry cancellation through every nested helper via async context.
    internal static Task<T> RunOperationAsync<T>(Func<Task<T>> operation, CancellationToken ct)
        => Task.Run(async () =>
        {
            CancellationToken previous = OperationToken.Value;
            OperationToken.Value = ct;
            try
            {
                ct.ThrowIfCancellationRequested();
                T result = await operation().ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                return result;
            }
            finally { OperationToken.Value = previous; }
        }, ct);

    public static Result Run(params string[] args)
        => RunAsync(OperationToken.Value, args).GetAwaiter().GetResult();

    public static async Task<Result> RunAsync(CancellationToken ct, params string[] args)
    {
        ct.ThrowIfCancellationRequested();
        string? exe = FindExecutable();
        if (string.IsNullOrEmpty(exe))
            return new Result { ExitCode = -1, StdErr = "warp-cli not found. Install Cloudflare WARP first." };
        return await WarpCommandRunner.RunAsync(exe, args, TimeSpan.FromSeconds(45), ct).ConfigureAwait(false);
    }

    internal static Task<Result> RunCleanupAsync(params string[] args)
    {
        string? exe = FindExecutable();
        return string.IsNullOrEmpty(exe)
            ? Task.FromResult(new Result { ExitCode = -1, StdErr = "warp-cli not found" })
            : WarpCommandRunner.RunAsync(exe, args, TimeSpan.FromSeconds(5));
    }

    public static Result AcceptTos() => Run("accept-tos");
    public static Result Register() => Run("registration", "new");
    public static Result Connect() => Run("connect");
    public static Result Disconnect() => Run("disconnect");
    public static Result Status() => Run("status");
    public static Result SetModeWarp() => Run("mode", "warp");
    /// <summary>Tunnel + DoH — sometimes more reliable when plain warp DNS path flaps under DPI.</summary>
    public static Result SetModeWarpDoh() => Run("mode", "warp+doh");
    /// <summary>Tunnel without WARP DNS proxy — lower overhead when DNSveil already handles DNS.</summary>
    public static Result SetModeTunnelOnly() => Run("mode", "tunnel_only");
    public static Result SetProtocol(string protocol) => Run("tunnel", "protocol", "set", protocol);
    public static Result SetMasqueOptions(string options) => Run("tunnel", "masque-options", "set", options);
    public static Result SetEndpoint(string endpoint) => Run("tunnel", "endpoint", "set", endpoint);
    public static Result ResetEndpoint() => Run("tunnel", "endpoint", "reset");
    public static Result ResetProtocol() => Run("tunnel", "protocol", "reset");

    /// <summary>
    /// warp-cli IPC is a named pipe. After CloudflareWARP start/restart the service
    /// can be Running while the daemon socket is not there yet (os error 2).
    /// </summary>
    public static async Task<bool> WaitForDaemonAsync(int timeoutMs, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            ct.ThrowIfCancellationRequested();
            Result st = Status();
            string t = st.Combined ?? "";
            bool missing =
                t.Contains("Unable to connect to the CloudflareWARP daemon", StringComparison.OrdinalIgnoreCase) ||
                t.Contains("Maybe the daemon is not running", StringComparison.OrdinalIgnoreCase) ||
                t.Contains("os error 2", StringComparison.OrdinalIgnoreCase);
            if (!missing && (st.Ok || t.Contains("Status update:", StringComparison.OrdinalIgnoreCase)))
                return true;
            await Task.Delay(400, ct).ConfigureAwait(false);
        }
        return false;
    }

    private static string? _expectProtocol;
    public static bool LastHandshakeUsedWireGuardPort { get; private set; }

    /// <summary>What warp-cli settings currently list as the tunnel protocol.</summary>
    public static string ReadEffectiveProtocol()
    {
        Result s = Run("settings", "list");
        foreach (string line in s.Combined.Split('\n'))
        {
            string t = line.Trim();
            if (!t.Contains("tunnel protocol", StringComparison.OrdinalIgnoreCase))
                continue;
            if (t.Contains("MASQUE", StringComparison.OrdinalIgnoreCase)) return "MASQUE";
            if (t.Contains("WireGuard", StringComparison.OrdinalIgnoreCase)) return "WireGuard";
        }
        return "";
    }

    private static bool LooksLikeWireGuardHandshake(string statusRaw) =>
        statusRaw.Contains(":2408", StringComparison.OrdinalIgnoreCase);

    private static string ExtractStatusReason(string statusRaw)
    {
        foreach (string line in statusRaw.Split('\n'))
        {
            string t = line.Trim();
            int idx = t.IndexOf("Reason:", StringComparison.OrdinalIgnoreCase);
            if (idx >= 0) return t[idx..].Trim();
            if (t.Contains("happy eyeballs", StringComparison.OrdinalIgnoreCase))
                return t;
        }
        return "";
    }

    private static void ApplyTunnelPrefs(string protocol, string? masqueOptions, IProgress<string>? progress)
    {
        LastHandshakeUsedWireGuardPort = false;
        _expectProtocol = protocol;

        // 2026.6 default is MASQUE; a leftover WireGuard consumer-override can ignore a bare `set`.
        if (protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
        {
            Result rst = ResetProtocol();
            WarpSessionLog.Cli("tunnel protocol reset", rst, always: true);
            Thread.Sleep(350);
        }

        Result p = SetProtocol(protocol);
        WarpSessionLog.Cli("tunnel protocol set " + protocol, p, always: true);
        if (!p.Ok) progress?.Report("WARN protocol set: " + p.ErrorLine);
        if (protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(masqueOptions))
        {
            Result m = SetMasqueOptions(masqueOptions);
            WarpSessionLog.Cli("tunnel masque-options set " + masqueOptions, m, always: true);
            if (!m.Ok) progress?.Report("WARN masque-options: " + m.ErrorLine);
        }

        Thread.Sleep(600);
        string effective = ReadEffectiveProtocol();
        WarpSessionLog.Step("protocol", "effective " + (string.IsNullOrEmpty(effective) ? "unknown" : effective),
            new Dictionary<string, object?> { ["wanted"] = protocol, ["effective"] = effective, ["masque"] = masqueOptions });

        if (string.IsNullOrEmpty(effective))
            progress?.Report($"Tunnel prefs: {protocol}" + (masqueOptions is null ? "" : " / " + masqueOptions) + " (settings unreadable)");
        else if (!effective.Equals(protocol, StringComparison.OrdinalIgnoreCase))
            progress?.Report($"WARN: you chose {protocol} but warp-cli settings still say {effective}");
        else
            progress?.Report($"Tunnel prefs: {effective}" + (masqueOptions is null ? "" : " / " + masqueOptions));
    }

    /// <summary>
    /// Apply MASQUE in settings. Do not <c>endpoint reset</c> — that loads WireGuard
    /// 162.159.192.9:2408 even when settings already say MASQUE. Do not bounce the
    /// service unless the daemon pipe is missing (restart races warp-cli with os error 2).
    /// </summary>
    public static async Task<bool> EnsureMasqueAppliedAsync(
        string masqueOptions,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        if (!await WaitForDaemonAsync(6000, ct).ConfigureAwait(false))
        {
            progress?.Report("warp-cli daemon not ready — restarting CloudflareWARP…");
            var (ok, msg) = await WarpPreflight.RestartWarpServiceAsync(progress, ct).ConfigureAwait(false);
            progress?.Report(msg);
            WarpSessionLog.Step("protocol", "service restart for MASQUE",
                new Dictionary<string, object?> { ["ok"] = ok, ["msg"] = msg });
            if (!await WaitForDaemonAsync(15000, ct).ConfigureAwait(false))
                progress?.Report("WARN: daemon still not answering after restart.");
        }

        AcceptTos();
        SetModeWarp();
        Run("debug", "high-timeouts", "enable");
        Result cc = Run("debug", "connectivity-check", "disable");
        WarpSessionLog.Cli("debug connectivity-check disable", cc, always: true);
        if (cc.Ok) progress?.Report("Connectivity-check off (IPv6 probe was poisoning happy-eyeballs).");
        await WaitUntilDisconnectedAsync(ct).ConfigureAwait(false);
        ApplyTunnelPrefs("MASQUE", masqueOptions, progress);
        await Task.Delay(400, ct).ConfigureAwait(false);

        string eff = ReadEffectiveProtocol();
        progress?.Report("warp-cli protocol=" + (string.IsNullOrEmpty(eff) ? "unknown" : eff) + " (not resetting endpoint — that forces :2408)");
        return !eff.Equals("WireGuard", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly string[] MasqueTcpEndpoints =
    {
        "162.159.197.1:443",
        "162.159.197.2:443",
        "162.159.197.3:443",
        "162.159.198.1:443",
        "162.159.198.2:443",
        "162.159.198.3:443",
        "188.114.96.1:443",
        "188.114.97.1:443",
        "188.114.98.1:443",
    };

    private static string NormalizeMasqueEndpoint(string endpoint)
    {
        endpoint = endpoint.Trim();
        int colon = endpoint.LastIndexOf(':');
        if (colon > 0 && int.TryParse(endpoint[(colon + 1)..], out int port))
        {
            if (port is 443 or 8443 or 4443)
                return endpoint;
            return endpoint[..colon] + ":443";
        }
        return endpoint + ":443";
    }

    private static List<string> BuildMasqueTargetList(
        IEnumerable<string>? userEndpoints,
        IEnumerable<string>? extra = null)
    {
        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return;
            string e = NormalizeMasqueEndpoint(raw);
            if (seen.Add(e)) list.Add(e);
        }
        if (userEndpoints != null)
        {
            foreach (string e in userEndpoints)
                Add(e);
        }
        if (extra != null)
        {
            foreach (string e in extra)
                Add(e);
        }
        foreach (string e in MasqueTcpEndpoints)
            Add(e);
        return list;
    }

    private static async Task<string> ProbeTlsAsync(string endpoint, CancellationToken ct)
    {
        try
        {
            int colon = endpoint.LastIndexOf(':');
            if (colon <= 0 || !int.TryParse(endpoint[(colon + 1)..], out int port))
                return "tls-skip";
            string host = endpoint[..colon];
            using TcpClient client = new();
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(4000);
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using SslStream ssl = new(client.GetStream(), false, static (_, _, _, _) => true);
            var opts = new SslClientAuthenticationOptions
            {
                TargetHost = "engage.cloudflareclient.com",
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            };
            await ssl.AuthenticateAsClientAsync(opts, linked.Token).ConfigureAwait(false);
            return "tls-ok " + ssl.SslProtocol + "/" + ssl.NegotiatedCipherSuite;
        }
        catch (Exception ex)
        {
            return "tls-fail " + ex.GetType().Name + ": " + (ex.InnerException?.Message ?? ex.Message);
        }
    }

    private static async Task<bool> TcpConnectAsync(string endpoint, int timeoutMs, CancellationToken ct)
    {
        try
        {
            int colon = endpoint.LastIndexOf(':');
            if (colon <= 0 || !int.TryParse(endpoint[(colon + 1)..], out int port))
                return false;
            string host = endpoint[..colon];
            using TcpClient client = new();
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeoutMs);
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            return client.Connected;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Pin MASQUE HTTP/2 TCP endpoints. Consumer default after <c>endpoint reset</c> is
    /// WireGuard :2408 even when settings say MASQUE.
    /// </summary>
    private static async Task<(bool Ok, string Message, string? Endpoint, string Protocol)?> TryMasqueTcpEndpointsAsync(
        IReadOnlyList<string> endpoints,
        string masqueOpt,
        CensorshipOptions censorship,
        IProgress<string>? progress,
        CancellationToken ct,
        bool skipTcpProbe = false)
    {
        progress?.Report($"Pinning MASQUE {masqueOpt} on {endpoints.Count} TCP :443 endpoint(s)…");
        foreach (string endpoint in endpoints)
        {
            ct.ThrowIfCancellationRequested();
            if (!skipTcpProbe)
            {
                bool tcp = await TcpConnectAsync(endpoint, 1800, ct).ConfigureAwait(false);
                WarpSessionLog.Step("probe", tcp ? "tcp-open " + endpoint : "tcp-closed " + endpoint,
                    new Dictionary<string, object?> { ["endpoint"] = endpoint, ["tcp"] = tcp });
                if (!tcp)
                {
                    progress?.Report($"Skip {endpoint}: TCP not open (blocked or filtered).");
                    continue;
                }
            }

            await WaitUntilDisconnectedAsync(ct).ConfigureAwait(false);
            ApplyTunnelPrefs("MASQUE", masqueOpt, progress);
            Result set = SetEndpoint(endpoint);
            WarpSessionLog.Cli("tunnel endpoint set " + endpoint, set, always: true);
            if (!set.Ok)
            {
                progress?.Report($"Skip {endpoint}: {set.ErrorLine}");
                continue;
            }
            progress?.Report($"MASQUE {masqueOpt} @ {endpoint} (TCP open)…");
            await Task.Delay(250, ct).ConfigureAwait(false);
            if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: false, masquePin: true).ConfigureAwait(false) &&
                await StabilizeConnectedAsync(progress, ct, soft: true).ConfigureAwait(false))
            {
                if (LastHandshakeUsedWireGuardPort)
                {
                    progress?.Report($"{endpoint} ignored by daemon — still :2408.");
                    continue;
                }
                var accepted = await QualifyOrRejectAsync(
                    endpoint, "MASQUE", censorship, progress, ct, WarpSessionLog.ElapsedMs, fromCache: false).ConfigureAwait(false);
                if (accepted != null) return accepted;
            }
        }
        return null;
    }

    public static bool HasRegistration()
    {
        Result show = Run("registration", "show");
        if (IsRegistrationPresent(show)) return true;
        Result showJson = Run("-j", "registration", "show");
        return IsRegistrationPresent(showJson);
    }

    public static bool EnsureRegistration(IProgress<string>? progress = null)
    {
        if (HasRegistration()) return true;
        progress?.Report("Creating WARP registration…");
        Result reg = Register();
        AcceptTos();
        if (HasRegistration()) return true;
        progress?.Report("Registration failed: " + reg.ErrorLine);
        return false;
    }

    private static bool IsRegistrationPresent(Result r)
    {
        string t = r.Combined;
        if (string.IsNullOrWhiteSpace(t)) return false;
        if (t.Contains("not registered", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("No registration", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("Missing registration", StringComparison.OrdinalIgnoreCase))
            return false;
        if (t.Contains("Account type", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("Device ID", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("License", StringComparison.OrdinalIgnoreCase))
            return true;
        if (t.Contains("account_type", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("\"device_id\"", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    public static string ParseStatus(Result r)
    {
        string text = r.Combined;
        foreach (string line in text.Split('\n'))
        {
            string s = line.Trim();
            if (s.StartsWith("Status update:", StringComparison.OrdinalIgnoreCase) ||
                s.StartsWith("Status:", StringComparison.OrdinalIgnoreCase))
                return s;
        }
        foreach (string line in text.Split('\n'))
        {
            string s = line.Trim();
            if (s.Contains("Connected", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("Disconnected", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("Connecting", StringComparison.OrdinalIgnoreCase))
                return s;
        }
        return string.IsNullOrWhiteSpace(r.StdOut) ? (r.Ok ? "Unknown" : r.ErrorLine) : r.StdOut.Split('\n')[0].Trim();
    }

    public static bool IsConnected(Result status)
    {
        foreach (string line in status.Combined.Split('\n'))
        {
            string s = line.Trim();
            if (!s.StartsWith("Status", StringComparison.OrdinalIgnoreCase)) continue;

            int colon = s.IndexOf(':');
            string value = colon >= 0 ? s[(colon + 1)..].Trim() : s;
            if (value.Equals("Connected", StringComparison.OrdinalIgnoreCase))
                return true;
            return false;
        }
        return false;
    }

    public static IEnumerable<string> EnumerateEndpointCandidates(string protocol = "WireGuard", int maxCount = 24)
    {
        if (maxCount <= 0) yield break;

        bool masque = protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase);
        int[] ports = masque ? MasquePorts : WireGuardPorts.Take(8).ToArray();

        var hosts = new List<string> { EngageHosts[0] };
        var ips = EngageHosts.Skip(1).ToList();
        Shuffle(ips);
        hosts.AddRange(ips);

        int n = 0;
        foreach (string host in hosts)
        {
            foreach (int port in ports)
            {
                yield return $"{host}:{port}";
                if (++n >= maxCount) yield break;
            }
        }
    }

    /// <summary>
    /// Build a large Iran/censorship-oriented candidate list:
    /// IRCF live endpoints + known engage hosts + random samples from WARP CF CIDRs.
    /// Prefer MASQUE :443 (looks like HTTPS; H2 TCP fallback works with TLS fragment).
    /// </summary>
    public static async Task<List<string>> BuildCensorshipCandidatesAsync(
        string preferredProtocol,
        CensorshipOptions opt,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool preferMasque = preferredProtocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase);

        // 1) Live IRCF community list (Iran-curated)
        progress?.Report("Fetching IRCF community endpoints…");
        foreach (string ep in await FetchIrcfEndpointsAsync(ct).ConfigureAwait(false))
            set.Add(ep);

        // 2) Hardcoded engage + IRCF-like seeds
        foreach (string host in EngageHosts.Skip(1))
        {
            set.Add($"{host}:443");
            set.Add($"{host}:8443");
            set.Add($"{host}:2408");
            set.Add($"{host}:500");
            set.Add($"{host}:4500");
            set.Add($"{host}:1701");
        }

        // 3) Random samples from WARP CF CIDRs × MASQUE ports (patterniha: TCP scan, not ICMP)
        progress?.Report("Sampling Cloudflare WARP CIDRs (TCP probe targets)…");
        int[] ports = preferMasque
            ? MasquePorts
            : new[] { 2408, 500, 4500, 1701, 878, 894, 903, 1002, 4177, 7281, 8886 };
        foreach (string cidr in WarpScanCidrs)
        {
            foreach (IPAddress ip in SampleCidr(cidr, opt.CidrSamplePerRange))
            {
                foreach (int port in ports.Take(preferMasque ? 2 : 4))
                    set.Add($"{ip}:{port}");
            }
        }

        List<string> list = set.ToList();
        Shuffle(list);

        // Put preferred protocol's ports first
        if (preferMasque)
        {
            list = list
                .OrderBy(e => e.EndsWith(":443") ? 0 : e.EndsWith(":8443") ? 1 : 2)
                .ThenBy(_ => Random.Shared.Next())
                .ToList();
        }
        else
        {
            list = list
                .OrderBy(e =>
                    e.EndsWith(":2408") ? 0 :
                    e.EndsWith(":500") ? 1 :
                    e.EndsWith(":4500") ? 2 : 3)
                .ThenBy(_ => Random.Shared.Next())
                .ToList();
        }

        if (list.Count > opt.MaxCandidates)
            list = list.Take(opt.MaxCandidates).ToList();

        progress?.Report($"Built {list.Count} censorship-resistant candidates" +
                         (preferMasque ? " (MASQUE ports)." : " (WireGuard UDP ports)."));
        return list;
    }

    public static async Task<List<string>> FetchIrcfEndpointsAsync(CancellationToken ct)
    {
        if (_cachedIrcf != null && (DateTime.UtcNow - _cachedIrcfAt).TotalMinutes < 30)
            return _cachedIrcf;

        var found = new List<string>();
        foreach (string url in IrcfEndpointUrls)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(8000);
                string json = await SharedHttp.GetStringAsync(url, cts.Token).ConfigureAwait(false);
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement root = doc.RootElement;

                void AddArr(JsonElement arr)
                {
                    if (arr.ValueKind != JsonValueKind.Array) return;
                    foreach (JsonElement el in arr.EnumerateArray())
                    {
                        string? s = el.GetString();
                        if (!string.IsNullOrWhiteSpace(s) && s.Contains(':') && !s.Contains('['))
                            found.Add(s.Trim());
                    }
                }

                if (root.TryGetProperty("masque", out JsonElement masque))
                {
                    if (masque.TryGetProperty("ipv4", out JsonElement m4)) AddArr(m4);
                }
                if (root.TryGetProperty("warp", out JsonElement warp))
                {
                    if (warp.TryGetProperty("ipv4", out JsonElement w4)) AddArr(w4);
                }
                // legacy ip.json shape
                if (root.TryGetProperty("ipv4", out JsonElement legacy)) AddArr(legacy);

                if (found.Count > 0) break;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("FetchIrcfEndpointsAsync: " + ex.Message);
            }
        }

        // Static IRCF v2 fallback seeds if network fetch failed
        if (found.Count == 0)
        {
            found.AddRange(new[]
            {
                "162.159.198.0:443", "162.159.198.1:443", "162.159.198.2:443",
                "162.159.192.1:2408", "162.159.192.1:500", "162.159.192.1:4500",
                "162.159.192.2:878", "162.159.192.64:894", "162.159.192.8:903",
                "162.159.195.1:4177", "162.159.195.3:878", "188.114.96.24:1002",
                "188.114.97.6:7281", "8.6.112.224:8886",
            });
        }

        _cachedIrcf = found.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        _cachedIrcfAt = DateTime.UtcNow;
        return _cachedIrcf;
    }

    public static async Task<(bool Ok, string Message, string? Endpoint, string Protocol)> TryConnectWithFallbackAsync(
        IEnumerable<string>? endpoints,
        string preferredProtocol = "WireGuard",
        IProgress<string>? progress = null,
        CancellationToken ct = default,
        CensorshipOptions? censorship = null)
        => await RunOperationAsync(() => censorship?.TryExitOutsideIran == true
            ? TryRegionalExitAsync(endpoints, preferredProtocol, progress, ct, censorship)
            : TryConnectCoreAsync(endpoints, preferredProtocol, progress, ct, censorship), ct).ConfigureAwait(false);

    private static async Task<(bool Ok, string Message, string? Endpoint, string Protocol)> TryRegionalExitAsync(
        IEnumerable<string>? endpoints, string protocol, IProgress<string>? progress,
        CancellationToken ct, CensorshipOptions opt)
    {
        var requested = endpoints?.ToList();
        var result = await WarpRegionalSearch.RunAsync(async (round, token) =>
        {
            string candidateProtocol = round == 1
                ? (protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase) ? "WireGuard" : "MASQUE")
                : protocol;
            IEnumerable<string>? candidate = round == 0 ? requested : null;
            if (round == 2 && candidateProtocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
                candidate = new[] { MasqueTcpEndpoints.FirstOrDefault(ep => requested == null || !requested.Contains(ep)) ?? MasqueTcpEndpoints[0] };
            var connected = await RunOperationAsync(() => TryConnectCoreAsync(candidate, candidateProtocol, progress, token,
                opt with { TryExitOutsideIran = false, MaxConnectAttempts = 1, RequireLinkQuality = false,
                    TryWireGuardUpgrade = false, ApplyIranExcludes = false, DpiAssist = false }), token).ConfigureAwait(false);
            return new WarpRegionalSearch.Connection(connected.Ok, connected.Message, connected.Endpoint, connected.Protocol);
        }, WarpExitCheck.FetchAsync, async connection =>
        {
            if (connection?.Endpoint != null) WarpSuccessCache.Demote(connection.Endpoint);
            Result disconnected = await RunCleanupAsync("disconnect").ConfigureAwait(false);
            if (!disconnected.Ok) progress?.Report("WARN: disconnect was not confirmed: " + disconnected.ErrorLine);
            await WarpDpiAssist.StopAsync().ConfigureAwait(false);
        }, "IR", progress, ct).ConfigureAwait(false);
        return (result.Ok, result.Message, result.Endpoint, result.Protocol);
    }

    private static async Task<(bool Ok, string Message, string? Endpoint, string Protocol)> TryConnectCoreAsync(
        IEnumerable<string>? endpoints, string preferredProtocol, IProgress<string>? progress,
        CancellationToken ct, CensorshipOptions? censorship)
    {
        censorship ??= new CensorshipOptions { Enabled = false, DpiAssist = false };

        WarpSessionLog.Step("connect", "TryConnectWithFallback start",
            new Dictionary<string, object?>
            {
                ["preferredProtocol"] = preferredProtocol,
                ["censorship"] = censorship.Enabled,
                ["dpi"] = censorship.DpiAssist,
                ["lowLatency"] = censorship.LowLatency,
                ["iranExcludes"] = censorship.ApplyIranExcludes,
                ["wgUpgrade"] = censorship.TryWireGuardUpgrade,
            });
        LogEnvironmentSnapshot();

        if (!IsInstalled())
        {
            WarpSessionLog.Decision("reject", "warp-cli not installed");
            return (false, "Cloudflare WARP (warp-cli) is not installed.", null, preferredProtocol);
        }

        // Ensure Windows service is up (auto-start if stopped).
        var (svcOk, svcMsg, _) = await WarpPreflight.EnsureWarpServiceAsync(progress, ct).ConfigureAwait(false);
        if (!svcOk)
        {
            WarpSessionLog.Step("connect", "service failed: " + svcMsg);
            return (false, svcMsg, null, preferredProtocol);
        }

        // MASQUE :443 is TLS. FakeTTL/WinDivert was mangling that handshake (logs: TCP :443 then Unable).
        // WireGuard UDP still benefits from DPI up front.
        bool masquePath = !preferredProtocol.Equals("WireGuard", StringComparison.OrdinalIgnoreCase);
        if (censorship.DpiAssist && !masquePath)
        {
            var (dpiOk, dpiMsg) = await WarpDpiAssist.StartProfileAsync(MasqueDpiProfile.LightFrag, progress).ConfigureAwait(false);
            progress?.Report(dpiMsg);
            WarpSessionLog.Step("dpi", dpiMsg, new Dictionary<string, object?> { ["ok"] = dpiOk, ["profile"] = "LightFrag" });
            if (!dpiOk)
                progress?.Report("Continuing without DPI assist…");
        }
        else if (masquePath)
        {
            await WarpDpiAssist.StopAsync().ConfigureAwait(false);
            progress?.Report("MASQUE: IPv4-only handshake first (no TLS split).");
        }

        AcceptTos();
        Disconnect();

        if (!EnsureRegistration(progress))
        {
            if (censorship.DpiAssist) await WarpDpiAssist.StopAsync().ConfigureAwait(false);
            WarpSessionLog.Step("connect", "registration failed");
            return (false, "WARP registration failed. Open the official WARP app once (or enable DPI assist), accept the ToS, then retry.", null, preferredProtocol);
        }

        if (censorship.Enabled)
        {
            progress?.Report(preferredProtocol.Equals("WireGuard", StringComparison.OrdinalIgnoreCase)
                ? "Stability: high-timeouts ON (WireGuard UDP path)…"
                : "Stability: high-timeouts ON + MASQUE h2-only…");
            Result hi = Run("debug", "high-timeouts", "enable");
            WarpSessionLog.Step("mode", "high-timeouts enable",
                new Dictionary<string, object?>
                {
                    ["ok"] = hi.Ok,
                    ["out"] = hi.Combined,
                    ["protocol"] = preferredProtocol,
                });
        }

        Result mode = SetModeWarp();
        WarpSessionLog.Step("mode", "warp before connect",
            new Dictionary<string, object?>
            {
                ["ok"] = mode.Ok,
                ["out"] = mode.Combined,
                ["lowLatency"] = censorship.LowLatency,
            });
        if (!mode.Ok)
            progress?.Report("WARN mode warp: " + mode.ErrorLine);
        if (censorship.LowLatency)
            progress?.Report("Mode: warp + post-connect DPI stop (Iran excludes off by default)…");

        // First shot: Cloudflare default endpoint (no force) — often works when forced IPs hang.
        if (censorship.Enabled || endpoints == null || !endpoints.Any())
        {
            string defProto = preferredProtocol.Equals("WireGuard", StringComparison.OrdinalIgnoreCase)
                ? "WireGuard"
                : (censorship.Enabled ? "MASQUE" : preferredProtocol);

            if (defProto.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
            {
                string masqueOpt = censorship.Enabled ? "h2-only" : "h3-with-h2-fallback";
                WarpPreflight.Ipv4HandshakeGuard? ipv4 = null;
                try
                {
                    ipv4 = await WarpPreflight.ForceIpv4HandshakeAsync(progress, ct).ConfigureAwait(false);
                    await EnsureMasqueAppliedAsync(masqueOpt, progress, ct).ConfigureAwait(false);

                    List<string> ircf443 = new();
                    try
                    {
                        foreach (string e in await FetchIrcfEndpointsAsync(ct).ConfigureAwait(false))
                        {
                            if (e.EndsWith(":443", StringComparison.Ordinal) ||
                                e.EndsWith(":8443", StringComparison.Ordinal) ||
                                e.EndsWith(":4443", StringComparison.Ordinal))
                                ircf443.Add(e);
                        }
                    }
                    catch { /* IRCF is optional */ }

                    List<string> masqueTargets = BuildMasqueTargetList(endpoints, ircf443)
                        .Take(Math.Max(1, censorship.MaxConnectAttempts)).ToList();
                    progress?.Report("MASQUE targets: " + string.Join(", ", masqueTargets.Take(8)) +
                                     (masqueTargets.Count > 8 ? "…" : ""));

                    var tcpOpen = new List<string>();
                    foreach (string ep in masqueTargets)
                    {
                        ct.ThrowIfCancellationRequested();
                        bool tcp = await TcpConnectAsync(ep, 1800, ct).ConfigureAwait(false);
                        WarpSessionLog.Step("probe", tcp ? "tcp-open " + ep : "tcp-closed " + ep,
                            new Dictionary<string, object?> { ["endpoint"] = ep, ["tcp"] = tcp });
                        if (tcp) tcpOpen.Add(ep);
                        else progress?.Report($"Skip {ep}: TCP not open (blocked or filtered).");
                    }

                    if (tcpOpen.Count == 0)
                    {
                        progress?.Report("No MASQUE IP accepted TCP :443 from this network.");
                        WarpSessionLog.Step("connect", "masque tcp all closed");
                        return (false,
                            "No Cloudflare MASQUE IP accepted TCP :443. Official warp-cli cannot open a path while those IPs are filtered. Paste a working IP:443 if you have one.",
                            null, "MASQUE");
                    }

                    string tls = await ProbeTlsAsync(tcpOpen[0], ct).ConfigureAwait(false);
                    progress?.Report("TLS probe " + tcpOpen[0] + ": " + tls);
                    WarpSessionLog.Step("probe", tls, new Dictionary<string, object?> { ["endpoint"] = tcpOpen[0] });

                    progress?.Report($"{tcpOpen.Count} MASQUE :443 IP(s) accept TCP — IPv4-only handshake, no DPI…");
                    var pinned = await TryMasqueTcpEndpointsAsync(
                        tcpOpen, masqueOpt, censorship, progress, ct, skipTcpProbe: true).ConfigureAwait(false);
                    if (pinned != null) return pinned.Value;

                    if (censorship.DpiAssist)
                    {
                        MasqueDpiProfile[] ladder = WarpDpiAssist.GetMasqueLadder();
                        progress?.Report("Handshake still failing — DPI without TLS split: " +
                                         string.Join(" → ", ladder.Select(WarpDpiAssist.ProfileLabel)));
                        foreach (MasqueDpiProfile profile in ladder)
                        {
                            ct.ThrowIfCancellationRequested();
                            var (dok, dmsg) = await WarpDpiAssist.StartProfileAsync(profile, progress).ConfigureAwait(false);
                            progress?.Report(dmsg);
                            if (!dok) continue;
                            var dpiPinned = await TryMasqueTcpEndpointsAsync(
                                tcpOpen, masqueOpt, censorship, progress, ct, skipTcpProbe: true).ConfigureAwait(false);
                            if (dpiPinned != null) return dpiPinned.Value;
                        }
                        await WarpDpiAssist.StopAsync().ConfigureAwait(false);
                    }

                    progress?.Report("MASQUE TCP :443 did not complete. Not falling back to WireGuard :2408 (blocked here).");
                    if (censorship.DpiAssist) await WarpDpiAssist.StopAsync().ConfigureAwait(false);
                    WarpSessionLog.Step("connect", "masque :443 exhausted");
                    return (false,
                        "TCP :443 reached Cloudflare but the WARP MASQUE handshake did not finish. Paste another IP:443 if you have one, or retry.",
                        null, "MASQUE");
                }
                finally
                {
                    try { await RunCleanupAsync("debug", "connectivity-check", "enable").ConfigureAwait(false); } catch { /* ignore */ }
                    if (ipv4 != null)
                    {
                        progress?.Report("Restoring IPv6 on NICs…");
                        await ipv4.DisposeAsync().ConfigureAwait(false);
                    }
                }
            }
            else
            {
                progress?.Report($"First try: Cloudflare default endpoint ({defProto})…");
                await WaitUntilDisconnectedAsync(ct).ConfigureAwait(false);
                ApplyTunnelPrefs(defProto, null, progress);
                ResetEndpoint();
                await Task.Delay(500, ct).ConfigureAwait(false);
                if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false) &&
                    await StabilizeConnectedAsync(progress, ct, soft: censorship.Enabled).ConfigureAwait(false))
                {
                    var accepted = await QualifyOrRejectAsync(
                        null, defProto, censorship, progress, ct, WarpSessionLog.ElapsedMs, fromCache: false).ConfigureAwait(false);
                    if (accepted != null) return accepted.Value;
                }
            }

            // Consumer warp-cli 2026: default HE is :2408 unless MASQUE actually loaded.
            if (defProto.Equals("MASQUE", StringComparison.OrdinalIgnoreCase) &&
                !LastHandshakeUsedWireGuardPort)
            {
                progress?.Report("Default h2 path failed — retry default with h3-with-h2-fallback…");
                await WaitUntilDisconnectedAsync(ct).ConfigureAwait(false);
                ApplyTunnelPrefs("MASQUE", "h3-with-h2-fallback", progress);
                ResetEndpoint();
                if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false) &&
                    await StabilizeConnectedAsync(progress, ct, soft: true).ConfigureAwait(false) &&
                    !LastHandshakeUsedWireGuardPort)
                {
                    var accepted = await QualifyOrRejectAsync(
                        null, "MASQUE", censorship, progress, ct, WarpSessionLog.ElapsedMs, fromCache: false).ConfigureAwait(false);
                    if (accepted != null) return accepted.Value;
                }
            }

            if (!defProto.Equals("WireGuard", StringComparison.OrdinalIgnoreCase) &&
                !LastHandshakeUsedWireGuardPort)
            {
                progress?.Report("Default MASQUE failed — retry Cloudflare default as WireGuard…");
                await WaitUntilDisconnectedAsync(ct).ConfigureAwait(false);
                ApplyTunnelPrefs("WireGuard", null, progress);
                ResetEndpoint();
                if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false) &&
                    await StabilizeConnectedAsync(progress, ct, soft: true).ConfigureAwait(false))
                {
                    var accepted = await QualifyOrRejectAsync(
                        null, "WireGuard", censorship, progress, ct, WarpSessionLog.ElapsedMs, fromCache: false).ConfigureAwait(false);
                    if (accepted != null) return accepted.Value;
                }
            }

            progress?.Report("Default endpoint variants failed.");
            await WaitUntilDisconnectedAsync(ct).ConfigureAwait(false);
            ResetEndpoint();
        }

        List<string> list = endpoints?.Where(e => !string.IsNullOrWhiteSpace(e)).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                            ?? new List<string>();

        // Known-good seed only when the user pasted a list — do not auto-force CF IPs
        // (warp-cli 2026 consumer goes Unable on tunnel endpoint set).
        if (censorship.Enabled && list.Count > 0 && endpoints != null)
        {
            // user-specified endpoints only
        }
        else if (censorship.Enabled && (endpoints == null || list.Count == 0))
        {
            list.Clear();
            WarpSessionLog.Step("scan", "skipped forced-IP scan (warp-cli 2026 Unable on endpoint set)");
            progress?.Report("Skipping IP scan — using Cloudflare default only.");
        }

        List<string> remembered = WarpSuccessCache.GetRecentEndpoints(protocol: preferredProtocol);
        // Do not replay cached IPs via `tunnel endpoint set` — warp-cli 2026 consumer returns Unable.
        if (remembered.Count > 0)
            progress?.Report($"Remembered {remembered.Count} endpoint(s) — not forcing them (warp-cli 2026).");

        if (censorship.Enabled && list.Count == 0)
        {
            WarpSessionLog.Step("scan", "no forced-IP scan");
        }

        // Only scan/force IPs when the user pasted a specific endpoint list.
        if (censorship.Enabled && list.Count > 0 && endpoints != null)
        {
            WarpSessionLog.Step("scan", $"user endpoints: {list.Count}");
        }

        // Single proven strategy (3.5.8–3.5.10): Light DPI + one protocol + full endpoint list.
        string[] protocols = preferredProtocol.Equals("WireGuard", StringComparison.OrdinalIgnoreCase)
            ? new[] { "WireGuard" }
            : censorship.Enabled
                ? new[] { "MASQUE" }
                : new[] { preferredProtocol };

        foreach (string protocol in protocols)
        {
            ct.ThrowIfCancellationRequested();
            string masqueOpt = censorship.Enabled ? "h2-only" : "h3-with-h2-fallback";
            ApplyTunnelPrefs(protocol, protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase) ? masqueOpt : null, progress);

            List<string> tryList = list;
            if (censorship.Enabled && list.Count > 0 &&
                protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
            {
                List<string> masquePorts = list
                    .Where(e => e.EndsWith(":443") || e.EndsWith(":8443") || e.EndsWith(":4443") || e.EndsWith(":8095"))
                    .ToList();
                tryList = masquePorts.Count > 0
                    ? masquePorts.Concat(list.Except(masquePorts, StringComparer.OrdinalIgnoreCase)).ToList()
                    : list;
            }
            if (remembered.Count > 0 && endpoints != null && list.Count > 0)
            {
                tryList = remembered
                    .Concat(tryList)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            if (tryList.Count == 0)
            {
                progress?.Report($"Connecting with Cloudflare default endpoint ({protocol})…");
                ResetEndpoint();
                if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false) &&
                    await StabilizeConnectedAsync(progress, ct, soft: censorship.Enabled).ConfigureAwait(false))
                {
                    var accepted = await QualifyOrRejectAsync(
                        null, protocol, censorship, progress, ct, WarpSessionLog.ElapsedMs, fromCache: false).ConfigureAwait(false);
                    if (accepted != null) return accepted.Value;
                }
                continue;
            }

            int takeN = censorship.Enabled ? Math.Max(censorship.MaxConnectAttempts, 14) : 12;
            progress?.Report($"Probing {tryList.Count} endpoints ({protocol})…");
            List<string> reachable = await FilterReachableEndpointsAsync(
                tryList, protocol, progress, ct, censorship.ProbeTimeoutMs,
                take: takeN).ConfigureAwait(false);

            if (reachable.Count == 0)
            {
                progress?.Report("Probe empty — trying seed/IRCF top entries anyway…");
                reachable = tryList.Take(takeN).ToList();
            }
            else
                progress?.Report($"{reachable.Count} reachable — connecting (fastest first)…");

            if (remembered.Count > 0 && endpoints != null && list.Count > 0)
            {
                foreach (string rem in remembered.AsEnumerable().Reverse())
                {
                    if (!reachable.Contains(rem, StringComparer.OrdinalIgnoreCase))
                        reachable.Insert(0, rem);
                    else
                    {
                        reachable.RemoveAll(e => string.Equals(e, rem, StringComparison.OrdinalIgnoreCase));
                        reachable.Insert(0, rem);
                    }
                }
                reachable = reachable.Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(takeN)
                    .ToList();
            }

            // Prefer historically working hosts at the front
            string[] preferHosts = { "162.159.198.49", "162.159.199.85", "162.159.192.1", "188.114.98.224" };
            reachable = reachable
                .OrderBy(e => preferHosts.Any(h => e.StartsWith(h, StringComparison.OrdinalIgnoreCase)) ? 0 : 1)
                .ThenBy(e => reachable.IndexOf(e))
                .ToList();

            RememberCandidatePool(reachable.Concat(tryList));
            WarpSessionLog.Step("probe", $"reachable={reachable.Count}",
                new Dictionary<string, object?>
                {
                    ["protocol"] = protocol,
                    ["endpoints"] = string.Join(", ", reachable.Take(12)),
                });

            // Escalate DPI mid-scan when handshakes stick on Connecting (common under IR DPI).
            MasqueDpiProfile[] dpiLadder = censorship.DpiAssist
                ? WarpDpiAssist.GetMasqueLadder()
                : Array.Empty<MasqueDpiProfile>();
            int dpiIdx = 0;
            int stuckStreak = 0;
            decimal[] fragLadder = { 2, 2, 3, 1 };
            string[] masqueLadder = censorship.Enabled
                ? new[] { "h2-only", "h2-only", "h3-with-h2-fallback", "h2-only" }
                : new[] { masqueOpt };

            int n = 0;
            foreach (string endpoint in reachable)
            {
                ct.ThrowIfCancellationRequested();
                n++;

                if (censorship.DpiAssist && stuckStreak >= 2 && dpiIdx + 1 < dpiLadder.Length)
                {
                    dpiIdx++;
                    stuckStreak = 0;
                    masqueOpt = masqueLadder[Math.Min(dpiIdx, masqueLadder.Length - 1)];
                    decimal frag = fragLadder[Math.Min(dpiIdx, fragLadder.Length - 1)];
                    progress?.Report($"Handshake stalled — escalating DPI to {WarpDpiAssist.ProfileLabel(dpiLadder[dpiIdx])} + {masqueOpt}…");
                    var (dok, dmsg) = await WarpDpiAssist.StartProfileAsync(dpiLadder[dpiIdx], progress, frag).ConfigureAwait(false);
                    progress?.Report(dmsg);
                    WarpSessionLog.Step("dpi", "escalate " + dpiLadder[dpiIdx],
                        new Dictionary<string, object?> { ["ok"] = dok, ["masque"] = masqueOpt, ["fragment"] = frag });
                }

                progress?.Report($"[{n}/{reachable.Count}] Connecting {endpoint} ({protocol}/{masqueOpt})…");
                WarpSessionLog.BeginAttempt(endpoint, protocol, n, reachable.Count);
                long t0 = WarpSessionLog.ElapsedMs;
                Disconnect();
                await WaitUntilDisconnectedAsync(ct, 5000).ConfigureAwait(false);
                ApplyTunnelPrefs(protocol, protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase) ? masqueOpt : null, progress);
                Result setEp = SetEndpoint(endpoint);
                WarpSessionLog.Cli("tunnel endpoint set " + endpoint, setEp, always: true);
                if (!setEp.Ok)
                {
                    progress?.Report($"Skip {endpoint}: {setEp.ErrorLine}");
                    continue;
                }

                if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false))
                {
                    stuckStreak = 0;
                    PublicIpInfo info = await FetchPublicIpInfoAsync(8000).ConfigureAwait(false);
                    WarpSessionLog.Egress(info.Source ?? "trace", info,
                        new Dictionary<string, object?>
                        {
                            ["endpoint"] = endpoint,
                            ["protocol"] = protocol,
                            ["status"] = ParseStatus(Status()),
                        });
                    if (info.WarpOn == true &&
                        await StabilizeConnectedAsync(progress, ct, soft: censorship.Enabled).ConfigureAwait(false))
                    {
                        var accepted = await QualifyOrRejectAsync(
                            endpoint, protocol, censorship, progress, ct, t0, fromCache: false).ConfigureAwait(false);
                        if (accepted != null) return accepted.Value;
                        continue;
                    }
                    progress?.Report(info.WarpOn == true
                        ? "Unstable after settle — next…"
                        : "Connected status but warp≠on — next…");
                }
                else
                {
                    stuckStreak++;
                    progress?.Report($"No connect on {endpoint}: {ParseStatus(Status())}");
                    WarpSessionLog.AttemptResult(endpoint, protocol, "reject-not-connected",
                        WarpSessionLog.ElapsedMs - t0,
                        new Dictionary<string, object?>
                        {
                            ["status"] = ParseStatus(Status()),
                            ["stuckStreak"] = stuckStreak,
                            ["dpi"] = dpiIdx < dpiLadder.Length ? dpiLadder[dpiIdx].ToString() : "none",
                        });
                }
            }

            // Last MASQUE pass: warp+doh only when the user pasted endpoints (forced IPs break warp-cli 2026).
            if (censorship.Enabled &&
                endpoints != null && list.Count > 0 &&
                protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
            {
                progress?.Report("Trying mode warp+doh with remaining seeds…");
                Result md = SetModeWarpDoh();
                WarpSessionLog.Cli("mode warp+doh", md, always: true);
                ApplyTunnelPrefs("MASQUE", "h2-only", progress);
                if (censorship.DpiAssist)
                {
                    var (dok, dmsg) = await WarpDpiAssist.StartAsync(DPIBasic.DPIBasicBypassMode.Medium, progress).ConfigureAwait(false);
                    progress?.Report(dmsg);
                }
                List<string> lastTry = reachable.Take(6).ToList();
                if (lastTry.Count == 0)
                    lastTry = new List<string> { "162.159.198.49:443", "162.159.199.85:443" };
                int li = 0;
                foreach (string endpoint in lastTry)
                {
                    ct.ThrowIfCancellationRequested();
                    li++;
                    progress?.Report($"[warp+doh {li}/{lastTry.Count}] {endpoint}…");
                    Disconnect();
                    await Task.Delay(300, ct).ConfigureAwait(false);
                    if (!SetEndpoint(endpoint).Ok) continue;
                    long t0 = WarpSessionLog.ElapsedMs;
                    if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false))
                    {
                        PublicIpInfo info = await FetchPublicIpInfoAsync(8000).ConfigureAwait(false);
                        if (info.WarpOn == true &&
                            await StabilizeConnectedAsync(progress, ct, soft: true).ConfigureAwait(false))
                        {
                            var accepted = await QualifyOrRejectAsync(
                                endpoint, protocol, censorship, progress, ct, t0, fromCache: false).ConfigureAwait(false);
                            if (accepted != null) return accepted.Value;
                        }
                    }
                }
                SetModeWarp(); // restore default mode for any further attempts
            }
        }

        // Optional final Medium/Mode5 seed pass only with a user-provided list.
        if (censorship.Enabled && censorship.DpiAssist && endpoints != null && list.Count > 0)
        {
            progress?.Report("Final Mode5 DPI seed pass…");
            var (mok, mmsg) = await WarpDpiAssist.StartAsync(DPIBasic.DPIBasicBypassMode.Mode5, progress).ConfigureAwait(false);
            progress?.Report(mmsg);
            if (mok)
            {
                string medProto = preferredProtocol.Equals("WireGuard", StringComparison.OrdinalIgnoreCase)
                    ? "WireGuard"
                    : "MASQUE";
                ApplyTunnelPrefs(medProto, medProto.Equals("MASQUE", StringComparison.OrdinalIgnoreCase) ? "h2-only" : null, progress);
                List<string> retry = (remembered.Count > 0 ? remembered : list).Take(8).ToList();
                if (retry.Count == 0) retry = new List<string> { "162.159.198.49:443", "162.159.199.85:443" };
                int n = 0;
                foreach (string endpoint in retry)
                {
                    ct.ThrowIfCancellationRequested();
                    n++;
                    progress?.Report($"[Mode5 {n}/{retry.Count}] {endpoint}…");
                    Disconnect();
                    if (!SetEndpoint(endpoint).Ok) continue;
                    long t0 = WarpSessionLog.ElapsedMs;
                    if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false))
                    {
                        PublicIpInfo info = await FetchPublicIpInfoAsync(8000).ConfigureAwait(false);
                        if (info.WarpOn == true &&
                            await StabilizeConnectedAsync(progress, ct, soft: true).ConfigureAwait(false))
                        {
                            var accepted = await QualifyOrRejectAsync(
                                endpoint, medProto, censorship, progress, ct, t0, fromCache: false).ConfigureAwait(false);
                            if (accepted != null) return accepted.Value;
                        }
                    }
                }
            }
        }

        // Last resort without custom list — stay on preferred protocol (do not silently switch MASQUE↔WG).
        if (!censorship.Enabled || list.Count > 0)
        {
            progress?.Report($"Last resort: default endpoint + {preferredProtocol}…");
            WarpSessionLog.Step("attempt", "last resort default " + preferredProtocol);
            Disconnect();
            ResetEndpoint();
            ApplyTunnelPrefs(preferredProtocol,
                preferredProtocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase)
                    ? (censorship.Enabled ? "h2-only" : "h3-with-h2-fallback")
                    : null,
                progress);
            if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false) &&
                await StabilizeConnectedAsync(progress, ct, soft: censorship.Enabled).ConfigureAwait(false))
            {
                var accepted = await QualifyOrRejectAsync(
                    null, preferredProtocol, censorship, progress, ct, WarpSessionLog.ElapsedMs, fromCache: false).ConfigureAwait(false);
                if (accepted != null) return accepted.Value;
            }
        }

        // Auto WireGuard fallback when MASQUE exhausted under IR (UDP sometimes works when H2 is inspected).
        if (censorship.Enabled &&
            !preferredProtocol.Equals("WireGuard", StringComparison.OrdinalIgnoreCase))
        {
            progress?.Report("MASQUE exhausted — trying WireGuard (UDP) fallback…");
            if (censorship.DpiAssist)
            {
                var (dok, dmsg) = await WarpDpiAssist.StartAsync(DPIBasic.DPIBasicBypassMode.Light, progress, 2).ConfigureAwait(false);
                progress?.Report(dmsg);
            }
            SetModeWarp();
            ApplyTunnelPrefs("WireGuard", null, progress);
            if (endpoints != null && list.Count > 0)
            {
                List<string> wgTry = new();
                foreach (string ep in list.Take(20))
                {
                    int colon = ep.LastIndexOf(':');
                    string host = colon > 0 ? ep[..colon] : ep;
                    string wg = host + ":2408";
                    if (!wgTry.Contains(wg, StringComparer.OrdinalIgnoreCase))
                        wgTry.Add(wg);
                }
                List<string> wgReach = await FilterReachableEndpointsAsync(
                    wgTry, "WireGuard", progress, ct, Math.Max(600, censorship.ProbeTimeoutMs), take: 10).ConfigureAwait(false);
                if (wgReach.Count == 0) wgReach = wgTry.Take(8).ToList();
                int wi = 0;
                foreach (string endpoint in wgReach)
                {
                    ct.ThrowIfCancellationRequested();
                    wi++;
                    progress?.Report($"[WG {wi}/{wgReach.Count}] {endpoint}…");
                    await WaitUntilDisconnectedAsync(ct, 5000).ConfigureAwait(false);
                    ApplyTunnelPrefs("WireGuard", null, progress);
                    if (!SetEndpoint(endpoint).Ok) continue;
                    long t0 = WarpSessionLog.ElapsedMs;
                    if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false) &&
                        await StabilizeConnectedAsync(progress, ct, soft: true).ConfigureAwait(false))
                    {
                        var accepted = await QualifyOrRejectAsync(
                            endpoint, "WireGuard", censorship, progress, ct, t0, fromCache: false).ConfigureAwait(false);
                        if (accepted != null) return accepted.Value;
                    }
                }
            }
            // Default WG endpoint (no forced IPs — warp-cli 2026 consumer goes Unable)
            await WaitUntilDisconnectedAsync(ct).ConfigureAwait(false);
            ResetEndpoint();
            ApplyTunnelPrefs("WireGuard", null, progress);
            if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false) &&
                await StabilizeConnectedAsync(progress, ct, soft: true).ConfigureAwait(false))
            {
                var accepted = await QualifyOrRejectAsync(
                    null, "WireGuard", censorship, progress, ct, WarpSessionLog.ElapsedMs, fromCache: false).ConfigureAwait(false);
                if (accepted != null) return accepted.Value;
            }
        }

        if (censorship.DpiAssist) await WarpDpiAssist.StopAsync().ConfigureAwait(false);

        WarpSessionLog.Step("connect", "all attempts exhausted");
        string tip = preferredProtocol.Equals("WireGuard", StringComparison.OrdinalIgnoreCase)
            ? "WireGuard (UDP) failed. Tip: switch Protocol to MASQUE and retry."
            : "Could not connect (MASQUE + WireGuard tried). Keep Iran mode + DPI assist on, run as Admin, retry. " +
              "If Cloudflare engage IPs are fully blocked, official warp-cli cannot open a path.";
        return (false, tip, null, preferredProtocol);
    }

    /// <summary>
    /// After Connected+warp=on+settle: run quality gate. Pass → FinishConnected; fail → demote and return null (try next).
    /// </summary>
    private static async Task<(bool Ok, string Message, string? Endpoint, string Protocol)?> QualifyOrRejectAsync(
        string? endpoint,
        string protocol,
        CensorshipOptions opt,
        IProgress<string>? progress,
        CancellationToken ct,
        long attemptStartMs,
        bool fromCache)
    {
        if (opt.RequireLinkQuality)
        {
            // Soft check only — full soak made connects feel "broken" under DPI.
            var q = await WarpLinkQuality.EvaluateAsync(progress, ct, strict: false).ConfigureAwait(false);
            if (!q.Ok)
            {
                progress?.Report($"Weak link on {endpoint ?? "default"} — {q.Reason}. Trying next…");
                WarpSessionLog.Decision("reject", "quality gate failed",
                    new Dictionary<string, object?>
                    {
                        ["endpoint"] = endpoint,
                        ["reason"] = q.Reason,
                        ["fromCache"] = fromCache,
                    });
                if (!string.IsNullOrWhiteSpace(endpoint))
                    WarpSuccessCache.Demote(endpoint);
                try { Disconnect(); } catch { }
                return null;
            }
        }

        WarpSessionLog.AttemptResult(endpoint ?? "default", protocol,
            fromCache ? "accept-cache-quality" : "accept-quality",
            WarpSessionLog.ElapsedMs - attemptStartMs,
            new Dictionary<string, object?> { ["endpoint"] = endpoint });
        WarpSessionLog.Decision("accept", "quality gate passed",
            new Dictionary<string, object?> { ["endpoint"] = endpoint, ["protocol"] = protocol, ["fromCache"] = fromCache });

        string msg = endpoint == null
            ? $"Connected via default endpoint ({protocol})."
            : fromCache
                ? $"Connected via remembered {endpoint} ({protocol})."
                : $"Connected via {endpoint} ({protocol}).";
        return await FinishConnectedAsync(msg, endpoint, protocol, opt, progress, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Health-watch failover: demote current endpoint and try the next candidates in the pool.
    /// </summary>
    public static async Task<(bool Ok, string Message, string? Endpoint, string Protocol)> RotateToNextEndpointAsync(
        string? currentEndpoint,
        string preferredProtocol,
        CensorshipOptions? censorship,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        censorship ??= new CensorshipOptions { Enabled = true, DpiAssist = false, RequireLinkQuality = true };
        if (!string.IsNullOrWhiteSpace(currentEndpoint))
            WarpSuccessCache.Demote(currentEndpoint);

        List<string> next = GetFailoverCandidates(currentEndpoint, take: Math.Max(8, censorship.MaxConnectAttempts));
        // Also try other remembered successes that weren't the failing one.
        foreach (string rem in WarpSuccessCache.GetRecentEndpoints())
        {
            if (string.Equals(rem, currentEndpoint, StringComparison.OrdinalIgnoreCase)) continue;
            if (!next.Contains(rem, StringComparer.OrdinalIgnoreCase))
                next.Insert(0, rem);
        }

        if (next.Count == 0)
        {
            progress?.Report("No failover candidates left — running a fresh scan…");
            return await TryConnectWithFallbackAsync(null, preferredProtocol, progress, ct, censorship with
            {
                // Don't restart DPI if already connected path — DpiAssist false for rotate is safer mid-session
                DpiAssist = false,
            }).ConfigureAwait(false);
        }

        progress?.Report($"Rotating: trying {next.Count} alternate endpoint(s)…");
        WarpSessionLog.Step("health", "rotate start",
            new Dictionary<string, object?>
            {
                ["from"] = currentEndpoint,
                ["candidates"] = string.Join(", ", next.Take(8)),
            });

        // Reuse connect path with explicit list (no DPI restart — handshake already worked before).
        var rotateOpt = censorship with { DpiAssist = false, RequireLinkQuality = true };
        return await TryConnectWithFallbackAsync(next, preferredProtocol, progress, ct, rotateOpt).ConfigureAwait(false);
    }

    /// <summary>
    /// Post-connect latency pass: stop WinDivert, optional WG upgrade, soft IR excludes.
    /// Never re-set tunnel mode after a proven connect — that drops the session.
    /// </summary>
    private static async Task<(bool Ok, string Message, string? Endpoint, string Protocol)> FinishConnectedAsync(
        string message,
        string? endpoint,
        string protocol,
        CensorshipOptions opt,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        WarpSessionLog.Step("finish", "proven connect — starting post-connect profile",
            new Dictionary<string, object?>
            {
                ["endpoint"] = endpoint,
                ["protocol"] = protocol,
                ["lowLatency"] = opt.LowLatency,
                ["iranExcludes"] = opt.ApplyIranExcludes,
                ["status"] = ParseStatus(Status()),
            });

        // Hold DPI assist briefly so the MASQUE session finishes settling before WinDivert stops.
        if (opt.Enabled && (opt.DpiAssist || WarpDpiAssist.IsActive))
        {
            progress?.Report("Holding DPI assist ~2.5s while tunnel settles…");
            await Task.Delay(2500, ct).ConfigureAwait(false);
        }

        // Critical for gaming: GoodbyeDPI/WinDivert adds latency to all TCP — stop once tunnel is up.
        if (opt.DpiAssist || WarpDpiAssist.IsActive)
        {
            progress?.Report("Stopping DPI assist (WinDivert fragment adds latency to games)…");
            await WarpDpiAssist.StopAsync().ConfigureAwait(false);
            if (!await EnsureTunnelAliveAsync(endpoint, protocol, progress, ct, "after DPI stop").ConfigureAwait(false))
            {
                WarpSessionLog.Step("finish", "lost tunnel after DPI stop; could not restore");
                return (false,
                    "Connected briefly, then dropped when stopping DPI assist. Retry Connect (log saved).",
                    endpoint, protocol);
            }
        }

        string usedProtocol = protocol;
        string? usedEndpoint = endpoint;
        var gamingNotes = new List<string>();

        if (opt.LowLatency)
        {
            // Do NOT call SetModeTunnelOnly() again — already applied before connect.
            // Mode changes after Connected restart the tunnel and often fail under DPI.
            progress?.Report("Low-latency: WARP DNS kept; Iran excludes skipped for stability…");
            WarpSessionLog.Step("gaming", "warp DNS (no tunnel_only); iran excludes only if requested");

            // WG upgrade is optional — under Iranian DPI it often fails and wastes 15–40s.
            if (opt.TryWireGuardUpgrade &&
                protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
            {
                var upgraded = await TryUpgradeToWireGuardAsync(endpoint, progress, ct).ConfigureAwait(false);
                if (upgraded.Ok)
                {
                    usedProtocol = "WireGuard";
                    usedEndpoint = upgraded.Endpoint ?? endpoint;
                    message = $"Connected via {usedEndpoint ?? "default"} (WireGuard, upgraded from MASQUE for lower latency).";
                    gamingNotes.Add("wg-upgrade=ok");
                }
                else
                {
                    progress?.Report("WireGuard upgrade skipped — staying on MASQUE.");
                    gamingNotes.Add("wg-upgrade=skipped");
                    if (!await EnsureTunnelAliveAsync(endpoint, protocol, progress, ct, "after WG upgrade revert").ConfigureAwait(false))
                    {
                        WarpSessionLog.Step("finish", "lost tunnel after WG upgrade attempt");
                        return (false,
                            "Connected on MASQUE, then lost during WireGuard upgrade. Retry Connect (log saved).",
                            endpoint, protocol);
                    }
                }
            }

            if (opt.ApplyIranExcludes)
            {
                progress?.Report("Excluding Iran/domestic ranges from tunnel (cached after first run)…");
                await Task.Run(() => ApplyDomesticSplitTunnelExcludes(progress), ct).ConfigureAwait(false);
                if (!await EnsureTunnelAliveAsync(usedEndpoint, usedProtocol, progress, ct, "after Iran excludes").ConfigureAwait(false))
                {
                    progress?.Report("Iran excludes unsettled the tunnel and restore failed.");
                    gamingNotes.Add("iran-excludes=failed");
                    WarpSessionLog.Step("gaming", "Iran excludes dropped tunnel; restore failed");
                    return (false,
                        "Connected, then dropped while applying Iran excludes. Retry Connect without excludes (log saved).",
                        endpoint, protocol);
                }
                gamingNotes.Add("iran-excludes=ok");
            }
            else
            {
                gamingNotes.Add("iran-excludes=skipped");
            }

            message += gamingNotes.Count > 0
                ? " Low-latency profile applied (" + string.Join(", ", gamingNotes) + ")."
                : " Low-latency profile applied.";
        }

        PublicIpInfo finalInfo = await FetchPublicIpInfoAsync(8000).ConfigureAwait(false);
        WarpSessionLog.Egress(finalInfo.Source ?? "trace", finalInfo,
            new Dictionary<string, object?>
            {
                ["endpoint"] = usedEndpoint,
                ["protocol"] = usedProtocol,
                ["status"] = ParseStatus(Status()),
                ["phase"] = "finish",
            });

        if (finalInfo.WarpOn != true)
        {
            WarpSessionLog.Decision("reject", "post-connect egress lost warp=on",
                new Dictionary<string, object?>
                {
                    ["warpOn"] = finalInfo.WarpOn,
                    ["ip"] = finalInfo.Ip,
                    ["error"] = finalInfo.Error,
                });
            return (false,
                "Tunnel looked up briefly but egress is not warp=on anymore. Retry Connect (log saved).",
                usedEndpoint, usedProtocol);
        }

        WarpSessionLog.Step("finish", "complete",
            new Dictionary<string, object?>
            {
                ["message"] = message,
                ["endpoint"] = usedEndpoint,
                ["protocol"] = usedProtocol,
                ["status"] = ParseStatus(Status()),
                ["ip"] = finalInfo.Ip,
                ["warpOn"] = finalInfo.WarpOn,
                ["loc"] = finalInfo.Loc,
                ["colo"] = finalInfo.Colo,
                ["gaming"] = gamingNotes,
            });
        WarpSessionLog.Decision("accept", "finish with warp=on",
            new Dictionary<string, object?>
            {
                ["endpoint"] = usedEndpoint,
                ["protocol"] = usedProtocol,
                ["ip"] = finalInfo.Ip,
                ["loc"] = finalInfo.Loc,
            });

        WarpSuccessCache.Record(usedEndpoint, usedProtocol, finalInfo);

        return (true, message, usedEndpoint, usedProtocol);
    }

    /// <summary>
    /// Confirm Connected + warp≠off; if broken, reconnect the proven endpoint/protocol without mode flips.
    /// </summary>
    private static async Task<bool> EnsureTunnelAliveAsync(
        string? endpoint,
        string protocol,
        IProgress<string>? progress,
        CancellationToken ct,
        string phase)
    {
        Result st = Status();
        bool connected = IsConnected(st);
        PublicIpInfo info = await FetchPublicIpInfoAsync(4000).ConfigureAwait(false);
        WarpSessionLog.Egress(info.Source ?? "trace", info,
            new Dictionary<string, object?>
            {
                ["phase"] = phase,
                ["status"] = ParseStatus(st),
                ["connected"] = connected,
                ["endpoint"] = endpoint,
                ["protocol"] = protocol,
            });
        WarpSessionLog.Step("verify", phase,
            new Dictionary<string, object?>
            {
                ["status"] = ParseStatus(st),
                ["connected"] = connected,
                ["ip"] = info.Ip,
                ["warpOn"] = info.WarpOn,
                ["loc"] = info.Loc,
                ["colo"] = info.Colo,
                ["endpoint"] = endpoint,
                ["protocol"] = protocol,
            });

        if (connected && info.WarpOn == true)
            return true;

        // Status Connected without warp=on is a false positive under DPI — do not accept.
        if (connected && info.WarpOn != true)
        {
            progress?.Report($"warp-cli Connected but egress warp≠on after {phase} — restoring…");
            WarpSessionLog.Step("verify", $"reject soft-connected after {phase}",
                new Dictionary<string, object?> { ["warpOn"] = info.WarpOn, ["ip"] = info.Ip });
        }
        else
        {
            progress?.Report($"Tunnel not healthy after {phase} — restoring {endpoint ?? "default"} ({protocol})…");
        }

        WarpSessionLog.Step("recover", $"restore after {phase}");
        Disconnect();
        SetProtocol(protocol);
        if (protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
            SetMasqueOptions("h2-only");
        if (!string.IsNullOrWhiteSpace(endpoint))
            SetEndpoint(endpoint);
        else
            ResetEndpoint();

        bool ok = await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false);
        PublicIpInfo after = await FetchPublicIpInfoAsync(8000).ConfigureAwait(false);
        WarpSessionLog.Step("recover", ok && after.WarpOn == true ? "restore ok" : "restore failed",
            new Dictionary<string, object?>
            {
                ["status"] = ParseStatus(Status()),
                ["ip"] = after.Ip,
                ["warpOn"] = after.WarpOn,
            });
        return ok && after.WarpOn == true;
    }

    /// <summary>Try same host on classic WG ports — lower overhead than MASQUE/H2 when UDP works.</summary>
    private static async Task<(bool Ok, string? Endpoint)> TryUpgradeToWireGuardAsync(
        string? currentEndpoint,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(currentEndpoint) ||
            !TryParseHostPort(currentEndpoint, out string host, out _))
        {
            host = (!string.IsNullOrWhiteSpace(currentEndpoint) && currentEndpoint.IndexOf(':') < 0)
                ? currentEndpoint.Trim()
                : "engage.cloudflareclient.com";
        }

        int[] ports = { 2408, 500 }; // keep short — full port sweep was a major Auto-find delay
        foreach (int port in ports)
        {
            ct.ThrowIfCancellationRequested();
            string ep = $"{host}:{port}";
            progress?.Report($"Low-latency: trying WireGuard {ep}…");
            Disconnect();
            SetProtocol("WireGuard");
            Result set = SetEndpoint(ep);
            if (!set.Ok) continue;
            if (!await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: false).ConfigureAwait(false))
                continue;
            PublicIpInfo info = await FetchPublicIpInfoAsync(5000).ConfigureAwait(false);
            if (info.WarpOn == true)
                return (true, ep);
        }

        // Revert to MASQUE on original endpoint
        progress?.Report("Reverting to MASQUE…");
        Disconnect();
        SetProtocol("MASQUE");
        SetMasqueOptions("h2-only");
        if (!string.IsNullOrWhiteSpace(currentEndpoint))
            SetEndpoint(currentEndpoint);
        else
            ResetEndpoint();
        await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false);
        return (false, null);
    }
    private static bool _iranExcludesApplied;

    /// <summary>
    /// Keep Iranian / private traffic off WARP so only foreign destinations (game servers) use the tunnel.
    /// Runs once per process — re-applying 80+ ranges was a major post-connect stall.
    /// </summary>
    public static void ApplyDomesticSplitTunnelExcludes(IProgress<string>? progress = null)
    {
        if (_iranExcludesApplied)
        {
            progress?.Report("Iran/domestic excludes already applied this session.");
            return;
        }

        // Fewer large aggregates (speed) — private RFC1918 + major IR blocks
        string[] ranges =
        {
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
            "2.144.0.0/14", "5.208.0.0/12", "5.232.0.0/14", "31.56.0.0/14",
            "37.156.0.0/14", "46.209.0.0/16", "78.38.0.0/15", "79.127.0.0/16",
            "81.12.0.0/16", "85.185.0.0/16", "89.198.0.0/16", "91.98.0.0/15",
            "94.182.0.0/15", "95.38.0.0/16", "151.232.0.0/14", "151.238.0.0/15",
            "176.65.192.0/18", "178.131.0.0/16", "185.4.0.0/16", "188.209.0.0/16",
            "188.245.0.0/16", "194.225.0.0/16", "217.218.0.0/15",
        };

        int ok = 0;
        foreach (string range in ranges)
        {
            Result r = Run("tunnel", "ip", "add-range", range);
            if (r.Ok || r.Combined.Contains("already", StringComparison.OrdinalIgnoreCase))
                ok++;
        }
        _iranExcludesApplied = true;
        progress?.Report($"Split-tunnel excludes applied ({ok}/{ranges.Length} ranges).");
        WarpSessionLog.Step("gaming", $"iran excludes {ok}/{ranges.Length}");
    }

    public static async Task<List<string>> FilterReachableEndpointsAsync(
        IList<string> endpoints,
        string protocol,
        IProgress<string>? progress,
        CancellationToken ct,
        int timeoutMs = 350,
        int take = 12)
    {
        ct.ThrowIfCancellationRequested();
        if (take <= 0) return new List<string>();

        bool masque = protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase);
        var scored = new ConcurrentBag<(string Ep, int Ms)>();

        await Parallel.ForEachAsync(
            endpoints,
            new ParallelOptions { MaxDegreeOfParallelism = 96, CancellationToken = ct },
            async (ep, token) =>
            {
                if (!TryParseHostPort(ep, out string host, out int port)) return;

                string reachableEndpoint = ep;
                int ms;
                if (masque)
                {
                    // Real TCP connect on the MASQUE port (patterniha: do not rely on ICMP).
                    ms = await MeasureTcpMsAsync(host, port, timeoutMs, token).ConfigureAwait(false);
                    if (ms < 0 && port == 443)
                    {
                        ms = await MeasureTcpMsAsync(host, 8443, timeoutMs, token).ConfigureAwait(false);
                        if (ms >= 0) reachableEndpoint = ep[..ep.LastIndexOf(':')] + ":8443";
                    }
                }
                else
                {
                    // WG is UDP — try cheap UDP send; also TCP/443 as CF-edge liveness.
                    ms = await MeasureUdpMsAsync(host, port, timeoutMs, token).ConfigureAwait(false);
                    if (ms < 0)
                    {
                        int tcp = await MeasureTcpMsAsync(host, 443, timeoutMs, token).ConfigureAwait(false);
                        if (tcp >= 0) ms = tcp + 80; // deprioritize vs real UDP hits
                    }
                }

                if (ms >= 0)
                    scored.Add((reachableEndpoint, ms));
            }).ConfigureAwait(false);

        List<string> ordered = scored
            .OrderBy(x => x.Ms)
            .Select(x => x.Ep)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(take)
            .ToList();

        progress?.Report(ordered.Count > 0
            ? $"Fastest probe: {ordered[0]} (~{scored.First(s => s.Ep == ordered[0]).Ms}ms)"
            : "Reachability probe found no open ports.");
        return ordered;
    }

    private static bool TryParseHostPort(string endpoint, out string host, out int port)
    {
        host = "";
        port = 0;
        int idx = endpoint.LastIndexOf(':');
        if (idx <= 0 || idx >= endpoint.Length - 1) return false;
        host = endpoint[..idx].Trim();
        return int.TryParse(endpoint[(idx + 1)..], out port) && port > 0 && port <= 65535 && host.Length > 0;
    }

    private static async Task<int> MeasureTcpMsAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            var sw = Stopwatch.StartNew();
            using var client = new TcpClient { NoDelay = true };
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeoutMs);
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            sw.Stop();
            return client.Connected ? (int)sw.ElapsedMilliseconds : -1;
        }
        catch
        {
            return -1;
        }
    }

    private static async Task<int> MeasureUdpMsAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            var sw = Stopwatch.StartNew();
            using var udp = new UdpClient();
            udp.Client.SendTimeout = timeoutMs;
            udp.Client.ReceiveTimeout = timeoutMs;
            // WireGuard handshake-ish bytes — we only care that the path accepts UDP.
            byte[] payload = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeoutMs);
            await udp.SendAsync(payload, host, port, linked.Token).ConfigureAwait(false);
            sw.Stop();
            // No reliable reply expected; treat successful send as weak positive.
            return (int)Math.Max(1, sw.ElapsedMilliseconds);
        }
        catch
        {
            return -1;
        }
    }

    /// <summary>
    /// After first warp=on, re-check a few times so we don't accept a flapping MASQUE session.
    /// </summary>
    private static async Task<bool> StabilizeConnectedAsync(
        IProgress<string>? progress, CancellationToken ct, bool soft = false)
    {
        int rounds = soft ? 1 : 3;
        progress?.Report(soft
            ? "Quick settle (confirm warp=on)…"
            : "Settling tunnel (confirm warp=on stays on)…");
        for (int i = 0; i < rounds; i++)
        {
            await Task.Delay(soft ? 800 : 1200, ct).ConfigureAwait(false);
            Result st = Status();
            string parsed = ParseStatus(st);
            if (!IsConnected(st))
            {
                WarpSessionLog.Step("stabilize", "lost Connected",
                    new Dictionary<string, object?> { ["i"] = i, ["status"] = parsed });
                return false;
            }

            PublicIpInfo info = await FetchPublicIpInfoAsync(6000).ConfigureAwait(false);
            WarpSessionLog.Egress(info.Source ?? "trace", info,
                new Dictionary<string, object?> { ["phase"] = "stabilize", ["i"] = i, ["status"] = parsed, ["soft"] = soft });
            if (info.WarpOn != true)
            {
                WarpSessionLog.Step("stabilize", "warp≠on during settle",
                    new Dictionary<string, object?> { ["i"] = i, ["warpOn"] = info.WarpOn, ["error"] = info.Error });
                return false;
            }
        }

        WarpSessionLog.Step("stabilize", soft ? "ok-soft" : "ok");
        return true;
    }

    private static async Task<bool> PollConnectedAsync(
        IProgress<string>? progress, bool verifyWarpOn, CancellationToken ct, bool longPoll = false, bool masquePin = false)
    {
        Result connect = Connect();
        WarpSessionLog.Cli("connect", connect, always: true);
        WarpSessionLog.Step("poll", "connect issued",
            new Dictionary<string, object?>
            {
                ["ok"] = connect.Ok,
                ["out"] = TruncateForLog(connect.Combined, 300),
                ["verifyWarpOn"] = verifyWarpOn,
                ["longPoll"] = longPoll,
                ["masquePin"] = masquePin,
            });
        // Patience: IR handshakes often need 20–40s. MASQUE pin: fail faster (~11s) and rotate IPs.
        int loops = masquePin ? 22 : (longPoll ? (verifyWarpOn ? 50 : 24) : (verifyWarpOn ? 18 : 10));
        const int delay = 500;
        int connectingStreak = 0;
        int stuckLimit = masquePin ? 20 : (longPoll ? 48 : 22);
        for (int i = 0; i < loops; i++)
        {
            await Task.Delay(delay, ct).ConfigureAwait(false);
            Result st = Status();
            string parsed = ParseStatus(st);
            string raw = st.Combined ?? "";
            WarpSessionLog.StatusChange(parsed, new Dictionary<string, object?> { ["i"] = i, ["raw"] = TruncateForLog(raw, 240) });

            if (i == 0)
            {
                string reason = ExtractStatusReason(raw);
                if (!string.IsNullOrEmpty(reason))
                    progress?.Report(reason);
            }

            if (_expectProtocol != null &&
                _expectProtocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase) &&
                LooksLikeWireGuardHandshake(raw) &&
                i >= 1)
            {
                LastHandshakeUsedWireGuardPort = true;
                progress?.Report("Handshake target is :2408 (WireGuard), not MASQUE :443 — protocol did not apply.");
                WarpSessionLog.Decision("reject", "MASQUE requested but handshake is WireGuard :2408",
                    new Dictionary<string, object?> { ["i"] = i, ["status"] = parsed, ["raw"] = TruncateForLog(raw, 240) });
                return false;
            }

            if (parsed.Contains("Failed", StringComparison.OrdinalIgnoreCase))
            {
                WarpSessionLog.Decision("reject", "warp status Failed",
                    new Dictionary<string, object?> { ["i"] = i, ["status"] = parsed });
                return false;
            }
            // warp-cli 2026: forced endpoints often go Unable then Disconnected — abort fast.
            if (parsed.Contains("Unable", StringComparison.OrdinalIgnoreCase) && i >= 2)
            {
                progress?.Report("WARP status Unable — next…");
                WarpSessionLog.Decision("reject", "warp status Unable",
                    new Dictionary<string, object?> { ["i"] = i, ["status"] = parsed });
                // Do not endpoint-reset on MASQUE — that loads WireGuard :2408 for the next try.
                if (_expectProtocol == null ||
                    !_expectProtocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
                {
                    try { ResetEndpoint(); } catch { /* ignore */ }
                }
                return false;
            }
            if (i >= 5 && (parsed.Contains("Disconnected", StringComparison.OrdinalIgnoreCase) ||
                           parsed.Contains("Not connected", StringComparison.OrdinalIgnoreCase)))
            {
                WarpSessionLog.Decision("reject", "disconnected during poll",
                    new Dictionary<string, object?> { ["i"] = i, ["status"] = parsed });
                return false;
            }

            bool connecting = parsed.Contains("Connecting", StringComparison.OrdinalIgnoreCase);
            if (connecting)
            {
                connectingStreak++;
                if (connectingStreak >= stuckLimit)
                {
                    progress?.Report("Handshake stuck on Connecting — next…");
                    WarpSessionLog.Decision("reject", "stuck Connecting",
                        new Dictionary<string, object?> { ["i"] = i, ["streak"] = connectingStreak });
                    return false;
                }
            }
            else connectingStreak = 0;

            if (!IsConnected(st)) continue;

            if (!verifyWarpOn)
            {
                WarpSessionLog.Step("poll", "connected (status only)", new Dictionary<string, object?> { ["i"] = i, ["status"] = parsed });
                return true;
            }

            PublicIpInfo info = await FetchPublicIpInfoAsync(7000).ConfigureAwait(false);
            WarpSessionLog.Egress(info.Source ?? "trace", info, new Dictionary<string, object?> { ["i"] = i, ["status"] = parsed });
            if (info.WarpOn == true)
            {
                WarpSessionLog.Step("poll", "connected warp=on",
                    new Dictionary<string, object?> { ["i"] = i, ["ip"] = info.Ip, ["loc"] = info.Loc, ["colo"] = info.Colo });
                return true;
            }
            if (info.WarpOn == false)
                progress?.Report("warp-cli says Connected but trace shows warp=off — waiting…");
            else
                progress?.Report("Connected status but could not confirm warp=on yet…");
        }
        // Never treat bare "Connected" as success when warp=on was required.
        Result finalSt = Status();
        WarpSessionLog.Step("poll", "timeout without warp=on",
            new Dictionary<string, object?>
            {
                ["status"] = ParseStatus(finalSt),
                ["statusRaw"] = TruncateForLog(finalSt.Combined, 400),
                ["verifyWarpOn"] = verifyWarpOn,
            });
        return false;
    }

    private static async Task WaitUntilDisconnectedAsync(CancellationToken ct, int maxMs = 8000)
    {
        Disconnect();
        int waited = 0;
        while (waited < maxMs)
        {
            ct.ThrowIfCancellationRequested();
            Result st = Status();
            string p = ParseStatus(st);
            if (!IsConnected(st) && !p.Contains("Connecting", StringComparison.OrdinalIgnoreCase))
                return;
            await Task.Delay(400, ct).ConfigureAwait(false);
            waited += 400;
            if (waited is 400 or 2000)
                Disconnect();
        }
    }

    public sealed class PublicIpInfo
    {
        public string? Ip { get; init; }
        public bool? WarpOn { get; init; }
        public string? Loc { get; init; }
        public string? Colo { get; init; }
        public string? Gateway { get; init; }
        public string? Http { get; init; }
        /// <summary>Which URL produced this result (or failure reason).</summary>
        public string? Source { get; init; }
        public string? Error { get; init; }
    }

    public static Task<PublicIpInfo> FetchPublicIpInfoAsync(int timeoutMs = 8000, CancellationToken ct = default)
        => FetchPublicIpInfoCoreAsync(SharedHttp, timeoutMs, ct);

    internal static async Task<PublicIpInfo> FetchPublicIpInfoCoreAsync(HttpClient http, int timeoutMs, CancellationToken ct)
    {
        if (timeoutMs <= 0) throw new ArgumentOutOfRangeException(nameof(timeoutMs));
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct, OperationToken.Value);
        cancellation.Token.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);
        deadline.CancelAfter(timeoutMs);
        string[] urls =
        {
            "https://cloudflare.com/cdn-cgi/trace",
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://1.1.1.1/cdn-cgi/trace",
            "https://api.ipify.org",
        };
        string? lastError = null;
        var elapsed = Stopwatch.StartNew();
        for (int i = 0; i < urls.Length; i++)
        {
            cancellation.Token.ThrowIfCancellationRequested();
            int remaining = timeoutMs - (int)elapsed.ElapsedMilliseconds;
            if (remaining <= 0) break;
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            // Reserve a share of the total deadline for each remaining fallback.
            attempt.CancelAfter(Math.Max(1, remaining / (urls.Length - i)));
            try
            {
                string body = await http.GetStringAsync(urls[i], attempt.Token).ConfigureAwait(false);
                cancellation.Token.ThrowIfCancellationRequested();
                if (i == urls.Length - 1)
                {
                    if (IPAddress.TryParse(body.Trim(), out var ip))
                        return new PublicIpInfo { Ip = ip.ToString(), Source = "ipify", Error = "IP-only fallback; WARP status unknown." };
                }
                else
                {
                    var parsed = ParseCfTrace(body, urls[i]);
                    if (IPAddress.TryParse(parsed.Ip, out _)) return parsed;
                }
                lastError = "Response did not contain a valid IP address.";
            }
            catch (OperationCanceledException)
            {
                cancellation.Token.ThrowIfCancellationRequested();
                lastError = "Public IP check timed out.";
            }
            catch (HttpRequestException ex) { lastError = ex.Message; }
        }
        cancellation.Token.ThrowIfCancellationRequested();
        return new PublicIpInfo { Source = "none", Error = lastError ?? "Public IP check timed out." };
    }

    private static PublicIpInfo ParseCfTrace(string body, string source)
    {
        string? ip = null;
        bool? warp = null;
        string? loc = null;
        string? colo = null;
        string? gateway = null;
        string? http = null;
        foreach (string raw in body.Split('\n'))
        {
            string line = raw.Trim();
            if (line.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                ip = line[3..].Trim();
            else if (line.StartsWith("warp=", StringComparison.OrdinalIgnoreCase))
                warp = line[5..].Trim().Equals("on", StringComparison.OrdinalIgnoreCase);
            else if (line.StartsWith("loc=", StringComparison.OrdinalIgnoreCase))
                loc = line[4..].Trim();
            else if (line.StartsWith("colo=", StringComparison.OrdinalIgnoreCase))
                colo = line[5..].Trim();
            else if (line.StartsWith("gateway=", StringComparison.OrdinalIgnoreCase))
                gateway = line[8..].Trim();
            else if (line.StartsWith("http=", StringComparison.OrdinalIgnoreCase))
                http = line[5..].Trim();
        }
        return new PublicIpInfo
        {
            Ip = ip,
            WarpOn = warp,
            Loc = loc,
            Colo = colo,
            Gateway = gateway,
            Http = http,
            Source = source,
        };
    }

    public static async Task<string?> FetchPublicIpAsync(int timeoutMs = 8000)
        => (await FetchPublicIpInfoAsync(timeoutMs).ConfigureAwait(false)).Ip;

    private static IEnumerable<IPAddress> SampleCidr(string cidr, int count)
    {
        if (!TryParseCidr(cidr, out uint start, out int prefix))
            yield break;

        int hostBits = 32 - prefix;
        long size = hostBits >= 31 ? int.MaxValue : (1L << hostBits);
        if (size <= 2)
        {
            yield return ToIp(start);
            yield break;
        }

        // Skip network/broadcast; sample randomly
        var seen = new HashSet<uint>();
        int attempts = 0;
        while (seen.Count < count && attempts++ < count * 8)
        {
            uint offset = (uint)(Random.Shared.NextInt64(1, Math.Min(size - 1, int.MaxValue)));
            uint ip = start + offset;
            if (seen.Add(ip))
                yield return ToIp(ip);
        }
    }

    private static bool TryParseCidr(string cidr, out uint network, out int prefix)
    {
        network = 0;
        prefix = 0;
        string[] parts = cidr.Split('/');
        if (parts.Length != 2) return false;
        if (!IPAddress.TryParse(parts[0], out IPAddress? ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            return false;
        if (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > 32) return false;
        byte[] b = ip.GetAddressBytes();
        uint addr = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        network = addr & mask;
        return true;
    }

    private static IPAddress ToIp(uint addr) =>
        new(new byte[] { (byte)(addr >> 24), (byte)(addr >> 16), (byte)(addr >> 8), (byte)addr });

    private static void Shuffle<T>(IList<T> list)
    {
        for (int i = list.Count - 1; i > 0; i--)
        {
            int j = Random.Shared.Next(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
    }

    private static string? FindOnPath(string fileName)
    {
        string? pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(pathEnv)) return null;
        foreach (string dir in pathEnv.Split(Path.PathSeparator))
        {
            try
            {
                string full = Path.Combine(dir.Trim(), fileName);
                if (File.Exists(full)) return full;
            }
            catch { /* ignore */ }
        }
        return null;
    }

    private static string Quote(string a)
    {
        if (string.IsNullOrEmpty(a)) return "\"\"";
        if (a.Contains(' ') || a.Contains('"')) return "\"" + a.Replace("\"", "\\\"") + "\"";
        return a;
    }

    private static string TruncateForLog(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        s = s.Replace("\r", " ").Replace("\n", " | ");
        return s.Length <= max ? s : s[..max] + "…";
    }

    /// <summary>High-signal warp-cli / host snapshot once per connect session.</summary>
    private static void LogEnvironmentSnapshot()
    {
        try
        {
            string? exe = FindExecutable();
            Result ver = Run("--version");
            Result st = Status();
            Result settings = Run("settings", "list");
            Result mode = Run("mode");
            Result reg = Run("registration", "show");
            string protoFromSettings = ReadEffectiveProtocol();

            // Registration: keep account type / device id only — never license keys.
            string regSafe = "";
            foreach (string line in reg.Combined.Split('\n'))
            {
                string t = line.Trim();
                if (t.StartsWith("Account type", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("Device ID", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("Device name", StringComparison.OrdinalIgnoreCase) ||
                    t.Contains("account_type", StringComparison.OrdinalIgnoreCase) ||
                    t.Contains("device_id", StringComparison.OrdinalIgnoreCase))
                {
                    regSafe += t + " | ";
                }
            }

            string settingsSafe = TruncateForLog(settings.Combined, 900);
            // Drop lines that look like secrets if any appear.
            if (settingsSafe.Contains("key", StringComparison.OrdinalIgnoreCase) ||
                settingsSafe.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                settingsSafe.Contains("license", StringComparison.OrdinalIgnoreCase))
            {
                var keep = new List<string>();
                foreach (string line in settings.Combined.Split('\n'))
                {
                    string t = line.Trim();
                    if (t.Length == 0) continue;
                    if (t.Contains("key", StringComparison.OrdinalIgnoreCase) ||
                        t.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                        t.Contains("license", StringComparison.OrdinalIgnoreCase) ||
                        t.Contains("secret", StringComparison.OrdinalIgnoreCase))
                        continue;
                    keep.Add(t);
                    if (keep.Count >= 40) break;
                }
                settingsSafe = string.Join(" | ", keep);
            }

            WarpSessionLog.Env(new Dictionary<string, object?>
            {
                ["warpCli"] = exe,
                ["version"] = TruncateForLog(ver.Combined, 120),
                ["serviceRunning"] = IsServiceRunning(),
                ["status"] = ParseStatus(st),
                ["statusRaw"] = TruncateForLog(st.Combined, 300),
                ["mode"] = TruncateForLog(mode.Combined, 120),
                ["protocol"] = string.IsNullOrEmpty(protoFromSettings) ? "(from settings: unknown)" : protoFromSettings,
                ["endpoint"] = "(use settings list — `tunnel endpoint` without args is help text on 2026.6)",
                ["registration"] = TruncateForLog(regSafe, 240),
                ["settings"] = settingsSafe,
                ["dpiActive"] = WarpDpiAssist.IsActive,
            });
        }
        catch (Exception ex)
        {
            WarpSessionLog.Env(new Dictionary<string, object?> { ["error"] = ex.Message });
        }
    }
}
