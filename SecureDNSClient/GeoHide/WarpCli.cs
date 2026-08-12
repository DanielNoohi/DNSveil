using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http;
using System.Text;

namespace SecureDNSClient.GeoHide;

/// <summary>
/// Thin wrapper around Cloudflare's official <c>warp-cli</c>, inspired by
/// https://github.com/saeedmasoudie/pywarp (endpoint set, protocol, connect).
/// </summary>
public static class WarpCli
{
    public static readonly string[] EngageHosts =
    {
        "engage.cloudflareclient.com",
        "162.159.192.1",
        "162.159.193.1",
        "162.159.195.1",
        "162.159.198.1",
        "162.159.199.1",
        "162.159.204.1",
        "188.114.96.1",
        "188.114.97.1",
        "188.114.98.1",
        "188.114.99.1",
        "188.114.100.1",
        "188.114.101.1",
    };

    public static readonly int[] WireGuardPorts = { 2408, 500, 1701, 4500 };
    public static readonly int[] MasquePorts = { 443, 8443 };

    private static string? _cachedExe;
    private static DateTime _cachedExeAt = DateTime.MinValue;
    private static readonly HttpClient SharedHttp = CreateHttpClient();

    private static HttpClient CreateHttpClient()
    {
        HttpClient c = new() { Timeout = TimeSpan.FromSeconds(12) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("DNSveil-GeoHide/3.5");
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

    /// <summary>True when Cloudflare WARP service process appears to be running.</summary>
    public static bool IsServiceRunning()
    {
        try
        {
            return Process.GetProcessesByName("warp-svc").Length > 0
                || Process.GetProcessesByName("Cloudflare WARP").Length > 0;
        }
        catch
        {
            return true; // don't block connect if we cannot inspect processes
        }
    }

    public static Result Run(params string[] args)
    {
        string? exe = FindExecutable();
        if (string.IsNullOrEmpty(exe))
            return new Result { ExitCode = -1, StdErr = "warp-cli not found. Install Cloudflare WARP first." };

        try
        {
            using Process p = new();
            p.StartInfo = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = string.Join(" ", args.Select(Quote)),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            p.Start();

            // Read stdout/stderr in parallel to avoid classic pipe-buffer deadlock.
            Task<string> outTask = p.StandardOutput.ReadToEndAsync();
            Task<string> errTask = p.StandardError.ReadToEndAsync();
            if (!Task.WaitAll(new Task[] { outTask, errTask }, 45_000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return new Result { ExitCode = -1, StdErr = "warp-cli timed out" };
            }
            if (!p.WaitForExit(5_000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return new Result { ExitCode = -1, StdErr = "warp-cli timed out" };
            }

            return new Result
            {
                ExitCode = p.ExitCode,
                StdOut = (outTask.Result ?? "").Trim(),
                StdErr = (errTask.Result ?? "").Trim()
            };
        }
        catch (Exception ex)
        {
            return new Result { ExitCode = -1, StdErr = ex.Message };
        }
    }

    public static Result AcceptTos() => Run("accept-tos");
    public static Result Register() => Run("registration", "new");
    public static Result Connect() => Run("connect");
    public static Result Disconnect() => Run("disconnect");
    public static Result Status() => Run("status");
    public static Result SetModeWarp() => Run("mode", "warp");
    public static Result SetProtocol(string protocol) => Run("tunnel", "protocol", "set", protocol);
    public static Result SetMasqueOptions(string options) => Run("tunnel", "masque-options", "set", options);
    public static Result SetEndpoint(string endpoint) => Run("tunnel", "endpoint", "set", endpoint);
    public static Result ResetEndpoint() => Run("tunnel", "endpoint", "reset");

    /// <summary>True when a consumer WARP registration already exists.</summary>
    public static bool HasRegistration()
    {
        // Prefer plain show; -j is not available on all builds.
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
        // Missing registration typically errors; success prints account/device fields.
        if (t.Contains("not registered", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("No registration", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("Missing registration", StringComparison.OrdinalIgnoreCase))
            return false;
        if (t.Contains("Account type", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("Device ID", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("License", StringComparison.OrdinalIgnoreCase))
            return true;
        // Some builds print JSON with id / account_type
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
        // Strict parsing: "Not Connected" must never count as Connected.
        foreach (string line in status.Combined.Split('\n'))
        {
            string s = line.Trim();
            if (!s.StartsWith("Status", StringComparison.OrdinalIgnoreCase)) continue;

            int colon = s.IndexOf(':');
            string value = colon >= 0 ? s[(colon + 1)..].Trim() : s;
            if (value.Equals("Connected", StringComparison.OrdinalIgnoreCase))
                return true;
            // Any other Status line (Connecting / Disconnected / Not connected / …) is not success.
            return false;
        }
        return false;
    }

    /// <summary>
    /// Endpoint candidates matched to protocol (WG ports vs MASQUE ports).
    /// </summary>
    public static IEnumerable<string> EnumerateEndpointCandidates(string protocol = "WireGuard", int maxCount = 24)
    {
        bool masque = protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase);
        int[] ports = masque ? MasquePorts : WireGuardPorts;

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

    public static async Task<(bool Ok, string Message, string? Endpoint, string Protocol)> TryConnectWithFallbackAsync(
        IEnumerable<string>? endpoints,
        string preferredProtocol = "WireGuard",
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        if (!IsInstalled())
            return (false, "Cloudflare WARP (warp-cli) is not installed.", null, preferredProtocol);

        if (!IsServiceRunning())
            return (false, "Cloudflare WARP service is not running. Open the official WARP app once, then retry.", null, preferredProtocol);

        AcceptTos();
        Disconnect();

        if (!EnsureRegistration(progress))
            return (false, "WARP registration failed. Open the official WARP app once, accept the ToS, then retry.", null, preferredProtocol);

        SetModeWarp();
        SetProtocol(preferredProtocol);
        if (preferredProtocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
            SetMasqueOptions("h3-with-h2-fallback");

        List<string> list = endpoints?.Where(e => !string.IsNullOrWhiteSpace(e)).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                            ?? new List<string>();

        // Empty list ⇒ Cloudflare default endpoint first, then MASQUE fallback.
        if (list.Count == 0)
        {
            progress?.Report($"Connecting with Cloudflare default endpoint ({preferredProtocol})…");
            ResetEndpoint();
            if (await PollConnectedAsync(progress, verifyWarpOn: true, ct).ConfigureAwait(false))
                return (true, $"Connected via default endpoint ({preferredProtocol}).", null, preferredProtocol);
            progress?.Report("Default endpoint failed: " + ParseStatus(Status()));
        }
        else
        {
            // Parallel reachability prefilter — skip dead host:ports before slow warp-cli connect loops.
            progress?.Report($"Probing {list.Count} endpoints in parallel…");
            List<string> reachable = await FilterReachableEndpointsAsync(list, preferredProtocol, progress, ct).ConfigureAwait(false);
            if (reachable.Count == 0)
            {
                progress?.Report("No endpoints responded to probe — trying full list anyway (top 8)…");
                reachable = list.Take(8).ToList();
            }
            else
            {
                progress?.Report($"{reachable.Count}/{list.Count} endpoints look reachable — connecting…");
            }

            int n = 0;
            foreach (string endpoint in reachable)
            {
                ct.ThrowIfCancellationRequested();
                n++;
                progress?.Report($"[{n}/{reachable.Count}] Connecting {endpoint} ({preferredProtocol})…");
                Disconnect();
                Result setEp = SetEndpoint(endpoint);
                if (!setEp.Ok)
                {
                    progress?.Report($"Skip {endpoint}: {setEp.ErrorLine}");
                    continue;
                }

                // Fast poll during auto-find; verify warp=on only on success path.
                if (await PollConnectedAsync(progress, verifyWarpOn: false, ct).ConfigureAwait(false))
                {
                    PublicIpInfo info = await FetchPublicIpInfoAsync(4000).ConfigureAwait(false);
                    if (info.WarpOn != false) // true or unknown
                        return (true, $"Connected via {endpoint} ({preferredProtocol}).", endpoint, preferredProtocol);
                    progress?.Report("Status connected but warp=off — trying next…");
                }
                else
                {
                    progress?.Report($"No connect on {endpoint}: {ParseStatus(Status())}");
                }
            }
        }

        // Last resort: default + MASQUE (helps when WireGuard UDP is blocked).
        if (!preferredProtocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
        {
            progress?.Report("Trying default endpoint + MASQUE…");
            Disconnect();
            ResetEndpoint();
            SetProtocol("MASQUE");
            SetMasqueOptions("h3-with-h2-fallback");
            if (await PollConnectedAsync(progress, verifyWarpOn: true, ct).ConfigureAwait(false))
                return (true, "Connected via default endpoint (MASQUE).", null, "MASQUE");
        }

        return (false, "Could not connect. Your ISP may block WARP; try MASQUE, another endpoint, or another network.", null, preferredProtocol);
    }

    /// <summary>
    /// Parallel TCP probe of engage IPs. For WireGuard UDP ports we still probe TCP on 443 of the same host
    /// as a cheap "is this Cloudflare edge reachable?" filter, then keep original endpoint strings ordered by RTT.
    /// </summary>
    public static async Task<List<string>> FilterReachableEndpointsAsync(
        IList<string> endpoints,
        string protocol,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        bool masque = protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase);
        var scored = new ConcurrentBag<(string Ep, int Ms)>();

        await Parallel.ForEachAsync(
            endpoints,
            new ParallelOptions { MaxDegreeOfParallelism = 64, CancellationToken = ct },
            async (ep, token) =>
            {
                if (!TryParseHostPort(ep, out string host, out int port)) return;

                int probePort = masque ? port : 443; // WG is UDP; use TCP/443 on same host as reachability signal
                int ms = await MeasureTcpMsAsync(host, probePort, 350, token).ConfigureAwait(false);
                if (ms >= 0)
                    scored.Add((ep, ms));
                else if (masque)
                {
                    // try alternate MASQUE port quickly
                    int alt = port == 443 ? 8443 : 443;
                    ms = await MeasureTcpMsAsync(host, alt, 350, token).ConfigureAwait(false);
                    if (ms >= 0) scored.Add((ep, ms + 50));
                }
            }).ConfigureAwait(false);

        List<string> ordered = scored
            .OrderBy(x => x.Ms)
            .Select(x => x.Ep)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .ToList();

        progress?.Report(ordered.Count > 0
            ? $"Fastest probe: {ordered[0]} (~{scored.First(s => s.Ep == ordered[0]).Ms}ms)"
            : "Reachability probe found no open TCP ports.");
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
            using var client = new System.Net.Sockets.TcpClient();
            client.NoDelay = true;
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

    private static async Task<bool> PollConnectedAsync(IProgress<string>? progress, bool verifyWarpOn, CancellationToken ct)
    {
        Connect();
        // Fast window (~3.5s). Auto-find tries many endpoints — keep each attempt short.
        int loops = verifyWarpOn ? 12 : 8;
        for (int i = 0; i < loops; i++)
        {
            await Task.Delay(400, ct).ConfigureAwait(false);
            Result st = Status();
            string parsed = ParseStatus(st);
            if (parsed.Contains("Failed", StringComparison.OrdinalIgnoreCase))
                return false;
            if (i >= 2 && (parsed.Contains("Disconnected", StringComparison.OrdinalIgnoreCase) ||
                           parsed.Contains("Not connected", StringComparison.OrdinalIgnoreCase)))
                return false;

            if (!IsConnected(st)) continue;

            if (!verifyWarpOn) return true;

            PublicIpInfo info = await FetchPublicIpInfoAsync(3500).ConfigureAwait(false);
            if (info.WarpOn == true) return true;
            if (info.WarpOn == false)
                progress?.Report("warp-cli says Connected but trace shows warp=off — waiting…");
            else if (i >= 5)
                return true;
        }
        return IsConnected(Status());
    }

    public sealed class PublicIpInfo
    {
        public string? Ip { get; init; }
        public bool? WarpOn { get; init; }
        public string? Loc { get; init; }
    }

    public static async Task<PublicIpInfo> FetchPublicIpInfoAsync(int timeoutMs = 8000)
    {
        try
        {
            using CancellationTokenSource cts = new(timeoutMs);
            string body = await SharedHttp.GetStringAsync("https://cloudflare.com/cdn-cgi/trace", cts.Token).ConfigureAwait(false);
            string? ip = null;
            bool? warp = null;
            string? loc = null;
            foreach (string line in body.Split('\n'))
            {
                if (line.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                    ip = line[3..].Trim();
                else if (line.StartsWith("warp=", StringComparison.OrdinalIgnoreCase))
                    warp = line[5..].Trim().Equals("on", StringComparison.OrdinalIgnoreCase);
                else if (line.StartsWith("loc=", StringComparison.OrdinalIgnoreCase))
                    loc = line[4..].Trim();
            }
            if (!string.IsNullOrEmpty(ip))
                return new PublicIpInfo { Ip = ip, WarpOn = warp, Loc = loc };
        }
        catch (Exception ex)
        {
            Debug.WriteLine("FetchPublicIpInfoAsync cf: " + ex.Message);
        }
        try
        {
            using CancellationTokenSource cts = new(timeoutMs);
            string ip = (await SharedHttp.GetStringAsync("https://api.ipify.org", cts.Token).ConfigureAwait(false)).Trim();
            return new PublicIpInfo { Ip = ip, WarpOn = null, Loc = null };
        }
        catch (Exception ex)
        {
            Debug.WriteLine("FetchPublicIpInfoAsync ipify: " + ex.Message);
            return new PublicIpInfo();
        }
    }

    public static async Task<string?> FetchPublicIpAsync(int timeoutMs = 8000)
        => (await FetchPublicIpInfoAsync(timeoutMs).ConfigureAwait(false)).Ip;

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
}
