using System.Diagnostics;
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

    public sealed class Result
    {
        public int ExitCode { get; init; }
        public string StdOut { get; init; } = "";
        public string StdErr { get; init; } = "";
        public bool Ok => ExitCode == 0;
        public string ErrorLine =>
            string.IsNullOrWhiteSpace(StdErr)
                ? StdOut.Split('\n').FirstOrDefault()?.Trim() ?? ""
                : StdErr.Split('\n').FirstOrDefault()?.Trim() ?? "";
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
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            if (!p.WaitForExit(45_000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return new Result { ExitCode = -1, StdErr = "warp-cli timed out" };
            }
            return new Result { ExitCode = p.ExitCode, StdOut = stdout?.Trim() ?? "", StdErr = stderr?.Trim() ?? "" };
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

    public static string ParseStatus(Result r)
    {
        string text = r.StdOut + "\n" + r.StdErr;
        foreach (string line in text.Split('\n'))
        {
            string s = line.Trim();
            if (s.StartsWith("Status", StringComparison.OrdinalIgnoreCase))
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
        string t = status.StdOut + "\n" + status.StdErr;
        // Avoid treating "Connecting" as success
        if (t.Contains("Connecting", StringComparison.OrdinalIgnoreCase) &&
            !t.Contains("Status update: Connected", StringComparison.OrdinalIgnoreCase) &&
            !t.Contains("Status: Connected", StringComparison.OrdinalIgnoreCase))
            return false;

        if (t.Contains("Status update: Connected", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("Status: Connected", StringComparison.OrdinalIgnoreCase))
            return true;

        bool hasConnected = t.Contains("Connected", StringComparison.OrdinalIgnoreCase);
        bool hasDisconnected = t.Contains("Disconnected", StringComparison.OrdinalIgnoreCase);
        return hasConnected && !hasDisconnected;
    }

    /// <summary>
    /// Endpoint candidates matched to protocol (WG ports vs MASQUE ports).
    /// </summary>
    public static IEnumerable<string> EnumerateEndpointCandidates(string protocol = "WireGuard", int maxCount = 24)
    {
        bool masque = protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase);
        int[] ports = masque ? MasquePorts : WireGuardPorts;

        // Prefer hostname first, then a shuffled subset of IPs to avoid long scans
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

    public static async Task<(bool Ok, string Message, string? Endpoint)> TryConnectWithFallbackAsync(
        IEnumerable<string> endpoints,
        string preferredProtocol = "WireGuard",
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        if (!IsInstalled())
            return (false, "Cloudflare WARP (warp-cli) is not installed.", null);

        AcceptTos();
        Disconnect();

        var show = Run("-j", "registration", "show");
        if (!show.Ok)
        {
            progress?.Report("Creating WARP registration…");
            var reg = Register();
            AcceptTos();
            if (!reg.Ok && !Run("-j", "registration", "show").Ok)
                return (false, "WARP registration failed: " + reg.ErrorLine, null);
        }

        SetModeWarp();
        SetProtocol(preferredProtocol);
        if (preferredProtocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
            SetMasqueOptions("h3-with-h2-fallback");

        foreach (string endpoint in endpoints)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report($"Trying endpoint {endpoint} ({preferredProtocol})…");
            Disconnect();
            var setEp = SetEndpoint(endpoint);
            if (!setEp.Ok)
            {
                progress?.Report($"Skip {endpoint}: {setEp.ErrorLine}");
                continue;
            }

            Connect();
            // Poll briefly — connection is often not instant
            for (int i = 0; i < 6; i++)
            {
                await Task.Delay(800, ct).ConfigureAwait(false);
                var st = Status();
                if (IsConnected(st))
                    return (true, $"Connected via {endpoint} ({preferredProtocol}).", endpoint);
                if (ParseStatus(st).Contains("Failed", StringComparison.OrdinalIgnoreCase))
                    break;
            }

            progress?.Report($"No connect on {endpoint}: {ParseStatus(Status())}");
        }

        progress?.Report("Trying default endpoint + MASQUE…");
        Disconnect();
        ResetEndpoint();
        SetProtocol("MASQUE");
        SetMasqueOptions("h3-with-h2-fallback");
        Connect();
        for (int i = 0; i < 6; i++)
        {
            await Task.Delay(800, ct).ConfigureAwait(false);
            var st2 = Status();
            if (IsConnected(st2))
                return (true, "Connected via default endpoint (MASQUE).", null);
        }

        return (false, "Could not connect. Your ISP may block WARP; try MASQUE, another endpoint, or another network.", null);
    }

    public static async Task<string?> FetchPublicIpAsync(int timeoutMs = 8000)
    {
        try
        {
            using HttpClient client = new() { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
            string body = await client.GetStringAsync("https://cloudflare.com/cdn-cgi/trace").ConfigureAwait(false);
            foreach (string line in body.Split('\n'))
            {
                if (line.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                    return line[3..].Trim();
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("FetchPublicIpAsync cf: " + ex.Message);
        }
        try
        {
            using HttpClient client = new() { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
            return (await client.GetStringAsync("https://api.ipify.org").ConfigureAwait(false)).Trim();
        }
        catch (Exception ex)
        {
            Debug.WriteLine("FetchPublicIpAsync ipify: " + ex.Message);
            return null;
        }
    }

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
