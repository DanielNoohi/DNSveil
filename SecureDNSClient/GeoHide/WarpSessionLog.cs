using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace SecureDNSClient.GeoHide;

/// <summary>
/// Persistent GeoHide connection diagnostics for humans and later agent debugging.
/// Files: <c>UserData/GeoHideLogs/session-*.log</c> + matching <c>.jsonl</c>.
/// </summary>
public static class WarpSessionLog
{
    private static readonly object Gate = new();
    private static string? _sessionId;
    private static string? _logPath;
    private static string? _jsonlPath;
    private static readonly Stopwatch SinceStart = new();

    public static string LogDirectory
    {
        get
        {
            string dir = Path.Combine(SecureDNS.UserDataDirPath, "GeoHideLogs");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    public static string? CurrentLogPath => _logPath;
    public static string? CurrentJsonlPath => _jsonlPath;

    public static void BeginSession(string reason, IDictionary<string, object?>? meta = null)
    {
        lock (Gate)
        {
            _sessionId = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8];
            _logPath = Path.Combine(LogDirectory, $"session-{_sessionId}.log");
            _jsonlPath = Path.Combine(LogDirectory, $"session-{_sessionId}.jsonl");
            SinceStart.Restart();

            var sb = new StringBuilder();
            sb.AppendLine($"# DNSveil GeoHide session {_sessionId}");
            sb.AppendLine($"# UTC {DateTime.UtcNow:O}");
            sb.AppendLine($"# reason: {reason}");
            sb.AppendLine($"# product: {InfoProductVersion()}");
            if (meta != null)
            {
                foreach (var kv in meta)
                    sb.AppendLine($"# meta.{kv.Key}: {kv.Value}");
            }
            sb.AppendLine();
            File.WriteAllText(_logPath, sb.ToString(), Encoding.UTF8);
            WriteJsonl(new Dictionary<string, object?>
            {
                ["t"] = DateTime.UtcNow.ToString("O"),
                ["ms"] = 0,
                ["event"] = "session_begin",
                ["reason"] = reason,
                ["meta"] = meta,
            });
        }
    }

    public static void Step(string phase, string detail, IDictionary<string, object?>? data = null)
    {
        lock (Gate)
        {
            if (string.IsNullOrEmpty(_logPath)) return;
            long ms = SinceStart.ElapsedMilliseconds;
            string line = $"[{DateTime.Now:HH:mm:ss.fff} +{ms}ms] [{phase}] {detail}";
            try { File.AppendAllText(_logPath, line + Environment.NewLine, Encoding.UTF8); }
            catch { /* ignore IO */ }

            var payload = new Dictionary<string, object?>
            {
                ["t"] = DateTime.UtcNow.ToString("O"),
                ["ms"] = ms,
                ["event"] = "step",
                ["phase"] = phase,
                ["detail"] = detail,
            };
            if (data != null)
            {
                foreach (var kv in data)
                    payload[kv.Key] = kv.Value;
            }
            WriteJsonl(payload);
        }
    }

    public static void Cli(string args, WarpCli.Result result)
    {
        Step("warp-cli", args,
            new Dictionary<string, object?>
            {
                ["exit"] = result.ExitCode,
                ["ok"] = result.Ok,
                ["stdout"] = Truncate(result.StdOut, 800),
                ["stderr"] = Truncate(result.StdErr, 800),
            });
    }

    public static void End(bool ok, string summary, IDictionary<string, object?>? data = null)
    {
        lock (Gate)
        {
            Step(ok ? "success" : "failure", summary, data);
            if (!string.IsNullOrEmpty(_logPath))
            {
                try
                {
                    File.AppendAllText(_logPath,
                        Environment.NewLine + $"# END ok={ok} elapsed={SinceStart.ElapsedMilliseconds}ms" + Environment.NewLine +
                        $"# log={_logPath}" + Environment.NewLine +
                        $"# jsonl={_jsonlPath}" + Environment.NewLine,
                        Encoding.UTF8);
                }
                catch { /* ignore */ }
            }
            WriteJsonl(new Dictionary<string, object?>
            {
                ["t"] = DateTime.UtcNow.ToString("O"),
                ["ms"] = SinceStart.ElapsedMilliseconds,
                ["event"] = "session_end",
                ["ok"] = ok,
                ["summary"] = summary,
                ["data"] = data,
                ["log"] = _logPath,
                ["jsonl"] = _jsonlPath,
            });
        }
    }

    /// <summary>Latest session log paths (for UI / agents).</summary>
    public static (string? Log, string? Jsonl) LatestPaths()
    {
        try
        {
            var logs = Directory.GetFiles(LogDirectory, "session-*.log")
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault();
            if (logs == null) return (null, null);
            string jsonl = Path.ChangeExtension(logs, ".jsonl");
            return (logs, File.Exists(jsonl) ? jsonl : null);
        }
        catch { return (null, null); }
    }

    private static void WriteJsonl(Dictionary<string, object?> payload)
    {
        if (string.IsNullOrEmpty(_jsonlPath)) return;
        try
        {
            string json = JsonSerializer.Serialize(payload);
            File.AppendAllText(_jsonlPath, json + Environment.NewLine, Encoding.UTF8);
        }
        catch { /* ignore */ }
    }

    private static string Truncate(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        s = s.Replace("\r", " ").Replace("\n", " | ");
        return s.Length <= max ? s : s[..max] + "…";
    }

    private static string InfoProductVersion()
    {
        try
        {
            return System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "?";
        }
        catch { return "?"; }
    }
}
