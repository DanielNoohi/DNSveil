using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace SecureDNSClient.GeoHide;

/// <summary>
/// Persistent GeoHide connection diagnostics for humans and later agent debugging.
/// Files: <c>UserData/GeoHideLogs/session-*.log</c> + matching <c>.jsonl</c>.
/// Prefer high-signal fields (status, warp=on, decisions, timings) — avoid spam.
/// </summary>
public static class WarpSessionLog
{
    private static readonly object Gate = new();
    private static string? _sessionId;
    private static string? _logPath;
    private static string? _jsonlPath;
    private static readonly Stopwatch SinceStart = new();
    private static string? _lastStatusLogged;
    private static int _attemptIndex;
    private static int _acceptCount;
    private static int _rejectCount;

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
    public static long ElapsedMs => SinceStart.IsRunning ? SinceStart.ElapsedMilliseconds : 0;

    public static void BeginSession(string reason, IDictionary<string, object?>? meta = null)
    {
        lock (Gate)
        {
            _sessionId = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8];
            _logPath = Path.Combine(LogDirectory, $"session-{_sessionId}.log");
            _jsonlPath = Path.Combine(LogDirectory, $"session-{_sessionId}.jsonl");
            SinceStart.Restart();
            _lastStatusLogged = null;
            _attemptIndex = 0;
            _acceptCount = 0;
            _rejectCount = 0;

            var sb = new StringBuilder();
            sb.AppendLine($"# DNSveil GeoHide session {_sessionId}");
            sb.AppendLine($"# UTC {DateTime.UtcNow:O}");
            sb.AppendLine($"# reason: {reason}");
            sb.AppendLine($"# product: {InfoProductVersion()}");
            sb.AppendLine($"# os: {Environment.OSVersion}");
            sb.AppendLine($"# admin: {IsElevated()}");
            sb.AppendLine($"# portable: {Program.IsPortable}");
            sb.AppendLine($"# userdata: {SecureDNS.UserDataDirPath}");
            if (meta != null)
            {
                foreach (var kv in meta)
                    sb.AppendLine($"# meta.{kv.Key}: {FormatVal(kv.Value)}");
            }
            sb.AppendLine("# ---");
            sb.AppendLine("# Agent hints: look for phase=decision (accept/reject reasons), phase=egress (warp/ip/loc/colo),");
            sb.AppendLine("# phase=attempt_result (per endpoint outcome), phase=status_change (Connecting→…), phase=env.");
            sb.AppendLine();
            File.WriteAllText(_logPath, sb.ToString(), Encoding.UTF8);
            WriteJsonl(new Dictionary<string, object?>
            {
                ["t"] = DateTime.UtcNow.ToString("O"),
                ["ms"] = 0,
                ["event"] = "session_begin",
                ["reason"] = reason,
                ["product"] = InfoProductVersion(),
                ["os"] = Environment.OSVersion.ToString(),
                ["admin"] = IsElevated(),
                ["portable"] = Program.IsPortable,
                ["userdata"] = SecureDNS.UserDataDirPath,
                ["meta"] = meta,
            });
        }
    }

    /// <summary>One-line human + structured step.</summary>
    public static void Step(string phase, string detail, IDictionary<string, object?>? data = null)
    {
        lock (Gate)
        {
            if (string.IsNullOrEmpty(_logPath)) return;
            long ms = SinceStart.ElapsedMilliseconds;
            string extra = FormatDataInline(data);
            string line = string.IsNullOrEmpty(extra)
                ? $"[{DateTime.Now:HH:mm:ss.fff} +{ms}ms] [{phase}] {detail}"
                : $"[{DateTime.Now:HH:mm:ss.fff} +{ms}ms] [{phase}] {detail} | {extra}";
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

    /// <summary>Environment / warp-cli capability snapshot (call once near start).</summary>
    public static void Env(IDictionary<string, object?> data)
        => Step("env", "snapshot", data);

    /// <summary>Explicit accept/reject so agents see why a path was taken.</summary>
    public static void Decision(string action, string reason, IDictionary<string, object?>? data = null)
    {
        if (action.StartsWith("accept", StringComparison.OrdinalIgnoreCase)) _acceptCount++;
        else if (action.StartsWith("reject", StringComparison.OrdinalIgnoreCase)) _rejectCount++;

        var payload = new Dictionary<string, object?> { ["action"] = action, ["reason"] = reason };
        if (data != null)
        {
            foreach (var kv in data)
                payload[kv.Key] = kv.Value;
        }
        Step("decision", $"{action}: {reason}", payload);
    }

    /// <summary>Log status only when the parsed status string changes (avoids poll spam).</summary>
    public static void StatusChange(string parsedStatus, IDictionary<string, object?>? data = null)
    {
        string key = (parsedStatus ?? "").Trim();
        if (string.Equals(key, _lastStatusLogged, StringComparison.OrdinalIgnoreCase))
            return;
        _lastStatusLogged = key;
        var payload = new Dictionary<string, object?> { ["status"] = key };
        if (data != null)
        {
            foreach (var kv in data)
                payload[kv.Key] = kv.Value;
        }
        Step("status_change", key, payload);
    }

    /// <summary>CF / egress probe result — the most important post-connect signal.</summary>
    public static void Egress(string source, WarpCli.PublicIpInfo info, IDictionary<string, object?>? extra = null)
    {
        var payload = new Dictionary<string, object?>
        {
            ["source"] = source,
            ["ip"] = info.Ip,
            ["warpOn"] = info.WarpOn,
            ["loc"] = info.Loc,
            ["colo"] = info.Colo,
            ["gateway"] = info.Gateway,
            ["http"] = info.Http,
            ["error"] = info.Error,
        };
        if (extra != null)
        {
            foreach (var kv in extra)
                payload[kv.Key] = kv.Value;
        }
        string detail = $"ip={info.Ip ?? "?"} warp={(info.WarpOn == true ? "on" : info.WarpOn == false ? "off" : "?")} loc={info.Loc ?? "?"} colo={info.Colo ?? "?"} via={source}";
        if (!string.IsNullOrEmpty(info.Error))
            detail += $" err={info.Error}";
        Step("egress", detail, payload);
    }

    /// <summary>Per-endpoint attempt start.</summary>
    public static int BeginAttempt(string endpoint, string protocol, int index, int total)
    {
        _attemptIndex = index;
        Step("attempt", $"start [{index}/{total}] {endpoint} ({protocol})",
            new Dictionary<string, object?>
            {
                ["endpoint"] = endpoint,
                ["protocol"] = protocol,
                ["index"] = index,
                ["total"] = total,
                ["attemptId"] = index,
            });
        return index;
    }

    /// <summary>Per-endpoint outcome with duration — gold for ranking what works.</summary>
    public static void AttemptResult(
        string endpoint,
        string protocol,
        string outcome,
        long durationMs,
        IDictionary<string, object?>? data = null)
    {
        var payload = new Dictionary<string, object?>
        {
            ["endpoint"] = endpoint,
            ["protocol"] = protocol,
            ["outcome"] = outcome,
            ["durationMs"] = durationMs,
            ["attemptId"] = _attemptIndex,
        };
        if (data != null)
        {
            foreach (var kv in data)
                payload[kv.Key] = kv.Value;
        }
        Step("attempt_result", $"{outcome} {endpoint} in {durationMs}ms", payload);
    }

    public static void Cli(string args, WarpCli.Result result, bool always = false)
    {
        // Skip noisy successful no-op spam unless always requested.
        if (!always && result.Ok && string.IsNullOrWhiteSpace(result.StdErr) &&
            (args.StartsWith("tunnel ip add-range", StringComparison.OrdinalIgnoreCase) ||
             args.Equals("status", StringComparison.OrdinalIgnoreCase)))
            return;

        Step("warp-cli", args,
            new Dictionary<string, object?>
            {
                ["exit"] = result.ExitCode,
                ["ok"] = result.Ok,
                ["stdout"] = Truncate(result.StdOut, 600),
                ["stderr"] = Truncate(result.StdErr, 600),
            });
    }

    public static void End(bool ok, string summary, IDictionary<string, object?>? data = null)
    {
        lock (Gate)
        {
            var stats = new Dictionary<string, object?>
            {
                ["ok"] = ok,
                ["elapsedMs"] = SinceStart.ElapsedMilliseconds,
                ["accepts"] = _acceptCount,
                ["rejects"] = _rejectCount,
                ["lastStatus"] = _lastStatusLogged,
            };
            if (data != null)
            {
                foreach (var kv in data)
                    stats[kv.Key] = kv.Value;
            }

            Step(ok ? "success" : "failure", summary, stats);
            if (!string.IsNullOrEmpty(_logPath))
            {
                try
                {
                    File.AppendAllText(_logPath,
                        Environment.NewLine +
                        $"# END ok={ok} elapsed={SinceStart.ElapsedMilliseconds}ms accepts={_acceptCount} rejects={_rejectCount}" + Environment.NewLine +
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
                ["data"] = stats,
                ["log"] = _logPath,
                ["jsonl"] = _jsonlPath,
            });
        }
    }

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

    private static string FormatDataInline(IDictionary<string, object?>? data)
    {
        if (data == null || data.Count == 0) return "";
        // Keep human log skim-friendly: only a few high-signal keys inline.
        string[] prefer = { "outcome", "reason", "action", "status", "warpOn", "ip", "loc", "colo", "endpoint", "protocol", "durationMs", "err", "error", "source" };
        var parts = new List<string>();
        foreach (string k in prefer)
        {
            if (!data.TryGetValue(k, out object? v) || v == null) continue;
            parts.Add($"{k}={FormatVal(v)}");
            if (parts.Count >= 8) break;
        }
        return string.Join(" ", parts);
    }

    private static string FormatVal(object? v)
    {
        if (v == null) return "";
        if (v is bool b) return b ? "true" : "false";
        string s = v.ToString() ?? "";
        s = s.Replace("\r", " ").Replace("\n", " | ");
        return s.Length <= 120 ? s : s[..120] + "…";
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

    private static bool IsElevated()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(id);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
