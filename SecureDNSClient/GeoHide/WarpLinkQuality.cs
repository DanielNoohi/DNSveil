using System.Diagnostics;
using System.Net.Http;

namespace SecureDNSClient.GeoHide;

/// <summary>
/// Measures tunnel usefulness beyond "Connected + warp=on":
/// RTT samples, success rate, and a small download. Weak/timing-out links are rejected
/// so Connect can rotate to another endpoint.
/// </summary>
public static class WarpLinkQuality
{
    private static readonly HttpClient Http = CreateHttp();

    private static HttpClient CreateHttp()
    {
        var h = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = true,
            UseProxy = false,
        })
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
        h.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "DNSveil-GeoHide/1.0");
        return h;
    }

    public sealed class Report
    {
        public bool Ok { get; init; }
        public string Reason { get; init; } = "";
        public int Successes { get; init; }
        public int Failures { get; init; }
        public int MedianRttMs { get; init; }
        public int MaxRttMs { get; init; }
        public int DownloadMs { get; init; }
        public bool DownloadOk { get; init; }
        public string Summary =>
            $"ok={Ok} rttMed={MedianRttMs}ms rttMax={MaxRttMs}ms " +
            $"okSamples={Successes}/{Successes + Failures} dl={(DownloadOk ? DownloadMs + "ms" : "fail")} ({Reason})";
    }

    /// <summary>
    /// Strict quality gate for accepting an endpoint under DPI / censorship.
    /// </summary>
    public static async Task<Report> EvaluateAsync(
        IProgress<string>? progress,
        CancellationToken ct,
        bool strict = true)
    {
        int samples = strict ? 6 : 3;
        int timeoutMs = strict ? 5500 : 4500;
        int gapMs = strict ? 1200 : 900;
        int minSuccess = strict ? 5 : 2;
        int maxMedianMs = strict ? 2800 : 3500;
        int maxAnyMs = strict ? 5500 : 7000;
        int soakDelayMs = strict ? 10000 : 0;
        int soakSamples = strict ? 2 : 0;

        progress?.Report($"Quality check: {samples} probes" +
                         (soakSamples > 0 ? $" + {soakSamples} after {soakDelayMs / 1000}s soak…" : "…"));

        var rtts = new List<int>();
        int successes = 0;
        int failures = 0;
        string lastFail = "";

        async Task RunBatchAsync(int count, string phase)
        {
            for (int i = 0; i < count; i++)
            {
                ct.ThrowIfCancellationRequested();
                if (!WarpCli.IsConnected(WarpCli.Status()))
                {
                    failures++;
                    lastFail = "status not Connected";
                    WarpSessionLog.Step("quality", $"{phase} lost Connected",
                        new Dictionary<string, object?> { ["i"] = i });
                    break;
                }

                var (ok, rtt, info) = await ProbeTraceAsync(timeoutMs, ct).ConfigureAwait(false);
                if (ok)
                {
                    successes++;
                    rtts.Add(rtt);
                    WarpSessionLog.Step("quality", $"{phase} ok {rtt}ms",
                        new Dictionary<string, object?>
                        {
                            ["i"] = i,
                            ["rtt"] = rtt,
                            ["ip"] = info.Ip,
                            ["loc"] = info.Loc,
                            ["colo"] = info.Colo,
                        });
                }
                else
                {
                    failures++;
                    lastFail = string.IsNullOrEmpty(info.Error) ? $"warp≠on or timeout ({rtt}ms)" : info.Error!;
                    WarpSessionLog.Step("quality", $"{phase} fail",
                        new Dictionary<string, object?>
                        {
                            ["i"] = i,
                            ["rtt"] = rtt,
                            ["error"] = lastFail,
                            ["warpOn"] = info.WarpOn,
                        });
                }

                if (i + 1 < count)
                    await Task.Delay(gapMs, ct).ConfigureAwait(false);
            }
        }

        await RunBatchAsync(samples, "burst").ConfigureAwait(false);

        if (soakSamples > 0 && failures < samples) // still possibly salvageable
        {
            progress?.Report($"Quality soak: waiting {soakDelayMs / 1000}s then re-probe (catches late timeouts)…");
            await Task.Delay(soakDelayMs, ct).ConfigureAwait(false);
            await RunBatchAsync(soakSamples, "soak").ConfigureAwait(false);
        }

        int median = Median(rtts);
        int max = rtts.Count > 0 ? rtts.Max() : timeoutMs;
        int total = successes + failures;

        // Tiny download through the tunnel — pure CF-trace success can still mean a dead path.
        progress?.Report("Quality: download probe (40KB via Cloudflare)…");
        var (dlOk, dlMs) = await ProbeDownloadAsync(40_000, Math.Max(timeoutMs, 8000), ct).ConfigureAwait(false);
        WarpSessionLog.Step("quality", dlOk ? $"download ok {dlMs}ms" : $"download fail {dlMs}ms",
            new Dictionary<string, object?> { ["ok"] = dlOk, ["ms"] = dlMs });

        string reason;
        bool okFinal;
        if (successes < minSuccess)
        {
            okFinal = false;
            reason = $"too many timeouts/fails ({successes}/{total} ok; last={lastFail})";
        }
        else if (median > maxMedianMs)
        {
            okFinal = false;
            reason = $"median RTT {median}ms > {maxMedianMs}ms";
        }
        else if (max > maxAnyMs)
        {
            okFinal = false;
            reason = $"worst RTT {max}ms > {maxAnyMs}ms";
        }
        else if (!dlOk)
        {
            okFinal = false;
            reason = $"download probe timed out/failed ({dlMs}ms)";
        }
        else if (dlMs > 12_000)
        {
            okFinal = false;
            reason = $"download too slow ({dlMs}ms)";
        }
        else
        {
            okFinal = true;
            reason = "pass";
        }

        var report = new Report
        {
            Ok = okFinal,
            Reason = reason,
            Successes = successes,
            Failures = failures,
            MedianRttMs = median,
            MaxRttMs = max,
            DownloadMs = dlMs,
            DownloadOk = dlOk,
        };

        WarpSessionLog.Step("quality", report.Summary,
            new Dictionary<string, object?>
            {
                ["ok"] = report.Ok,
                ["reason"] = report.Reason,
                ["median"] = median,
                ["max"] = max,
                ["successes"] = successes,
                ["failures"] = failures,
                ["downloadMs"] = dlMs,
                ["downloadOk"] = dlOk,
            });
        progress?.Report("Quality: " + report.Summary);
        return report;
    }

    /// <summary>Lighter check for background health (no long soak).</summary>
    public static Task<Report> EvaluateHealthAsync(IProgress<string>? progress, CancellationToken ct)
        => EvaluateAsync(progress, ct, strict: false);

    private static async Task<(bool Ok, int RttMs, WarpCli.PublicIpInfo Info)> ProbeTraceAsync(
        int timeoutMs, CancellationToken ct)
    {
        string[] urls =
        {
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://1.1.1.1/cdn-cgi/trace",
            "https://cloudflare.com/cdn-cgi/trace",
        };
        string url = urls[Environment.TickCount % urls.Length];
        var sw = Stopwatch.StartNew();
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeoutMs);
            string body = await Http.GetStringAsync(url, linked.Token).ConfigureAwait(false);
            sw.Stop();
            var info = ParseTrace(body, url);
            bool ok = info.WarpOn == true && !string.IsNullOrWhiteSpace(info.Ip);
            return (ok, (int)sw.ElapsedMilliseconds, info);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return (false, (int)sw.ElapsedMilliseconds,
                new WarpCli.PublicIpInfo { Error = ex.GetType().Name + ": " + ex.Message, Source = url });
        }
    }

    private static async Task<(bool Ok, int Ms)> ProbeDownloadAsync(int bytes, int timeoutMs, CancellationToken ct)
    {
        string url = $"https://speed.cloudflare.com/__down?bytes={bytes}";
        var sw = Stopwatch.StartNew();
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeoutMs);
            byte[] data = await Http.GetByteArrayAsync(url, linked.Token).ConfigureAwait(false);
            sw.Stop();
            bool ok = data.Length >= Math.Min(bytes, 1024);
            return (ok, (int)sw.ElapsedMilliseconds);
        }
        catch
        {
            sw.Stop();
            return (false, (int)sw.ElapsedMilliseconds);
        }
    }

    private static WarpCli.PublicIpInfo ParseTrace(string body, string source)
    {
        string? ip = null;
        bool? warp = null;
        string? loc = null;
        string? colo = null;
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
        }
        return new WarpCli.PublicIpInfo
        {
            Ip = ip,
            WarpOn = warp,
            Loc = loc,
            Colo = colo,
            Source = source,
        };
    }

    private static int Median(List<int> values)
    {
        if (values.Count == 0) return 0;
        var sorted = values.OrderBy(x => x).ToList();
        int mid = sorted.Count / 2;
        if (sorted.Count % 2 == 1) return sorted[mid];
        return (sorted[mid - 1] + sorted[mid]) / 2;
    }
}
