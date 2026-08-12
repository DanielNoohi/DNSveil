using MsmhToolsClass;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace SecureDNSClient;

public class IpScannerResult
{
    public string? IP { get; set; }
    public int RealDelay { get; set; }
    public int TcpDelay { get; set; }
    public int PingDelay { get; set; }

    public IpScannerResult() { }
}

public class IpScanner
{
    private readonly List<IpScannerResult> WorkingIPs = new();
    private List<string> CIDR_List { get; set; } = new();
    private CancellationTokenSource? _cts;
    private int _checkedCount;

    public bool IsRunning { get; private set; }
    public int CheckPort { get; set; } = 443;

    /// <summary>An open website with chosen CDN to check. e.g. https://www.cloudflare.com</summary>
    public string CheckWebsite { get; set; } = "https://www.cloudflare.com";

    /// <summary>HTTP check timeout (ms). TCP prefilter uses a shorter fraction of this.</summary>
    public int Timeout { get; set; } = 1000;

    /// <summary>How many IPs to probe at once (TCP+HTTP).</summary>
    public int Parallelism { get; set; } = 48;

    public bool RandomScan { get; set; } = true;

    /// <summary>When false, ICMP is measured but not required for a hit (much faster / works when ping is blocked).</summary>
    public bool RequirePing { get; set; } = false;

    public event EventHandler<EventArgs>? OnWorkingIpReceived;
    public event EventHandler<EventArgs>? OnNewIpCheck;
    public event EventHandler<EventArgs>? OnNumberOfCheckedIpChanged;
    public event EventHandler<EventArgs>? OnPercentChanged;
    public event EventHandler<EventArgs>? OnFullReportChanged;

    public List<IpScannerResult> GetWorkingIPs => WorkingIPs;

    public int GetAllIPsCount { get; private set; }

    public void SetIpRange(List<string> cidrList) => CIDR_List = cidrList;

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { /* ignore */ }
    }

    public void Start()
    {
        if (IsRunning) return;
        IsRunning = true;
        WorkingIPs.Clear();
        _checkedCount = 0;
        GetAllIPsCount = 0;
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        CancellationToken ct = _cts.Token;

        int parallelism = Math.Clamp(Parallelism, 1, 256);
        int httpTimeout = Math.Clamp(Timeout, 200, 15_000);
        int tcpTimeout = Math.Clamp(httpTimeout / 3, 150, 800);

        _ = Task.Run(async () =>
        {
            IPRange? ipRange = null;
            try
            {
                NetworkTool.URL urid = NetworkTool.GetUrlOrDomainDetails(CheckWebsite, CheckPort);
                string urlScheme = CheckWebsite.Contains("://", StringComparison.Ordinal)
                    ? CheckWebsite.Split("://", 2)[0].Trim().ToLowerInvariant() + "://"
                    : "https://";
                string checkUrl = $"{urlScheme}{urid.Host}:{CheckPort}";

                ipRange = new IPRange(CIDR_List);
                ipRange.StartGenerateIPs();
                await Task.Delay(80, ct).ConfigureAwait(false);

                int startIndex = 0;
                while (!ct.IsCancellationRequested)
                {
                    ipRange.Pause(true);
                    await Task.Delay(1, ct).ConfigureAwait(false);

                    List<IPAddress> batch = ipRange.IPs.GetRange(startIndex, ipRange.IPs.Count - startIndex);
                    startIndex = ipRange.IPs.Count;
                    GetAllIPsCount = Math.Max(GetAllIPsCount, startIndex);

                    if (batch.Count == 0)
                    {
                        ipRange.Pause(false);
                        await Task.Delay(30, ct).ConfigureAwait(false);
                        if (!ipRange.IsRunning) break;
                        continue;
                    }

                    if (RandomScan)
                        Shuffle(batch);

                    await Parallel.ForEachAsync(
                        batch,
                        new ParallelOptions { MaxDegreeOfParallelism = parallelism, CancellationToken = ct },
                        async (ip, token) =>
                        {
                            string ipOut = ip.ToString();
                            int checkedNow = Interlocked.Increment(ref _checkedCount);
                            try
                            {
                                OnNewIpCheck?.Invoke(ipOut, EventArgs.Empty);
                                OnNumberOfCheckedIpChanged?.Invoke(checkedNow, EventArgs.Empty);
                                if (checkedNow % 8 == 0 || checkedNow <= 3)
                                {
                                    int percent = GetAllIPsCount > 0
                                        ? Math.Min(99, (checkedNow * 100) / Math.Max(GetAllIPsCount, 1))
                                        : 0;
                                    OnPercentChanged?.Invoke(percent, EventArgs.Empty);
                                    OnFullReportChanged?.Invoke(
                                        $"Checking: {ipOut} ({checkedNow} checked, {WorkingIPs.Count} hits, x{parallelism})",
                                        EventArgs.Empty);
                                }

                                // 1) Cheap TCP prefilter — most CF IPs fail here in <tcpTimeout ms
                                Stopwatch swTcp = Stopwatch.StartNew();
                                bool tcpOk = await FastTcpConnectAsync(ipOut, CheckPort, tcpTimeout, token).ConfigureAwait(false);
                                swTcp.Stop();
                                if (!tcpOk) return;

                                int tcpDelayOut = (int)swTcp.ElapsedMilliseconds;

                                // 2) HTTPS with Host header to candidate IP (only survivors)
                                Stopwatch swHttp = Stopwatch.StartNew();
                                HttpStatusCode hsc = await NetworkTool.GetHttpStatusCodeAsync(
                                    checkUrl, ipOut, httpTimeout, true, false, false,
                                    null, null, null, token).ConfigureAwait(false);
                                swHttp.Stop();
                                if (hsc != HttpStatusCode.OK) return;

                                int realDelayOut = (int)swHttp.ElapsedMilliseconds;

                                // 3) Optional ping (display only unless RequirePing)
                                int pingDelayOut = -1;
                                try
                                {
                                    Stopwatch swPing = Stopwatch.StartNew();
                                    bool canPing = await NetworkTool.CanPingAsync(ipOut, Math.Min(httpTimeout, 800)).ConfigureAwait(false);
                                    swPing.Stop();
                                    if (canPing) pingDelayOut = (int)swPing.ElapsedMilliseconds;
                                }
                                catch { /* ignore */ }

                                if (RequirePing && pingDelayOut < 0) return;

                                var result = new IpScannerResult
                                {
                                    IP = ipOut,
                                    RealDelay = realDelayOut,
                                    TcpDelay = tcpDelayOut,
                                    PingDelay = pingDelayOut
                                };

                                lock (WorkingIPs) WorkingIPs.Add(result);
                                OnWorkingIpReceived?.Invoke(result, EventArgs.Empty);
                            }
                            catch (OperationCanceledException) { throw; }
                            catch (Exception ex)
                            {
                                Debug.WriteLine("IpScanner probe: " + ex.Message);
                            }
                        }).ConfigureAwait(false);

                    ipRange.Pause(false);
                    await Task.Delay(1, ct).ConfigureAwait(false);
                    if (!ipRange.IsRunning && startIndex >= ipRange.IPs.Count) break;
                }

                OnPercentChanged?.Invoke(100, EventArgs.Empty);
                OnFullReportChanged?.Invoke(
                    $"Done. Checked {_checkedCount}, found {WorkingIPs.Count} clean IP(s).",
                    EventArgs.Empty);
            }
            catch (OperationCanceledException)
            {
                OnFullReportChanged?.Invoke(
                    $"Stopped. Checked {_checkedCount}, found {WorkingIPs.Count} clean IP(s).",
                    EventArgs.Empty);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("IpScanner Start: " + ex.Message);
            }
            finally
            {
                try { ipRange?.Dispose(); } catch { /* ignore */ }
                IsRunning = false;
            }
        }, ct);
    }

    private static async Task<bool> FastTcpConnectAsync(string hostOrIp, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            client.NoDelay = true;
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeoutMs);
            await client.ConnectAsync(hostOrIp, port, linked.Token).ConfigureAwait(false);
            return client.Connected;
        }
        catch
        {
            return false;
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
}
