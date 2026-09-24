namespace SecureDNSClient.GeoHide;

/// <summary>Each worker owns its profile pair and waits for cleanup before taking another endpoint.</summary>
internal static class WarpParallelScan
{
    internal static async Task RunAsync(IReadOnlyList<string> endpoints, int workers,
        Func<int, string, CancellationToken, Task> scan, CancellationToken ct)
    {
        if (workers is < 1 or > 4) throw new ArgumentOutOfRangeException(nameof(workers));
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        int next = -1;
        async Task WorkerAsync(int worker)
        {
            try
            {
                while (true)
                {
                    stop.Token.ThrowIfCancellationRequested();
                    int index = Interlocked.Increment(ref next);
                    if (index >= endpoints.Count) return;
                    await scan(worker, endpoints[index], stop.Token);
                }
            }
            catch { stop.Cancel(); throw; }
        }
        // Keep the caller's synchronization context so UI callbacks remain serialized.
        await Task.WhenAll(Enumerable.Range(0, Math.Min(workers, endpoints.Count)).Select(WorkerAsync));
    }
}
