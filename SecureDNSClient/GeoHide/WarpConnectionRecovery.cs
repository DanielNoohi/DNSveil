namespace SecureDNSClient.GeoHide;

/// <summary>Serial, bounded attempts. A failed or cancelled attempt finishes cleanup before the next starts.</summary>
internal static class WarpConnectionRecovery
{
    internal sealed record Attempt(string Protocol, string? Endpoint);

    internal static IReadOnlyList<Attempt> WireGuardPlan(IEnumerable<string>? endpoints, int limit)
    {
        var supplied = endpoints?.Where(e => !string.IsNullOrWhiteSpace(e)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        // Use actual daemon handshakes; a UDP send cannot establish remote reachability.
        var plan = supplied is { Count: > 0 }
            ? supplied.Select(e => new Attempt("WireGuard", e)).ToList()
            : new List<Attempt> { new("WireGuard", null), new("WireGuard", "162.159.192.1:500"),
                new("WireGuard", "162.159.192.1:4500"), new("WireGuard", "162.159.192.2:1701") };
        return plan.Take(Math.Clamp(limit, 1, 4)).ToArray();
    }

    internal static async Task<WarpRegionalSearch.Connection> RunAsync(
        IReadOnlyList<Attempt> attempts,
        Func<Attempt, CancellationToken, Task<WarpRegionalSearch.Connection>> connect,
        Func<Task> cleanup, IProgress<string>? progress, CancellationToken ct, TimeSpan attemptBudget)
    {
        var failures = new List<string>();
        foreach (var attempt in attempts)
        {
            ct.ThrowIfCancellationRequested();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(attemptBudget);
            bool accepted = false;
            try
            {
                progress?.Report($"Trying {attempt.Protocol} / {attempt.Endpoint ?? "automatic endpoint"}…");
                var result = await connect(attempt, timeout.Token).ConfigureAwait(false);
                timeout.Token.ThrowIfCancellationRequested();
                if (result.Ok) { accepted = true; return result; }
                failures.Add(result.Message);
                progress?.Report(result.Message);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                string reason = $"{attempt.Protocol} / {attempt.Endpoint ?? "automatic endpoint"}: attempt timed out.";
                failures.Add(reason);
                progress?.Report(reason);
            }
            finally
            {
                if (!accepted) await cleanup().ConfigureAwait(false);
            }
        }
        ct.ThrowIfCancellationRequested();
        return new(false, "No tunnel completed the connection checks. " + string.Join(" ", failures), null,
            attempts.LastOrDefault()?.Protocol ?? "MASQUE");
    }
}
