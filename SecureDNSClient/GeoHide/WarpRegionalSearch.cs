namespace SecureDNSClient.GeoHide;

/// <summary>Bounded experimental search. A changed country is an observation, not an access guarantee.</summary>
internal static class WarpRegionalSearch
{
    internal sealed record Connection(bool Ok, string Message, string? Endpoint, string Protocol);

    internal static async Task<Connection> RunAsync(
        Func<int, CancellationToken, Task<Connection>> connect,
        Func<CancellationToken, Task<WarpExitCheck.Report>> observe,
        Func<Connection?, Task> cleanup,
        string excludedCountry, IProgress<string>? progress, CancellationToken ct,
        int rounds = 3, TimeSpan? budget = null)
    {
        ct.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(budget ?? TimeSpan.FromMinutes(2));
        Connection? current = null;
        bool accepted = false;
        bool needsCleanup = false;
        string last = "No exit could be verified.";
        try
        {
            for (int round = 0; round < Math.Clamp(rounds, 1, 3); round++)
            {
                deadline.Token.ThrowIfCancellationRequested();
                progress?.Report($"Experimental exit search: round {round + 1}/{Math.Clamp(rounds, 1, 3)}. WARP cannot guarantee a country change.");
                needsCleanup = true;
                current = await connect(round, deadline.Token).ConfigureAwait(false);
                if (current.Ok)
                {
                    var report = await observe(deadline.Token).ConfigureAwait(false);
                    last = report.Summary;
                    progress?.Report(last);
                    deadline.Token.ThrowIfCancellationRequested();
                    if (report.IsOutside(excludedCountry))
                    {
                        accepted = true;
                        return current with { Message = "Both tested routes report a country outside " + excludedCountry + ". " + last +
                            " App login, playback and gameplay remain unverified. This is not a kill switch." };
                    }
                    progress?.Report("Exit not accepted: original country, WARP off, or an unverified IP family. Trying another route.");
                }
                else last = current.Message;
                await cleanup(current).ConfigureAwait(false);
                needsCleanup = false;
                current = null;
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            last = "The two-minute search budget expired.";
        }
        finally
        {
            if (!accepted && needsCleanup) await cleanup(current).ConfigureAwait(false);
        }
        ct.ThrowIfCancellationRequested();
        return new(false, "No verified exit outside " + excludedCountry + " was found. " + last +
            " WARP was asked to disconnect; normal Internet traffic is not blocked. DNS or a Frankfurt entry point cannot guarantee another country.", null, current?.Protocol ?? "MASQUE");
    }
}
