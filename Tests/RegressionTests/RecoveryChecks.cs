using SecureDNSClient.GeoHide;

internal static class RecoveryChecks
{
    internal static async Task RunAsync(Action<bool, string> check)
    {
        var plan = WarpConnectionRecovery.WireGuardPlan(null, 100);
        check(plan.Count == 4 && plan.Select(x => x.Endpoint).Distinct().Count() == 4,
            "WireGuard uses distinct actual handshake targets and caps attempts at four");
        check(WarpConnectionRecovery.WireGuardPlan(null, 1).Count == 1,
            "Strict regional round does not repeat the WireGuard default endpoint");
        var custom = WarpConnectionRecovery.WireGuardPlan(new[] { "127.0.0.1:500", "127.0.0.1:500" }, 4);
        check(custom.Count == 1 && custom[0].Endpoint == "127.0.0.1:500", "WireGuard preserves and deduplicates explicit endpoints");
        var messages = new List<string>();
        var candidates = await WarpCli.FilterReachableEndpointsAsync(new[] { "127.0.0.1:500" }, "WireGuard",
            new InlineProgress(messages.Add), default);
        check(candidates.Count == 1 && messages.Any(x => x.Contains("unverified")) && !messages.Any(x => x.Contains("ms)")),
            "WireGuard scan labels candidates unverified instead of inventing UDP latency");
        var attempts = new[] { new WarpConnectionRecovery.Attempt("MASQUE", null), new WarpConnectionRecovery.Attempt("WireGuard", null) };
        var events = new List<string>();
        var result = await WarpConnectionRecovery.RunAsync(attempts, (attempt, _) =>
        {
            events.Add(attempt.Protocol);
            return Task.FromResult(new WarpRegionalSearch.Connection(attempt.Protocol == "WireGuard", "result", null, attempt.Protocol));
        }, () => { events.Add("cleanup"); return Task.CompletedTask; }, null, default, TimeSpan.FromSeconds(1));
        check(result.Ok && events.SequenceEqual(new[] { "MASQUE", "cleanup", "WireGuard" }),
            "Auto falls back only after failed protocol cleanup and preserves successful tunnel");
        events.Clear();
        result = await WarpConnectionRecovery.RunAsync(attempts, (attempt, _) =>
        {
            events.Add(attempt.Protocol);
            return Task.FromResult(new WarpRegionalSearch.Connection(true, "ok", null, attempt.Protocol));
        }, () => { events.Add("cleanup"); return Task.CompletedTask; }, null, default, TimeSpan.FromSeconds(1));
        check(result.Ok && events.SequenceEqual(new[] { "MASQUE" }), "Working MASQUE is preserved without unnecessary WireGuard probing");
        int count = 0, cleaned = 0;
        result = await WarpConnectionRecovery.RunAsync(attempts, async (attempt, token) =>
        {
            count++;
            if (count == 1) await Task.Delay(5000, token);
            return new(true, "ok", null, attempt.Protocol);
        }, () => { cleaned++; return Task.CompletedTask; }, null, default, TimeSpan.FromMilliseconds(60));
        check(result.Ok && count == 2 && cleaned == 1, "Timed-out protocol is cleaned up before recovery");
        count = cleaned = 0;
        using (var cts = new CancellationTokenSource())
        {
            bool cancelled = false;
            try
            {
                await WarpConnectionRecovery.RunAsync(attempts, (attempt, token) =>
                {
                    count++;
                    cts.Cancel();
                    token.ThrowIfCancellationRequested();
                    return Task.FromResult(new WarpRegionalSearch.Connection(true, "ok", null, attempt.Protocol));
                }, () => { cleaned++; return Task.CompletedTask; }, null, cts.Token, TimeSpan.FromSeconds(1));
            }
            catch (OperationCanceledException) { cancelled = true; }
            check(cancelled && count == 1 && cleaned == 1, "User cancellation never starts another protocol");
        }
        count = 0;
        bool cleanupFailure = false;
        try
        {
            await WarpConnectionRecovery.RunAsync(attempts, (attempt, _) =>
            {
                count++;
                return Task.FromResult(new WarpRegionalSearch.Connection(false, "failed", null, attempt.Protocol));
            }, () => throw new InvalidOperationException("disconnect failed"), null, default, TimeSpan.FromSeconds(1));
        }
        catch (InvalidOperationException) { cleanupFailure = true; }
        check(cleanupFailure && count == 1, "Unconfirmed cleanup stops recovery instead of stacking tunnels");
        check(WarpDiagnostics.DescribeHttp("Spotify", 200).Contains("app access not tested"), "HTTP success does not claim playback works");
        check(WarpDiagnostics.DescribeHttp("ChatGPT", 403).Contains("does not prove a country block"), "HTTP denial is not misdiagnosed as a regional block");
        check(WarpDiagnostics.DescribeHttp("Service", 429).Contains("rate limited"), "Rate limiting is distinguished from connection failure");
    }

    private sealed class InlineProgress : IProgress<string>
    {
        private readonly Action<string> report;
        public InlineProgress(Action<string> report) { this.report = report; }
        public void Report(string value) => report(value);
    }
}
