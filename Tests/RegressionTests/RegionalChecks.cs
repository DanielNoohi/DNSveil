using System.Net.Sockets;
using SecureDNSClient.GeoHide;

internal static class RegionalChecks
{
    internal static async Task RunAsync(Action<bool, string> check)
    {
        WarpExitCheck.Observation V4(string country, string warp = "on") =>
            WarpExitCheck.Parse($"ip=203.0.113.5\nloc={country}\ncolo=FRA\nwarp={warp}", AddressFamily.InterNetwork);
        WarpExitCheck.Observation V6(string country, string warp = "on") =>
            WarpExitCheck.Parse($"ip=2001:db8::5\nloc={country}\ncolo=FRA\nwarp={warp}", AddressFamily.InterNetworkV6);
        var iran = new WarpExitCheck.Report(V4("IR"), V6("IR"));
        var germany = new WarpExitCheck.Report(V4("DE"), V6("DE"));
        check(!iran.IsOutside("IR"), "Frankfurt data center does not override Iranian exit country");
        check(germany.IsOutside("IR"), "Both verified non-IR routes meet the experimental criterion");
        check(!new WarpExitCheck.Report(V4("DE"), V6("IR")).IsOutside("IR"), "IPv6 original-country route prevents acceptance");
        check(!new WarpExitCheck.Report(V4("IR"), V6("DE")).IsOutside("IR"), "IPv4 original-country route prevents acceptance");
        check(!new WarpExitCheck.Report(V4("DE", "off"), V6("DE")).IsOutside("IR"), "Unprotected route prevents acceptance");
        var missing = WarpExitCheck.Parse("ip=203.0.113.5\nwarp=on\ncolo=FRA", AddressFamily.InterNetwork);
        check(!new WarpExitCheck.Report(missing, V6("DE")).IsOutside("IR"), "Unknown country is not interpreted as hidden");
        var wrongFamily = WarpExitCheck.Parse("ip=203.0.113.5\nloc=DE\nwarp=on", AddressFamily.InterNetworkV6);
        check(wrongFamily.Ip == null, "Family-specific check rejects a mismatched IP family");
        check(!new WarpExitCheck.Report(V4("XX"), V6("DE")).IsOutside("IR"), "Unknown-country placeholder is rejected");
        check(!new WarpExitCheck.Report(V4("DE"), new("IPv6", null, null, null, "timeout")).IsOutside("IR"),
            "Unavailable IPv6 cannot be silently treated as safe");

        var fastIran = new XrayWarpProbeResult(iran, 50, true);
        var slowerGermany = new XrayWarpProbeResult(germany, 500, true);
        check(!fastIran.IsEligible(true) && fastIran.IsEligible(false), "Iran exit is rejected under strict mode but available for explicit connectivity-only use");
        check(slowerGermany.IsPreferredTo(fastIran) && !fastIran.IsPreferredTo(slowerGermany), "Verified outside-Iran exit outranks a faster Iranian exit");
        check(!new XrayWarpProbeResult(new(missing, V6("DE")), 20, true).IsEligible(true), "Unknown country cannot qualify as outside Iran");
        check(fastIran.SelectionStatus(false).Contains("IR"), "Connectivity-only Iranian result is explicitly labeled");

        int attempts = 0, cleanups = 0;
        var result = await WarpRegionalSearch.RunAsync((i, _) =>
        {
            attempts++;
            return Task.FromResult(new WarpRegionalSearch.Connection(true, "connected", "test-" + i, "MASQUE"));
        }, _ => Task.FromResult(iran), _ => { cleanups++; return Task.CompletedTask; }, "IR", null, default);
        check(!result.Ok && attempts == 3 && cleanups == 3, "Unchanged location stops after three rounds and cleans every attempt");

        attempts = cleanups = 0;
        result = await WarpRegionalSearch.RunAsync((i, _) =>
        {
            attempts++;
            return Task.FromResult(new WarpRegionalSearch.Connection(true, "connected", "test-" + i, "MASQUE"));
        }, _ => Task.FromResult(attempts == 2 ? germany : iran), _ => { cleanups++; return Task.CompletedTask; }, "IR", null, default);
        check(result.Ok && attempts == 2 && cleanups == 1, "Verified alternative stops the search without disconnecting the accepted tunnel");

        cleanups = 0;
        using (var cts = new CancellationTokenSource())
        {
            bool cancelled = false;
            try
            {
                await WarpRegionalSearch.RunAsync(async (_, token) =>
                {
                    cts.Cancel();
                    await Task.Delay(100, token);
                    return new(false, "unreachable", null, "MASQUE");
                }, _ => Task.FromResult(germany), _ => { cleanups++; return Task.CompletedTask; }, "IR", null, cts.Token);
            }
            catch (OperationCanceledException) { cancelled = true; }
            check(cancelled && cleanups == 1, "Cancellation during connection cleans up and remains cancellation");
        }
        cleanups = 0;
        result = await WarpRegionalSearch.RunAsync(async (_, token) =>
        {
            await Task.Delay(5000, token);
            return new(false, "unreachable", null, "MASQUE");
        }, _ => Task.FromResult(germany), _ => { cleanups++; return Task.CompletedTask; }, "IR", null, default,
            budget: TimeSpan.FromMilliseconds(50));
        check(!result.Ok && cleanups == 1, "Search deadline aborts connection and runs cleanup");
    }
}
