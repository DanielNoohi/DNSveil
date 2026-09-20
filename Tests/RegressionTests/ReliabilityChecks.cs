using System.Diagnostics;
using System.Net;
using System.Reflection;
using SecureDNSClient.GeoHide;

internal static class ReliabilityChecks
{
    internal static async Task RunAsync(Action<bool, string> check)
    {
        string executable = Environment.ProcessPath!;
        string[] Fixture(params string[] args) =>
            (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase)
                ? new[] { Assembly.GetExecutingAssembly().Location, "--fixture" }
                : new[] { "--fixture" }).Concat(args).ToArray();

        string argument = "space and \"quotes\" and trailing slash\\";
        var echo = await WarpCommandRunner.RunAsync(executable, Fixture("echo", argument), TimeSpan.FromSeconds(10));
        check(echo.ExitCode == 7 && echo.StdOut == argument && echo.StdErr == "diagnostic",
            "CLI preserves arguments, stderr and nonzero exit code");
        var flood = await WarpCommandRunner.RunAsync(executable, Fixture("flood"), TimeSpan.FromSeconds(10));
        check(flood.Ok && flood.StdOut.Length == 100_000 && flood.StdErr.Length == 100_000,
            "Large simultaneous output streams do not deadlock");

        foreach (bool cancel in new[] { false, true })
        {
            string pidFile = Path.Combine(Path.GetTempPath(), "dnsveil-test-" + Guid.NewGuid().ToString("N"));
            using var cts = new CancellationTokenSource();
            Task<WarpCli.Result>? command = null;
            try
            {
                command = WarpCommandRunner.RunAsync(executable, Fixture("wait", pidFile),
                    TimeSpan.FromSeconds(cancel ? 30 : 2), cts.Token);
                var start = Stopwatch.StartNew();
                while (!File.Exists(pidFile) && start.Elapsed < TimeSpan.FromSeconds(5) && !command.IsCompleted)
                    await Task.Delay(20);
                if (!File.Exists(pidFile)) throw new Exception("Child fixture did not start.");
                int pid = int.Parse(await File.ReadAllTextAsync(pidFile));
                bool cancelled = false;
                WarpCli.Result? result = null;
                if (cancel) cts.Cancel();
                try { result = await command; }
                catch (OperationCanceledException) { cancelled = true; }
                bool running;
                try { using var process = Process.GetProcessById(pid); running = !process.HasExited; }
                catch (ArgumentException) { running = false; }
                check(!running && (cancel ? cancelled : result?.Combined.Contains("timed out") == true),
                    cancel ? "Cancellation stops the running child process" : "Timeout stops the running child process");
            }
            finally
            {
                cts.Cancel();
                if (command != null)
                {
                    try { await command; } catch (OperationCanceledException) { }
                }
                File.Delete(pidFile);
                File.Delete(pidFile + ".writing");
            }
        }

        using (var cts = new CancellationTokenSource())
        {
            cts.Cancel();
            bool cancelled = false;
            try { await WarpCli.TryConnectWithFallbackAsync(null, ct: cts.Token); }
            catch (OperationCanceledException) { cancelled = true; }
            check(cancelled, "Pre-cancelled connect exits before inspecting or changing the network");
        }

        using (var http = new HttpClient(new Handler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ip=203.0.113.7\nwarp=on\nloc=DE") }))))
        {
            var info = await WarpCli.FetchPublicIpInfoCoreAsync(http, 1000, default);
            check(info.Ip == "203.0.113.7" && info.WarpOn == true && info.Loc == "DE", "Valid trace retains verified WARP state");
        }
        using (var http = new HttpClient(new Handler((request, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(
                request.RequestUri!.Host == "api.ipify.org" ? "203.0.113.8" : "ip=not-an-address\nwarp=on") }))))
        {
            var info = await WarpCli.FetchPublicIpInfoCoreAsync(http, 1000, default);
            check(info.Ip == "203.0.113.8" && info.WarpOn == null && info.Source == "ipify",
                "Malformed trace falls back without falsely confirming WARP");
        }
        using (var http = new HttpClient(new Handler(async (_, ct) =>
        {
            await Task.Delay(10_000, ct);
            return new HttpResponseMessage(HttpStatusCode.OK);
        })))
        {
            var elapsed = Stopwatch.StartNew();
            var info = await WarpCli.FetchPublicIpInfoCoreAsync(http, 400, default);
            check(info.Ip == null && elapsed.ElapsedMilliseconds < 1200, "All IP fallback attempts share one deadline");
            using var cts = new CancellationTokenSource(100);
            bool cancelled = false;
            try { await WarpCli.FetchPublicIpInfoCoreAsync(http, 8000, cts.Token); }
            catch (OperationCanceledException) { cancelled = true; }
            check(cancelled, "IP lookup propagates caller cancellation");
        }

        // Construct the form without showing it: no startup preflight or live WARP.
        Exception? uiError = null;
        var thread = new Thread(() =>
        {
            try
            {
                using var form = new SecureDNSClient.FormGeoHideWarp();
                var flags = BindingFlags.Instance | BindingFlags.NonPublic;
                var type = form.GetType();
                using var operation = (CancellationTokenSource)type.GetMethod("BeginOperation", flags)!.Invoke(form, null)!;
                var connectButton = (System.Windows.Forms.Button)type.GetField("_btnConnect", flags)!.GetValue(form)!;
                var refreshButton = (System.Windows.Forms.Button)type.GetField("_btnRefresh", flags)!.GetValue(form)!;
                check(!connectButton.Enabled && !refreshButton.Enabled, "Active operation prevents overlapping connect and refresh");
                var cancelButton = (System.Windows.Forms.Button)type.GetField("_btnCancel", flags)!.GetValue(form)!;
                typeof(System.Windows.Forms.Control).GetMethod("OnClick", flags)!.Invoke(cancelButton, new object[] { EventArgs.Empty });
                check(operation.IsCancellationRequested, "Cancel button targets the active operation");
                type.GetMethod("EndOperation", flags)!.Invoke(form, new object[] { operation });
                using var cancelledWatch = new CancellationTokenSource();
                cancelledWatch.Cancel();
                var done = new TaskCompletionSource<bool>();
                var task = (Task)type.GetMethod("RotateUiAsync", flags)!.Invoke(form, new object?[]
                    { null, "MASQUE", new WarpCli.CensorshipOptions(), done, cancelledWatch.Token })!;
                task.GetAwaiter().GetResult();
                check(done.Task.IsCompletedSuccessfully && !done.Task.Result,
                    "Stale cancelled health watcher cannot start recovery");
                using var closingOperation = (CancellationTokenSource)type.GetMethod("BeginOperation", flags)!.Invoke(form, null)!;
                var closeArgs = new System.Windows.Forms.FormClosingEventArgs(System.Windows.Forms.CloseReason.UserClosing, false);
                typeof(System.Windows.Forms.Form).GetMethod("OnFormClosing", flags)!.Invoke(form, new object[] { closeArgs });
                check(closeArgs.Cancel && closingOperation.IsCancellationRequested,
                    "Closing waits for the active operation to cancel before disposal");
            }
            catch (Exception ex) { uiError = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        if (!thread.Join(TimeSpan.FromSeconds(10))) throw new Exception("UI regression check hung.");
        if (uiError != null) throw new Exception("UI regression check failed.", uiError);
    }

    private sealed class Handler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _send;
        internal Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) => _send = send;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => _send(request, ct);
    }
}
