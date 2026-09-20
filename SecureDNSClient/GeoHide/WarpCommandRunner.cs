using System.Diagnostics;
using System.Text;

namespace SecureDNSClient.GeoHide;

/// <summary>Runs a child command without blocking the UI; cancellation owns its process tree.</summary>
internal static class WarpCommandRunner
{
    internal static async Task<WarpCli.Result> RunAsync(string executable, IEnumerable<string> arguments,
        TimeSpan timeout, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            }
        };
        foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        try
        {
            process.Start();
            Task<string> stdout = process.StandardOutput.ReadToEndAsync();
            Task<string> stderr = process.StandardError.ReadToEndAsync();
            try
            {
                await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
                await Task.WhenAll(stdout, stderr).WaitAsync(deadline.Token).ConfigureAwait(false);
                return new WarpCli.Result
                {
                    ExitCode = process.ExitCode,
                    StdOut = (await stdout.ConfigureAwait(false)).Trim(),
                    StdErr = (await stderr.ConfigureAwait(false)).Trim(),
                };
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                // Reap the child before allowing another connect/disconnect operation.
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
                try { await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
                catch (Exception) { /* pipes may close during process termination */ }
                ct.ThrowIfCancellationRequested();
                return new WarpCli.Result { ExitCode = -1, StdErr = "warp-cli timed out" };
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            ct.ThrowIfCancellationRequested();
            return new WarpCli.Result { ExitCode = -1, StdErr = ex.Message };
        }
    }
}
