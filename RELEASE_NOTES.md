# DNSveil v3.7.0 — connection reliability overhaul

## Improvements

- Move the WARP connection engine off the window thread so long CLI commands do not freeze controls.
- Add cancellable CLI execution with safe argument handling, concurrent output draining, process-tree termination and bounded cleanup.
- Make Cancel control startup checks, refresh, connect and automatic recovery. Prevent overlapping operations and discard recovery work from cancelled health watchers.
- Keep the window alive while active cancellation cleanup completes; avoid disposing cancellation state while it is still in use.
- Make service readiness waits and fallback country checks cancellable. Restore temporary IPv6 changes if handshake preparation is cancelled.
- Give public-IP lookups one overall deadline across fallback services. Reject malformed IP addresses and keep IP-only results distinct from verified WARP connectivity.
- Add Windows GitHub build/regression checks and a repeatable release script that rejects placeholder helper binaries and verifies archive integrity and SHA-256 checksums.

## Validation

19 isolated regression checks cover endpoint limits and fallback ports, process output and arguments, timeout/cancellation cleanup, public-IP responses and deadlines, operation controls, stale recovery and form closure. Tests use local child processes, loopback listeners and simulated HTTP responses; they do not change DNS, proxy, service or tunnel settings.

Live WARP connectivity and a full interactive UI session have not been verified. Existing .NET 6 / dependency compatibility warnings remain. This release does not claim increased throughput or new censorship-bypass success rates.

## Download

Download `SecureDNSClientPortable_v3.7.0_x64.7z`, extract it, and run `SecureDNSClientPortable.exe`. Windows x64, .NET Desktop 6 and ASP.NET Core 6 runtimes are required. DPI / WinDivert functionality requires administrator privileges. Verify the download using `SHA256SUMS.txt`.
