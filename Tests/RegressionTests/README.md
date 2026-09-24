# Regression checks and release packaging

Run from the repository root on Windows with .NET SDK 8 and .NET Desktop 6 installed:

```powershell
./Scripts/Restore-XrayBackends.ps1
dotnet run --project Tests/RegressionTests/RegressionTests.csproj --configuration Release
```

The 69 checks use local TCP/UDP listeners, child-process fixtures, simulated responses, and a temporary offscreen WinForms window. They validate generated configurations with the pinned Xray/sing-box binaries and run Xray only against local forwarding fixtures. They do not register Cloudflare accounts, invoke official WARP, or install system DNS/proxy/TUN routes. Loopback ports 443 and 8443 must be available. A nonzero exit code indicates failure. GitHub runs the suite and builds the portable launcher on main-branch pushes and pull requests.

To build a portable x64 release:

```powershell
./Scripts/Build-Release.ps1
```

Install 7-Zip and restore the real x64 helper binaries in `SecureDNSClient/NecessaryFiles` first. Git contains placeholders, which are sufficient for compilation and the isolated tests but cannot be shipped. The release script rejects placeholders, runs the tests, publishes both projects, checks matching versions, validates the archive and writes SHA256SUMS.txt under `artifacts/bin/v<version>`. It refuses to overwrite an existing output directory. Publishing the resulting archive to GitHub is a separate step.

Regional checks simulate successful and rejected exits, mixed IPv4/IPv6 countries, unavailable families, the attempt cap, and cancellation/deadline cleanup. They do not establish that WARP will provide a different country on a live connection.

Recovery coverage includes distinct WireGuard targets, cleanup before fallback, timeout recovery, cancellation without fallback, failed-cleanup abort, and honest HTTP diagnostics. No live service-access or WireGuard connectivity claim is made.

The advanced-backend tests verify nested routing, separate account keys, protected profile reuse, authenticated loopback listeners, matching UDP responses, executable hashes, actual core configuration acceptance, local TCP/UDP forwarding, and process cleanup. Live TUN routing, ISP unblocking and service access require a separate user trial.
