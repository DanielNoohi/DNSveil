# Regression checks and release packaging

Run from the repository root on Windows with .NET SDK 8 and .NET Desktop 6 installed:

```powershell
dotnet run --project Tests/RegressionTests/RegressionTests.csproj --configuration Release
```

The 44 checks use local TCP listeners, child-process fixtures, simulated HTTP responses and an unshown WinForms window. They do not invoke WARP or change DNS, proxy, service or tunnel settings. Loopback ports 443 and 8443 must be available. A nonzero exit code indicates failure. GitHub runs the suite and builds the portable launcher on main-branch pushes and pull requests.

To build a portable x64 release:

```powershell
./Scripts/Build-Release.ps1
```

Install 7-Zip and restore the real x64 helper binaries in `SecureDNSClient/NecessaryFiles` first. Git contains placeholders, which are sufficient for compilation and the isolated tests but cannot be shipped. The release script rejects placeholders, runs the tests, publishes both projects, checks matching versions, validates the archive and writes SHA256SUMS.txt under `artifacts/bin/v<version>`. It refuses to overwrite an existing output directory. Publishing the resulting archive to GitHub is a separate step.

Regional checks simulate successful and rejected exits, mixed IPv4/IPv6 countries, unavailable families, the attempt cap, and cancellation/deadline cleanup. They do not establish that WARP will provide a different country on a live connection.

Recovery coverage includes distinct WireGuard targets, cleanup before fallback, timeout recovery, cancellation without fallback, failed-cleanup abort, and honest HTTP diagnostics. No live service-access or WireGuard connectivity claim is made.
