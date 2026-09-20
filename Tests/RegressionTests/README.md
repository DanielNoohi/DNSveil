# Regression checks

Run from the repository root:

```powershell
dotnet run --project Tests/RegressionTests/RegressionTests.csproj
```

Requires the .NET SDK and Windows Desktop .NET 6 runtime used by the application.
The checks use local TCP listeners only; they do not invoke WARP or change DNS,
proxy, or tunnel settings. The fallback check requires loopback ports 443 and
8443 to be available and fails visibly if another process owns either port.
A nonzero exit code indicates a failure.
