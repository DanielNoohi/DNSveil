[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
Push-Location $repoRoot
try {
    [xml]$project = Get-Content -LiteralPath 'SecureDNSClient/SecureDNSClient.csproj'
    $version = [regex]::Match(($project.Project.PropertyGroup.Version -join ''), '\d+\.\d+\.\d+').Value
    if (-not $version) { throw 'Cannot read application version.' }
    $releaseRoot = Join-Path $repoRoot "artifacts/bin/v$version"
    if (Test-Path -LiteralPath $releaseRoot) { throw "Output already exists: $releaseRoot. Use a fresh version or move the old output before packaging." }
    # Source control has placeholder helpers. Never ship a package containing them.
    foreach ($name in @('SDCAgnosticServer-X64.exe', 'SDCLookup-X64.exe', 'dnslookup-X64.exe', 'goodbyedpi.exe', 'WinDivert.dll', 'WinDivert32.sys', 'WinDivert64.sys')) {
        $path = Join-Path $repoRoot "SecureDNSClient/NecessaryFiles/$name"
        $bytes = [IO.File]::ReadAllBytes($path)
        if ($bytes.Length -lt 1024 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { throw "Restore the real release helper before packaging: $name" }
    }
    $sevenZip = Join-Path $env:ProgramFiles '7-Zip/7z.exe'
    if (-not (Test-Path -LiteralPath $sevenZip)) { throw 'Install 7-Zip before packaging.' }
    dotnet run --project Tests/RegressionTests/RegressionTests.csproj --configuration Release
    if ($LASTEXITCODE -ne 0) { throw 'Regression checks failed.' }
    $portableRoot = Join-Path $releaseRoot 'SecureDNSClientPortable'
    dotnet publish SecureDNSClient/SecureDNSClient.csproj -p:PublishProfile=X64 "-p:PublishDir=$portableRoot/SecureDNSClient/"
    if ($LASTEXITCODE -ne 0) { throw 'Application publish failed.' }
    dotnet publish SecureDNSClientPortable/SecureDNSClientPortable.csproj -p:PublishProfile=X64 "-p:PublishDir=$portableRoot/"
    if ($LASTEXITCODE -ne 0) { throw 'Launcher publish failed.' }
    foreach ($binary in @('SecureDNSClient/SecureDNSClient.dll', 'SecureDNSClientPortable.exe')) {
        $actual = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $portableRoot $binary)).ProductVersion
        if ($actual.Split('+')[0] -ne $version) { throw "Version mismatch: $binary has $actual instead of $version" }
    }
    Copy-Item -LiteralPath README.md, RELEASE_NOTES.md, LICENSE, CheckDotNet.bat -Destination $portableRoot
    $archiveName = "SecureDNSClientPortable_v${version}_x64.7z"
    $archivePath = Join-Path $releaseRoot $archiveName
    & $sevenZip a -t7z -mx=5 $archivePath $portableRoot
    if ($LASTEXITCODE -ne 0) { throw 'Archive creation failed.' }
    & $sevenZip t $archivePath
    if ($LASTEXITCODE -ne 0) { throw 'Archive integrity check failed.' }
    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $archiveName" | Set-Content -LiteralPath (Join-Path $releaseRoot 'SHA256SUMS.txt') -Encoding ascii
    Write-Output "Verified release package: $archivePath"
} finally { Pop-Location }
