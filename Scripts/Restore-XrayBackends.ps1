[CmdletBinding()]
param([switch]$IncludeSources)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$cache = Join-Path $root 'artifacts/bin/backend-tools'
$destination = Join-Path $root 'artifacts/bin/Backends'
New-Item -ItemType Directory -Path $cache,$destination -Force | Out-Null
$packages = @(
    @{ File='xray.zip'; Url='https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip'; Hash='d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad'; Entries=@{'xray.exe'='xray.exe';'wintun.dll'='wintun.dll';'LICENSE'='LICENSE-Xray.txt';'LICENSE-wintun.txt'='LICENSE-Wintun.txt'} },
    @{ File='sing-box.zip'; Url='https://github.com/SagerNet/sing-box/releases/download/v1.14.1/sing-box-1.14.1-windows-amd64.zip'; Hash='5197f16d492d93202dc623622149a6ed040f8eca263128f91d603f2b901baa89'; Entries=@{'sing-box-1.14.1-windows-amd64/sing-box.exe'='sing-box.exe';'sing-box-1.14.1-windows-amd64/LICENSE'='LICENSE-sing-box.txt'} }
)
foreach ($package in $packages) {
    $archivePath = Join-Path $cache $package.File
    if (-not (Test-Path -LiteralPath $archivePath)) { Invoke-WebRequest -Uri $package.Url -OutFile $archivePath }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant() -ne $package.Hash) { throw "Checksum mismatch: $archivePath" }
    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        foreach ($entryName in $package.Entries.Keys) {
            $entry = $archive.GetEntry($entryName)
            if ($null -eq $entry) { throw "Missing archive member: $entryName" }
            # Extract only these explicitly named members to fixed filenames.
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $destination $package.Entries[$entryName]), $true)
        }
    } finally { $archive.Dispose() }
}
Copy-Item -LiteralPath (Join-Path $root 'THIRD_PARTY_BACKENDS.md') -Destination $destination
Write-Output "Verified backends restored to $destination"

if ($IncludeSources) {
    $sources = @(
        @{File='Xray-core-v26.3.27-source.tar.gz';Url='https://github.com/XTLS/Xray-core/archive/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0.tar.gz';Hash='14fa566ee0a801d3d51144c67018b449f5dcf462ddfacadd032da069787e61f9'},
        @{File='sing-box-v1.14.1-source.tar.gz';Url='https://github.com/SagerNet/sing-box/archive/1ac1a339cb1223e9c70eae14c44411c75033c02d.tar.gz';Hash='8420c7723828a8d9d062c3fafee28c7b7e0d20a4c904fa7ff283f6e884edd537'}
    )
    foreach ($source in $sources) {
        $path = Join-Path $cache $source.File
        if (-not (Test-Path -LiteralPath $path)) { Invoke-WebRequest -Uri $source.Url -OutFile $path }
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() -ne $source.Hash) { throw "Source checksum mismatch: $path" }
    }
}
