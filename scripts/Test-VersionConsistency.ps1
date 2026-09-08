[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))

function Read-PackageVersion {
    param([Parameter(Mandatory)][string] $Directory)

    $manifestPath = Join-Path $repositoryRoot "$Directory/package.json"
    $lockPath = Join-Path $repositoryRoot "$Directory/package-lock.json"
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
    $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json -AsHashtable

    if ($lock.version -ne $manifest.version -or $lock.packages[''].version -ne $manifest.version) {
        throw "$Directory package.json and package-lock.json versions do not agree."
    }

    return [string] $manifest.version
}

$buildInfo = Get-Content -LiteralPath (Join-Path $repositoryRoot 'internal/buildinfo/buildinfo.go') -Raw
$match = [regex]::Match($buildInfo, 'const Version = "(?<version>[^"]+)"')
if (-not $match.Success) {
    throw 'Could not read the public release version from internal/buildinfo/buildinfo.go.'
}

$releaseVersion = $match.Groups['version'].Value
if ($releaseVersion -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$') {
    throw "HAVEN version '$releaseVersion' is not a supported semantic version."
}

$versions = [ordered]@{
    Go = $releaseVersion
    Web = Read-PackageVersion -Directory 'web'
    Desktop = Read-PackageVersion -Directory 'desktop'
}

$mismatches = $versions.GetEnumerator() | Where-Object Value -ne $releaseVersion
if ($mismatches) {
    $details = ($mismatches | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
    throw "Release versions do not agree with Go=${releaseVersion}: $details"
}

$desktopSecurity = Get-Content -LiteralPath (Join-Path $repositoryRoot 'desktop/security.cjs') -Raw
if ($desktopSecurity -notmatch 'require\("\./package\.json"\)') {
    throw 'The desktop user-agent version must come from desktop/package.json.'
}

Write-Host "HAVEN release versions agree at $releaseVersion."
