[CmdletBinding()]
param(
    [string] $OutputDirectory = (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts') 'agents'),
    [string] $Revision
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
$resolvedRepository = [System.IO.Path]::GetFullPath($repositoryRoot)
if ($resolvedOutput -eq $resolvedRepository) {
    throw 'Agent artifacts cannot be written over the repository root.'
}
if (-not $Revision) {
    $Revision = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'The Git revision could not be determined.' }
}
if ($Revision -notmatch '^[0-9a-f]{40}$') {
    throw 'A full Git revision is required for immutable agent artifacts.'
}

New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
$versionSource = Get-Content -LiteralPath (Join-Path $repositoryRoot 'internal/buildinfo/buildinfo.go') -Raw
$versionMatch = [regex]::Match($versionSource, 'const Version = "([^"]+)"')
if (-not $versionMatch.Success) { throw 'The HAVEN release version could not be determined.' }
$version = $versionMatch.Groups[1].Value
$targets = @(
    @{ Name = 'haven-agent-windows-amd64.exe'; OS = 'windows'; Architecture = 'amd64'; GUI = $false; Installation = 'interactive' },
    @{ Name = 'haven-agent-background-windows-amd64.exe'; OS = 'windows'; Architecture = 'amd64'; GUI = $true; Installation = 'windows-task' },
    @{ Name = 'haven-agent-linux-amd64'; OS = 'linux'; Architecture = 'amd64'; GUI = $false; Installation = 'interactive' },
    @{ Name = 'haven-agent-linux-arm64'; OS = 'linux'; Architecture = 'arm64'; GUI = $false; Installation = 'interactive' }
)
$originalGOOS = $env:GOOS
$originalGOARCH = $env:GOARCH
$manifest = @()
try {
    foreach ($target in $targets) {
        $env:GOOS = $target.OS
        $env:GOARCH = $target.Architecture
        $output = Join-Path $resolvedOutput $target.Name
        $linkerFlags = "-s -w -X github.com/AdamWentworth/haven/internal/buildinfo.Revision=$Revision"
        if ($target.GUI) { $linkerFlags = "-H=windowsgui $linkerFlags -X github.com/AdamWentworth/haven/internal/buildinfo.AgentInstallation=windows-task" }
        Push-Location -LiteralPath $repositoryRoot
        try {
            & go build -trimpath -ldflags $linkerFlags -o $output ./cmd/haven-agent
            if ($LASTEXITCODE -ne 0) { throw "Agent build failed for $($target.Name)." }
        } finally { Pop-Location }
        $hash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
        $manifest += [ordered]@{ file = $target.Name; os = $target.OS; architecture = $target.Architecture; background = $target.GUI; installation = $target.Installation; version = $version; revision = $Revision; sha256 = $hash }
    }
} finally {
    $env:GOOS = $originalGOOS
    $env:GOARCH = $originalGOARCH
}

$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $resolvedOutput 'manifest.json') -Encoding utf8NoBOM
$manifest | Sort-Object file | ForEach-Object { "$($_.sha256)  $($_.file)" } | Set-Content -LiteralPath (Join-Path $resolvedOutput 'SHA256SUMS') -Encoding ascii
Write-Host "Built $($manifest.Count) immutable agent artifacts for $Revision in $resolvedOutput."
