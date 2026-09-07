[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("haven-public-check-" + [guid]::NewGuid().ToString('N'))

function Invoke-TestGuard {
    param([Parameter(Mandatory)][string] $Root)

    Push-Location -LiteralPath $Root
    try {
        $output = & pwsh -NoLogo -NoProfile -File .\scripts\Test-PublicRepository.ps1 -Staged 2>&1
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join [Environment]::NewLine) }
    }
    finally {
        Pop-Location
    }
}

try {
    New-Item -ItemType Directory -Path (Join-Path $temporaryRoot 'scripts'), (Join-Path $temporaryRoot '.githooks') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'scripts\Test-PublicRepository.ps1') -Destination (Join-Path $temporaryRoot 'scripts\Test-PublicRepository.ps1')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot '.githooks\pre-commit') -Destination (Join-Path $temporaryRoot '.githooks\pre-commit')

    & git -C $temporaryRoot init --quiet --initial-branch main
    & git -C $temporaryRoot add .githooks/pre-commit scripts/Test-PublicRepository.ps1
    & git -C $temporaryRoot update-index --chmod=+x .githooks/pre-commit

    $environmentTemplate = Join-Path $temporaryRoot '.env.example'
    $syntheticCredential = ('api' + '_key=' + ('x' * 24))
    Set-Content -LiteralPath $environmentTemplate -Value $syntheticCredential -NoNewline
    & git -C $temporaryRoot add .env.example
    Set-Content -LiteralPath $environmentTemplate -Value 'SAFE_EXAMPLE=value' -NoNewline

    $result = Invoke-TestGuard -Root $temporaryRoot
    if ($result.ExitCode -eq 0 -or $result.Output -notmatch 'credential-like assignment') {
        throw 'Staged mode did not inspect the staged environment-template blob independently of the working tree.'
    }

    & git -C $temporaryRoot add .env.example
    $result = Invoke-TestGuard -Root $temporaryRoot
    if ($result.ExitCode -ne 0) {
        throw "A safe staged tree did not pass the publication guard: $($result.Output)"
    }

    $privateMarker = 'local-machine-marker'
    Set-Content -LiteralPath (Join-Path $temporaryRoot '.git\info\haven-private-identifiers') -Value $privateMarker -NoNewline
    Set-Content -LiteralPath $environmentTemplate -Value "DEVICE_LABEL=$privateMarker" -NoNewline
    & git -C $temporaryRoot add .env.example
    $result = Invoke-TestGuard -Root $temporaryRoot
    if ($result.ExitCode -eq 0 -or $result.Output -notmatch 'owner-defined') {
        throw "The local-only private-identifier denylist was not enforced (exit $($result.ExitCode)): $($result.Output)"
    }

    Write-Host 'Public-repository guard regression tests passed.'
}
finally {
    $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
    $resolvedSystemTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if ($resolvedTemporaryRoot.StartsWith($resolvedSystemTemp, [System.StringComparison]::OrdinalIgnoreCase) -and
        [System.IO.Path]::GetFileName($resolvedTemporaryRoot).StartsWith('haven-public-check-', [System.StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
