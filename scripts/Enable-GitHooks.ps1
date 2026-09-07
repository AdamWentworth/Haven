[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (& git rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repositoryRoot)) {
    throw 'Run this command from inside a HAVEN Git checkout.'
}

$expectedRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$actualRoot = [System.IO.Path]::GetFullPath($repositoryRoot)
if ($actualRoot -ne $expectedRoot) {
    throw 'This script must be run from the HAVEN checkout that contains it.'
}

& git -C $repositoryRoot config --local core.hooksPath .githooks
if ($LASTEXITCODE -ne 0) {
    throw 'Git did not accept the local hooks-path configuration.'
}

$configuredPath = (& git -C $repositoryRoot config --local --get core.hooksPath).Trim()
if ($LASTEXITCODE -ne 0 -or $configuredPath -ne '.githooks') {
    throw 'The HAVEN hooks path could not be verified.'
}

Write-Host "Enabled HAVEN's versioned Git hooks for this clone."
Write-Host 'The pre-commit hook checks staged content; GitHub Actions repeats the full repository check.'
Write-Host 'Optional: list private hostnames or project names, one per line, in .git/info/haven-private-identifiers.'
