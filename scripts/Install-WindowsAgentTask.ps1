[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string] $TaskName = 'HAVEN Agent',

    [ValidateRange(1, 1440)]
    [int] $IntervalMinutes = 15,

    [string] $InstallDirectory = (Join-Path $env:LOCALAPPDATA 'HAVEN\bin'),

    [string] $AgentBinary,

    [string] $ExpectedSHA256,

    [switch] $DoNotStart
)

$ErrorActionPreference = 'Stop'
$taskPath = '\'

if ($env:OS -ne 'Windows_NT') {
    throw 'The Windows agent task can only be installed on Windows.'
}

$windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$windowsPrincipal = [System.Security.Principal.WindowsPrincipal]::new($windowsIdentity)
if (-not $windowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell session. HAVEN needs an elevated reporting task to read protected Windows posture signals.'
}
$identity = $windowsIdentity.Name

$repositoryRoot = Split-Path -Parent $PSScriptRoot
if (-not $AgentBinary -and -not (Test-Path -LiteralPath (Join-Path $repositoryRoot 'go.mod') -PathType Leaf)) {
    throw 'Run the installer from a complete HAVEN source checkout.'
}

function Get-PortableExecutableSubsystem {
    param([Parameter(Mandatory)][string] $Path)

    $stream = [System.IO.File]::OpenRead($Path)
    $reader = [System.IO.BinaryReader]::new($stream)
    try {
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        $stream.Position = $peOffset + 24 + 68
        return $reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

$resolvedInstallDirectory = [System.IO.Path]::GetFullPath($InstallDirectory)
$backgroundAgentPath = Join-Path $resolvedInstallDirectory 'haven-agent-background.exe'
$temporaryAgentPath = Join-Path $resolvedInstallDirectory "haven-agent-background.$PID.exe"

New-Item -ItemType Directory -Path $resolvedInstallDirectory -Force | Out-Null

if ($AgentBinary) {
    if ($ExpectedSHA256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw '-ExpectedSHA256 is required when installing a prebuilt agent.'
    }
    $sourceBinary = [System.IO.Path]::GetFullPath($AgentBinary)
    if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) {
        throw 'The prebuilt agent binary was not found.'
    }
    $sourceHash = (Get-FileHash -LiteralPath $sourceBinary -Algorithm SHA256).Hash
    if ($sourceHash -ne $ExpectedSHA256) {
        throw 'The prebuilt agent SHA-256 does not match the expected manifest value.'
    }
    Copy-Item -LiteralPath $sourceBinary -Destination $temporaryAgentPath -Force
}
else {
    $revision = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') {
        throw 'The HAVEN source revision could not be determined. Refusing to install an unstamped background reporter.'
    }
    $linkerFlags = "-H=windowsgui -s -w -X github.com/AdamWentworth/haven/internal/buildinfo.Revision=$revision -X github.com/AdamWentworth/haven/internal/buildinfo.AgentInstallation=windows-task"
    Push-Location -LiteralPath $repositoryRoot
    try {
        & go build -trimpath -ldflags $linkerFlags -o $temporaryAgentPath .\cmd\haven-agent
        if ($LASTEXITCODE -ne 0) {
            throw "The background HAVEN agent build failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

try {
    if ((Get-PortableExecutableSubsystem -Path $temporaryAgentPath) -ne 2) {
        throw 'Refusing to schedule an agent that is not a Windows GUI-subsystem executable.'
    }

    $existingTask = Get-ScheduledTask -TaskPath $taskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $existingTask -and $existingTask.State -eq 'Running') {
        Stop-ScheduledTask -TaskPath $taskPath -TaskName $TaskName
        $deadline = (Get-Date).AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 200
            $existingTask = Get-ScheduledTask -TaskPath $taskPath -TaskName $TaskName
        } while ($existingTask.State -eq 'Running' -and (Get-Date) -lt $deadline)
        if ($existingTask.State -eq 'Running') {
            throw 'The existing HAVEN agent task did not stop in time; its executable was not replaced.'
        }
    }

    Move-Item -LiteralPath $temporaryAgentPath -Destination $backgroundAgentPath -Force

    $action = New-ScheduledTaskAction -Execute $backgroundAgentPath -Argument 'report --installation windows-task' -WorkingDirectory $resolvedInstallDirectory
    $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Highest
    if ($null -ne $existingTask) {
        Set-ScheduledTask -TaskPath $taskPath -TaskName $TaskName -Action $action -Principal $principal | Out-Null
    }
    else {
        $triggers = @(
            New-ScheduledTaskTrigger -AtLogOn -User $identity
            New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration (New-TimeSpan -Days 3650)
        )
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
        Register-ScheduledTask -TaskPath $taskPath -TaskName $TaskName -Description 'Reports read-only Windows security posture to the private HAVEN hub without displaying a window.' -Action $action -Trigger $triggers -Principal $principal -Settings $settings | Out-Null
    }

    $installedTask = Get-ScheduledTask -TaskPath $taskPath -TaskName $TaskName
    if ($installedTask.Principal.RunLevel -ne 'Highest') {
        throw "Scheduled task '$TaskName' was installed without the required elevated run level."
    }

    if (-not $DoNotStart) {
        Start-ScheduledTask -TaskPath $taskPath -TaskName $TaskName
    }

    $binaryHash = (Get-FileHash -LiteralPath $backgroundAgentPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "Installed the verified console-free HAVEN reporter as scheduled task '$TaskName'."
    Write-Host "SHA-256: $binaryHash"
}
finally {
    if (Test-Path -LiteralPath $temporaryAgentPath) {
        Remove-Item -LiteralPath $temporaryAgentPath -Force
    }
}
