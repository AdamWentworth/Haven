[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string] $TaskName = 'HAVEN Agent'
)

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    throw 'Windows agent status is available only on Windows.'
}

$task = Get-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -eq $task) {
    [pscustomobject]@{ installed = $false; taskName = $TaskName }
    return
}

$taskInfo = Get-ScheduledTaskInfo -TaskPath '\' -TaskName $TaskName
$executable = $task.Actions[0].Execute
$hash = if (Test-Path -LiteralPath $executable -PathType Leaf) {
    (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
} else { $null }

[pscustomobject]@{
    installed = $true
    taskName = $TaskName
    state = [string]$task.State
    executable = $executable
    executablePresent = Test-Path -LiteralPath $executable -PathType Leaf
    sha256 = $hash
    arguments = $task.Actions[0].Arguments
    runLevel = [string]$task.Principal.RunLevel
    lastRunTime = $taskInfo.LastRunTime
    lastTaskResult = $taskInfo.LastTaskResult
    nextRunTime = $taskInfo.NextRunTime
}
