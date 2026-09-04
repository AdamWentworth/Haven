[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateNotNullOrEmpty()]
    [string] $TaskName = 'HAVEN Agent',

    [switch] $RemoveIdentity
)

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    throw 'The Windows agent uninstaller can run only on Windows.'
}
$principal = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this uninstaller from an elevated PowerShell session.'
}

$task = Get-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $task -and $PSCmdlet.ShouldProcess("scheduled task $TaskName", 'Unregister')) {
    $executable = $task.Actions[0].Execute
    if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskPath '\' -TaskName $TaskName }
    Unregister-ScheduledTask -TaskPath '\' -TaskName $TaskName -Confirm:$false
    $expectedDirectory = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'HAVEN\bin'))
    if ($executable -and [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($executable)) -eq $expectedDirectory -and (Test-Path -LiteralPath $executable -PathType Leaf)) {
        Remove-Item -LiteralPath $executable -Force
    }
}

if ($RemoveIdentity) {
    $identityDirectory = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'HAVEN\agent'))
    $expectedIdentityDirectory = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'HAVEN\agent'))
    if ($identityDirectory -ne $expectedIdentityDirectory) { throw 'Refusing to remove an unexpected identity directory.' }
    if ((Test-Path -LiteralPath $identityDirectory) -and $PSCmdlet.ShouldProcess($identityDirectory, 'Permanently remove the enrolled device identity')) {
        Remove-Item -LiteralPath $identityDirectory -Recurse -Force
    }
}

Write-Host 'The HAVEN scheduled reporter was removed. Its enrolled identity was preserved unless -RemoveIdentity was explicitly confirmed.'
