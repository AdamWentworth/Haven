package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

type WindowsCollector struct {
	runner ScriptRunner
}

func NewWindowsCollector(runner ScriptRunner) *WindowsCollector {
	return &WindowsCollector{runner: runner}
}

func (collector *WindowsCollector) Collect(ctx context.Context) model.SecuritySnapshot {
	output, err := collector.runner.Run(ctx, windowsSnapshotScript)
	if err != nil {
		snapshot := unavailableSnapshot(err)
		attachBrowserSecurity(&snapshot, "windows")
		return snapshot
	}

	var snapshot model.SecuritySnapshot
	if err := json.Unmarshal(output, &snapshot); err != nil {
		unavailable := unavailableSnapshot(fmt.Errorf("HAVEN could not understand the Windows collector response: %w", err))
		attachBrowserSecurity(&unavailable, "windows")
		return unavailable
	}

	snapshot.CollectedAt = time.Now().UTC()
	if snapshot.FirewallProfiles == nil {
		snapshot.FirewallProfiles = []model.FirewallProfileStatus{}
	}
	if snapshot.Connections == nil {
		snapshot.Connections = []model.NetworkConnection{}
	}
	if snapshot.Notices == nil {
		snapshot.Notices = []model.CollectorNotice{}
	}
	attachBrowserSecurity(&snapshot, "windows")
	return snapshot
}

func unavailableSnapshot(err error) model.SecuritySnapshot {
	hostName, hostError := os.Hostname()
	if hostError != nil || hostName == "" {
		hostName = "Unknown device"
	}

	return model.SecuritySnapshot{
		CollectedAt: time.Now().UTC(),
		Device: model.DeviceSummary{
			HostName:        hostName,
			OperatingSystem: runtime.GOOS,
			Architecture:    runtime.GOARCH,
		},
		FirewallProfiles: []model.FirewallProfileStatus{},
		Connections:      []model.NetworkConnection{},
		Notices: []model.CollectorNotice{{
			Source:   "Windows collector",
			Severity: "warning",
			Message:  err.Error(),
		}},
	}
}

const windowsSnapshotScript = `
$ErrorActionPreference = 'Stop'
$notices = [System.Collections.Generic.List[object]]::new()
$defender = $null
$firewallProfiles = @()
$connections = @()
$windowsUpdate = $null
$systemEncryption = $null
$platformSecurity = $null
$remoteAccess = $null
$localAccounts = $null
$threats = $null
$browserProtections = @()

try {
    $operatingSystem = Get-CimInstance Win32_OperatingSystem
    $uptime = [int64]((Get-Date) - $operatingSystem.LastBootUpTime).TotalSeconds
    $device = [pscustomobject]@{
        HostName = [System.Environment]::MachineName
        OperatingSystem = "$($operatingSystem.Caption) $($operatingSystem.Version)"
        Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        UptimeSeconds = [Math]::Max(0, $uptime)
    }
}
catch {
    $device = [pscustomobject]@{
        HostName = [System.Environment]::MachineName
        OperatingSystem = 'Windows'
        Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        UptimeSeconds = $null
    }
    $notices.Add([pscustomobject]@{ Source = 'Device'; Severity = 'warning'; Message = "Device details are incomplete. $($_.Exception.Message)" })
}

try {
    $status = Get-MpComputerStatus
    $defender = [pscustomobject]@{
        AntivirusEnabled = $status.AntivirusEnabled
        RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
        BehaviorMonitorEnabled = $status.BehaviorMonitorEnabled
        DownloadProtectionEnabled = $status.IoavProtectionEnabled
        TamperProtected = $status.IsTamperProtected
        TamperProtectionSource = if ($null -eq $status.TamperProtectionSource) { $null } else { [string]$status.TamperProtectionSource }
        SignatureVersion = [string]$status.AntivirusSignatureVersion
        SignatureUpdatedAt = if ($null -eq $status.AntivirusSignatureLastUpdated) { $null } else { $status.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') }
        LastQuickScanAt = if ($null -eq $status.QuickScanEndTime) { $null } else { $status.QuickScanEndTime.ToUniversalTime().ToString('o') }
        LastFullScanAt = if ($null -eq $status.FullScanEndTime) { $null } else { $status.FullScanEndTime.ToUniversalTime().ToString('o') }
    }
}
catch {
    $notices.Add([pscustomobject]@{ Source = 'Microsoft Defender'; Severity = 'warning'; Message = "Defender status is unavailable. $($_.Exception.Message)" })
}

try {
    $firewallProfiles = @(Get-NetFirewallProfile | ForEach-Object {
        [pscustomobject]@{
            Name = [string]$_.Name
            Enabled = [bool]$_.Enabled
            DefaultInboundAction = [string]$_.DefaultInboundAction
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
            LogFileName = [string]$_.LogFileName
        }
    })
}
catch {
    $notices.Add([pscustomobject]@{ Source = 'Windows Firewall'; Severity = 'warning'; Message = "Firewall status is unavailable. $($_.Exception.Message)" })
}

try {
    $latestHotFix = Get-HotFix -ErrorAction Stop |
        Where-Object { $null -ne $_.InstalledOn } |
        Sort-Object -Property InstalledOn -Descending |
        Select-Object -First 1
    $rebootReasons = [System.Collections.Generic.List[string]]::new()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $rebootReasons.Add('Component servicing') }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rebootReasons.Add('Windows Update') }
    $pendingFileReplacement = $null -ne (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
    $windowsUpdate = [pscustomobject]@{
        LastInstalledAt = if ($null -eq $latestHotFix) { $null } else { $latestHotFix.InstalledOn.ToUniversalTime().ToString('o') }
        PendingReboot = [bool]($rebootReasons.Count -gt 0)
        RebootReasons = @($rebootReasons)
        PendingFileReplacement = [bool]$pendingFileReplacement
    }
}
catch {
    $notices.Add([pscustomobject]@{ Source = 'Windows servicing'; Severity = 'information'; Message = "Update freshness is unavailable. $($_.Exception.Message)" })
}

try {
    $bitLockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $systemEncryption = [pscustomobject]@{
        SystemDrive = [string]$env:SystemDrive
        VolumeStatus = [string]$bitLockerVolume.VolumeStatus
        ProtectionStatus = [string]$bitLockerVolume.ProtectionStatus
        EncryptionPercentage = if ($null -eq $bitLockerVolume.EncryptionPercentage) { $null } else { [double]$bitLockerVolume.EncryptionPercentage }
    }
}
catch {
    $notices.Add([pscustomobject]@{ Source = 'System drive encryption'; Severity = 'information'; Message = "BitLocker status is unavailable. $($_.Exception.Message)" })
}

$secureBootEnabled = $null
$tpmPresent = $null
$tpmReady = $null
$tpmVersion = $null
$tpmManufacturer = $null
$tpmSource = $null
try {
    $secureBootState = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction Stop
    $secureBootEnabled = [bool]($secureBootState.UEFISecureBootEnabled -eq 1)
}
catch {
    $notices.Add([pscustomobject]@{ Source = 'Secure Boot'; Severity = 'information'; Message = 'Secure Boot state could not be verified on this system.' })
}
$getTpmError = $null
try {
    $tpm = Get-Tpm -ErrorAction Stop
    if ($null -ne $tpm -and $null -ne $tpm.TpmPresent -and $null -ne $tpm.TpmReady) {
        $tpmPresent = [bool]$tpm.TpmPresent
        $tpmReady = [bool]$tpm.TpmReady
        $tpmSource = 'Get-Tpm'
    }
}
catch {
    $getTpmError = $_.Exception.Message
}
if ($null -eq $tpmPresent -or $null -eq $tpmReady) {
    try {
        $tpmToolPath = Join-Path $env:SystemRoot 'System32\tpmtool.exe'
        $tpmToolOutput = @(& $tpmToolPath getdeviceinformation 2>&1 | ForEach-Object { [string]$_ })
        if ($LASTEXITCODE -ne 0) {
            throw "Windows TPM Tool exited with code $LASTEXITCODE."
        }
        $presentMatch = $tpmToolOutput | Select-String -Pattern '^-TPM Present:\s*(True|False)\s*$' | Select-Object -First 1
        $initializedMatch = $tpmToolOutput | Select-String -Pattern '^-Is Initialized:\s*(True|False)\s*$' | Select-Object -First 1
        $storageMatch = $tpmToolOutput | Select-String -Pattern '^-Ready For Storage:\s*(True|False)\s*$' | Select-Object -First 1
        $versionMatch = $tpmToolOutput | Select-String -Pattern '^-TPM Version:\s*(.+?)\s*$' | Select-Object -First 1
        $manufacturerMatch = $tpmToolOutput | Select-String -Pattern '^-TPM Manufacturer Full Name:\s*(.+?)\s*$' | Select-Object -First 1
        if ($null -eq $presentMatch -or $null -eq $initializedMatch -or $null -eq $storageMatch) {
            throw 'Windows TPM Tool did not return the expected readiness fields.'
        }
        $tpmPresent = [System.Convert]::ToBoolean($presentMatch.Matches[0].Groups[1].Value)
        $initialized = [System.Convert]::ToBoolean($initializedMatch.Matches[0].Groups[1].Value)
        $readyForStorage = [System.Convert]::ToBoolean($storageMatch.Matches[0].Groups[1].Value)
        $tpmReady = [bool]($initialized -and $readyForStorage)
        $tpmVersion = if ($null -eq $versionMatch) { $null } else { $versionMatch.Matches[0].Groups[1].Value.Trim() }
        $tpmManufacturer = if ($null -eq $manufacturerMatch) { $null } else { $manufacturerMatch.Matches[0].Groups[1].Value.Trim() }
        $tpmSource = 'Windows TPM Tool'
    }
    catch {
        $detail = if ([string]::IsNullOrWhiteSpace($getTpmError)) { $_.Exception.Message } else { "$getTpmError; fallback failed: $($_.Exception.Message)" }
        $notices.Add([pscustomobject]@{ Source = 'TPM'; Severity = 'information'; Message = "TPM state could not be verified. $detail" })
    }
}
$platformSecurity = [pscustomobject]@{
    SecureBootEnabled = $secureBootEnabled
    TpmPresent = $tpmPresent
    TpmReady = $tpmReady
    TpmVersion = $tpmVersion
    TpmManufacturer = $tpmManufacturer
    TpmSource = $tpmSource
}

try {
    $terminalServer = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
    $rdpTcp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction Stop
    $remoteAssistance = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -ErrorAction SilentlyContinue
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    $sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue

    $rdpFirewallScope = 'unknown'
    $rdpFirewallRuleCount = $null
    try {
        $firewallRulePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
        $firewallRuleProperties = (Get-ItemProperty -Path $firewallRulePath -ErrorAction Stop).PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' }
        $rdpAllowRules = [System.Collections.Generic.List[string]]::new()
        foreach ($property in $firewallRuleProperties) {
            $ruleText = [string]$property.Value
            if ($ruleText -notmatch '\|Action=Allow\|' -or $ruleText -notmatch '\|Active=TRUE\|' -or $ruleText -notmatch '\|Dir=In\|') {
                continue
            }
            $explicitRdpPort = $ruleText -match '\|LPort=3389(?:\||$)'
			$appIndependentAnyPort = $ruleText -notmatch '\|LPort=' -and $ruleText -notmatch '\|App=' -and $ruleText -notmatch '\|AppPkgId=' -and $ruleText -notmatch '\|Svc=' -and ($ruleText -notmatch '\|Protocol=' -or $ruleText -match '\|Protocol=(?:6|17)(?:\||$)')
            if ($explicitRdpPort -or $appIndependentAnyPort) {
                $rdpAllowRules.Add($ruleText)
            }
        }
        $rdpFirewallRuleCount = [int]$rdpAllowRules.Count
        if ($rdpAllowRules.Count -eq 0) {
            $rdpFirewallScope = 'blocked'
        }
        else {
            $hasUnrestrictedRule = $false
            foreach ($ruleText in $rdpAllowRules) {
                $remoteRestricted = $ruleText -match '\|RA4=[^|]+' -or $ruleText -match '\|RA6=[^|]+'
                $interfaceRestricted = $ruleText -match '\|IF=[^|]+' -or $ruleText -match '\|IFType=[^|]+'
                if (-not $remoteRestricted -and -not $interfaceRestricted) {
                    $hasUnrestrictedRule = $true
                }
            }
            $rdpFirewallScope = if ($hasUnrestrictedRule) { 'unrestricted' } else { 'restricted' }
        }
    }
    catch {
        $notices.Add([pscustomobject]@{ Source = 'Remote Desktop firewall scope'; Severity = 'information'; Message = "RDP firewall scope could not be verified. $($_.Exception.Message)" })
    }

    $remoteAccess = [pscustomobject]@{
        RemoteDesktopEnabled = [bool]($terminalServer.fDenyTSConnections -eq 0)
        NetworkLevelAuthRequired = [bool]($rdpTcp.UserAuthentication -eq 1)
        RdpFirewallScope = $rdpFirewallScope
        RdpFirewallRuleCount = $rdpFirewallRuleCount
        RemoteAssistanceEnabled = [bool]($null -ne $remoteAssistance -and $remoteAssistance.fAllowToGetHelp -eq 1)
        SMB1Enabled = [bool]$smb.EnableSMB1Protocol
        OpenSshServerRunning = [bool]($null -ne $sshd -and $sshd.Status -eq 'Running')
    }
}
catch {
    $notices.Add([pscustomobject]@{ Source = 'Remote access'; Severity = 'information'; Message = "Remote-access settings are unavailable. $($_.Exception.Message)" })
}

try {
    $administratorMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    $administratorCount = $administratorMembers.Count
    $enabledAdministratorCount = 0
    $enabledStateComplete = $true
    foreach ($administratorMember in $administratorMembers) {
        if ([string]$administratorMember.ObjectClass -ne 'User') {
            $enabledStateComplete = $false
            continue
        }
        $accountName = ([string]$administratorMember.Name -split '\\')[-1]
        $localAdministrator = Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue
        if ($null -eq $localAdministrator) {
            $enabledStateComplete = $false
            continue
        }
        if ([bool]$localAdministrator.Enabled) {
            $enabledAdministratorCount++
        }
    }
    $localAccounts = [pscustomobject]@{
        AdministratorCount = [int]$administratorCount
        EnabledAdministratorCount = if ($enabledStateComplete) { [int]$enabledAdministratorCount } else { $null }
    }
}
catch {
    $notices.Add([pscustomobject]@{ Source = 'Local administrators'; Severity = 'information'; Message = 'Local administrator count is unavailable. Account names are never collected.' })
}

try {
    $activeThreats = @(Get-MpThreat -ErrorAction Stop | Where-Object { $_.IsActive })
    $recentDetections = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $null -ne $_.InitialDetectionTime -and $_.InitialDetectionTime -ge (Get-Date).AddDays(-30) })
    $lastDetection = $recentDetections | Sort-Object -Property InitialDetectionTime -Descending | Select-Object -First 1
    $threats = [pscustomobject]@{
        ActiveThreatCount = [int]$activeThreats.Count
        RecentDetectionCount = [int]$recentDetections.Count
        LastDetectedAt = if ($null -eq $lastDetection) { $null } else { $lastDetection.InitialDetectionTime.ToUniversalTime().ToString('o') }
    }
}
catch {
    $notices.Add([pscustomobject]@{ Source = 'Defender detections'; Severity = 'information'; Message = 'Defender threat counts are unavailable. Threat names and resource paths are never collected.' })
}

try {
    $preferences = Get-MpPreference -ErrorAction Stop
    $puaState = switch ([int]$preferences.PUAProtection) {
        1 { 'enabled' }
        2 { 'audit' }
        0 { 'disabled' }
        default { 'unknown' }
    }
    $networkProtectionState = switch ([int]$preferences.EnableNetworkProtection) {
        1 { 'enabled' }
        2 { 'audit' }
        0 { 'disabled' }
        default { 'unknown' }
    }
    $browserProtections += [pscustomobject]@{ Id = 'defender-pua'; Name = 'Potentially unwanted app protection'; State = $puaState; Source = 'Microsoft Defender preferences' }
    $browserProtections += [pscustomobject]@{ Id = 'defender-network'; Name = 'Microsoft Defender Network Protection'; State = $networkProtectionState; Source = 'Microsoft Defender preferences' }
}
catch {
    $browserProtections += [pscustomobject]@{ Id = 'defender-pua'; Name = 'Potentially unwanted app protection'; State = 'unknown'; Source = 'Microsoft Defender preferences' }
    $browserProtections += [pscustomobject]@{ Id = 'defender-network'; Name = 'Microsoft Defender Network Protection'; State = 'unknown'; Source = 'Microsoft Defender preferences' }
    $notices.Add([pscustomobject]@{ Source = 'Web protection'; Severity = 'information'; Message = 'Microsoft Defender web-protection preferences could not be verified.' })
}

$smartScreenState = 'unknown'
$smartScreenSource = 'Windows shell configuration'
try {
    $policyValue = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableSmartScreen -ErrorAction Stop
    $smartScreenState = if ([int]$policyValue -eq 1) { 'enabled' } elseif ([int]$policyValue -eq 0) { 'disabled' } else { 'unknown' }
    $smartScreenSource = 'Windows policy'
}
catch {
    try {
        $shellValue = [string](Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -ErrorAction Stop)
        $smartScreenState = if ($shellValue -eq 'Off') { 'disabled' } elseif ([string]::IsNullOrWhiteSpace($shellValue)) { 'unknown' } else { 'enabled' }
    }
    catch {}
}
$browserProtections += [pscustomobject]@{ Id = 'windows-smartscreen'; Name = 'Microsoft Defender SmartScreen'; State = $smartScreenState; Source = $smartScreenSource }

try {
    $processNames = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $processNames[[int]$_.Id] = $_.ProcessName }
    $connections = @(Get-NetTCPConnection -State Established, Listen |
        Sort-Object -Property State, OwningProcess, RemoteAddress, RemotePort |
        Select-Object -First 250 |
        ForEach-Object {
            $owner = [int]$_.OwningProcess
            [pscustomobject]@{
                Protocol = 'TCP'
                LocalAddress = [string]$_.LocalAddress
                LocalPort = [int]$_.LocalPort
                RemoteAddress = [string]$_.RemoteAddress
                RemotePort = [int]$_.RemotePort
                State = [string]$_.State
                ProcessId = $owner
                ProcessName = if ($processNames.ContainsKey($owner)) { [string]$processNames[$owner] } elseif ($owner -eq 0) { 'System' } else { 'Unknown' }
            }
        })
}
catch {
    $notices.Add([pscustomobject]@{ Source = 'Network connections'; Severity = 'warning'; Message = "Connection data is unavailable. $($_.Exception.Message)" })
}

[pscustomobject]@{
    Device = $device
    BrowserSecurity = [pscustomobject]@{ Coverage = 'unavailable'; Browsers = @(); Protections = @($browserProtections) }
    Defender = $defender
    WindowsBaseline = [pscustomobject]@{
        Update = $windowsUpdate
        SystemEncryption = $systemEncryption
        PlatformSecurity = $platformSecurity
        RemoteAccess = $remoteAccess
        LocalAccounts = $localAccounts
        Threats = $threats
    }
    FirewallProfiles = $firewallProfiles
    Connections = $connections
    Notices = @($notices)
} | ConvertTo-Json -Depth 8 -Compress
`
