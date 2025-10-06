# includes\06-DefensiveCountermeasures.ps1
# Defensive Countermeasures � STUBS ONLY (no working commands included)

function Invoke-DefensiveCountermeasures {
    param([hashtable]$Config)

    Write-Host "[Defensive Countermeasures] Start" -ForegroundColor Cyan

    # Windows Firewall � All profiles
    DCM-Firewall-EnableAllProfiles               -Config $Config
    DCM-Firewall-BlockInboundDefault             -Config $Config
    DCM-Firewall-DisableBlockedNotifications     -Config $Config
    DCM-Firewall-DisallowLocalFirewallRules      -Config $Config
    DCM-Firewall-DisallowLocalIPSecRules         -Config $Config
    DCM-Firewall-SetLogFilePath                  -Config $Config
    DCM-Firewall-SetLogMaxKB                     -Config $Config
    DCM-Firewall-EnableLogDropped                -Config $Config
    DCM-Firewall-EnableLogAllowed                -Config $Config

    # Microsoft Defender AV
    DCM-Defender-EnableRealtime                  -Config $Config
    DCM-Defender-ClearExclusionPaths             -Config $Config
    DCM-Defender-ClearExclusionExtensions        -Config $Config
    DCM-Defender-SetSeverityDefaultActions       -Config $Config

    Write-Host "[Defensive Countermeasures] Done" -ForegroundColor Cyan
}

# -----------------------------
# Windows Firewall (NetSecurity)
# -----------------------------

function DCM-Firewall-EnableAllProfiles {
<#
.EXPLANATION
Enable the Windows Firewall for Domain, Private, and Public profiles.

.AI_PROMPT
Return only PowerShell code (no markdown, no comments):

function DCM-Firewall-EnableAllProfiles {
  param([hashtable]$Config)
  Set-NetFirewallProfile -All -Enabled True
  Write-Host "Set Windows Firewall: All Profiles: Firewall state to On"
}
#>
    param([hashtable]$Config)
    # TODO
}

function DCM-Firewall-BlockInboundDefault {
<#
.EXPLANATION
Set default inbound action to Block for all profiles.

.AI_PROMPT
Return only PowerShell code:

function DCM-Firewall-BlockInboundDefault {
  param([hashtable]$Config)
  Set-NetFirewallProfile -All -DefaultInboundAction Block
  Write-Host "Set Windows Firewall: All Profiles: Inbound connections to Block"
}
#>
    param([hashtable]$Config)
    # TODO
}

function DCM-Firewall-DisableBlockedNotifications {
<#
.EXPLANATION
Disable notifications for blocked inbound connections for all profiles.

.AI_PROMPT
Return only PowerShell code:

function DCM-Firewall-DisableBlockedNotifications {
  param([hashtable]$Config)
  Set-NetFirewallProfile -All -NotifyOnListen False
  Write-Host "Set Windows Firewall: All Profiles: Display a notification to No"
}
#>
    param([hashtable]$Config)
    # TODO
}

function DCM-Firewall-DisallowLocalFirewallRules {
<#
.EXPLANATION
Disallow local firewall rules for all profiles.

.AI_PROMPT
Return only PowerShell code:

function DCM-Firewall-DisallowLocalFirewallRules {
  param([hashtable]$Config)
  Set-NetFirewallProfile -All -AllowLocalFirewallRules False
  Write-Host "Set Windows Firewall: All Profiles: Apply local firewall rules to No"
}
#>
    param([hashtable]$Config)
    # TODO
}

function DCM-Firewall-DisallowLocalIPSecRules {
<#
.EXPLANATION
Disallow local IPsec (connection security) rules for all profiles.

.AI_PROMPT
Return only PowerShell code:

function DCM-Firewall-DisallowLocalIPSecRules {
  param([hashtable]$Config)
  Set-NetFirewallProfile -All -AllowLocalIPsecRules False
  Write-Host "Set Windows Firewall: All Profiles: Apply local connection security rules to No"
}
#>
    param([hashtable]$Config)
    # TODO
}

function DCM-Firewall-SetLogFilePath {
<#
.EXPLANATION
Set the firewall log file path for all profiles. Use $Config.FirewallLogPath if present, otherwise
default to '%SystemRoot%\System32\logfiles\firewall\allprofilesfw.log'.

.AI_PROMPT
Return only PowerShell code:

function DCM-Firewall-SetLogFilePath {
  param([hashtable]$Config)
  $path = if ($Config.FirewallLogPath) { $Config.FirewallLogPath } else { "%SystemRoot%\System32\logfiles\firewall\allprofilesfw.log" }
  Set-NetFirewallProfile -All -LogFileName $path
  Write-Host "Set Windows Firewall: All Profiles: Logging file name to '$path'"
}
#>
    param([hashtable]$Config)
    # TODO
}

function DCM-Firewall-SetLogMaxKB {
<#
.EXPLANATION
Set the firewall log size limit (KB) for all profiles. Use $Config.FirewallLogMaxSizeKB if present, otherwise 16384.

.AI_PROMPT
Return only PowerShell code:

function DCM-Firewall-SetLogMaxKB {
  param([hashtable]$Config)
  $size = if ($Config.FirewallLogMaxSizeKB) { [int]$Config.FirewallLogMaxSizeKB } else { 16384 }
  Set-NetFirewallProfile -All -LogMaxSizeKilobytes $size
  Write-Host "Set Windows Firewall: All Profiles: Logging size limit to $size KB"
}
#>
    param([hashtable]$Config)
    # TODO
}

function DCM-Firewall-EnableLogDropped {
<#
.EXPLANATION
Enable logging of dropped packets for all profiles.

.AI_PROMPT
Return only PowerShell code:

function DCM-Firewall-EnableLogDropped {
  param([hashtable]$Config)
  Set-NetFirewallProfile -All -LogBlocked True
  Write-Host "Set Windows Firewall: All Profiles: Logging dropped packets to Yes"
}
#>
    param([hashtable]$Config)
    # TODO
}

function DCM-Firewall-EnableLogAllowed {
<#
.EXPLANATION
Enable logging of successful connections for all profiles.

.AI_PROMPT
Return only PowerShell code:

function DCM-Firewall-EnableLogAllowed {
  param([hashtable]$Config)
  Set-NetFirewallProfile -All -LogAllowed True
  Write-Host "Set Windows Firewall: All Profiles: Logging successful connections to Yes"
}
#>
    param([hashtable]$Config)
    # TODO
}

# -----------------------------
# Microsoft Defender Antivirus
# -----------------------------

function DCM-Defender-EnableRealtime {
<#
.EXPLANATION
Enable Microsoft Defender AV and real-time protection. Ensure policy keys are configured and runtime
real-time monitoring is on.

.AI_PROMPT
Return only PowerShell code:

function DCM-Defender-EnableRealtime {
  param([hashtable]$Config)
  New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Force | Out-Null
  New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Force | Out-Null
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 0 -Force
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableRealTimeMonitoring' -Value 0 -Force
  Set-MpPreference -DisableRealtimeMonitoring $false
  Write-Host "Windows Defender real-time protection enabled"
}
#>
    param([hashtable]$Config)
    # TODO
}

function DCM-Defender-ClearExclusionPaths {
<#
.EXPLANATION
Remove all Defender exclusion paths.

.AI_PROMPT
Return only PowerShell code:

function DCM-Defender-ClearExclusionPaths {
  param([hashtable]$Config)
  (Get-MpPreference).ExclusionPath | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionPath $_ } 
  Write-Host "Windows Defender exclusion path cleared"
}
#>
    param([hashtable]$Config)
    # TODO
}

function DCM-Defender-ClearExclusionExtensions {
<#
.EXPLANATION
Remove all Defender exclusion extensions.

.AI_PROMPT
Return only PowerShell code:

function DCM-Defender-ClearExclusionExtensions {
  param([hashtable]$Config)
  (Get-MpPreference).ExclusionExtension | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionExtension $_ } 2>$null
  Write-Host "Extension exclusion removed from Windows Defender"
}
#>
    param([hashtable]$Config)
    # TODO
}

function DCM-Defender-SetSeverityDefaultActions {
<#
.EXPLANATION
Configure Defender default actions by severity/category: High/Moderate/Low/ZeroDay = 0 (Recommended action),
and numeric categories 1,2,4,5 = 2.

.AI_PROMPT
Return only PowerShell code:

function DCM-Defender-SetSeverityDefaultActions {
  param([hashtable]$Config)
  $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
  New-Item -Path $regPath -Force | Out-Null
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 0 -Force
  Set-ItemProperty -Path $regPath -Name 'High'     -Value 0 -Force
  Set-ItemProperty -Path $regPath -Name 'Moderate' -Value 0 -Force
  Set-ItemProperty -Path $regPath -Name 'Low'      -Value 0 -Force
  Set-ItemProperty -Path $regPath -Name 'ZeroDay'  -Value 0 -Force
  Set-ItemProperty -Path $regPath -Name '1' -Value 2 -Force
  Set-ItemProperty -Path $regPath -Name '2' -Value 2 -Force
  Set-ItemProperty -Path $regPath -Name '4' -Value 2 -Force
  Set-ItemProperty -Path $regPath -Name '5' -Value 2 -Force
  Write-Host "Windows Defender default actions configured"
}
#>
    param([hashtable]$Config)
    # TODO
}
