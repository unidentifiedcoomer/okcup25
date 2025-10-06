# includes\07-UncategorizedOS.ps1
# Uncategorized OS – STUBS ONLY (no working commands included)

function Invoke-UncategorizedOS {
    param([hashtable]$Config)

    Write-Host "[Uncategorized OS] Start" -ForegroundColor Cyan

    UOS-Disable-FileSharing            -Config $Config
    UOS-Disable-RemoteDesktop          -Config $Config
    UOS-Disable-RemoteAssistance       -Config $Config
    UOS-Set-ExecutionPolicy-Restricted -Config $Config

    Write-Host "[Uncategorized OS] Done" -ForegroundColor Cyan
}

function UOS-Disable-FileSharing {
<#
.EXPLANATION
Disable file sharing by removing all SMB shares (non-interactively). Suppress errors from built-in/admin shares.

.AI_PROMPT
Return only PowerShell code (no markdown, no comments, no extra text):

function UOS-Disable-FileSharing {
  param([hashtable]$Config)
  Get-SmbShare | Remove-SmbShare -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "All SMB shares removed."
}
#>
    param([hashtable]$Config)
    # TODO
}


function UOS-Disable-RemoteDesktop {
<#
.EXPLANATION
Turn off Remote Desktop by setting fDenyTSConnections = 1.

.AI_PROMPT
Return only PowerShell code:

function UOS-Disable-RemoteDesktop {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
  Write-Host "Remote Desktop disabled."
}
#>
    param([hashtable]$Config)
    # TODO
}

function UOS-Disable-RemoteAssistance {
<#
.EXPLANATION
Disable Remote Assistance by setting fAllowToGetHelp = 0.

.AI_PROMPT
Return only PowerShell code:

function UOS-Disable-RemoteAssistance {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
  Write-Host "Remote Assistance disabled."
}
#>
    param([hashtable]$Config)
    # TODO
}

function UOS-Set-ExecutionPolicy-Restricted {
<#
.EXPLANATION
Set PowerShell execution policy to Restricted (simple, blind-change). Your entry script relaunches with -ExecutionPolicy Bypass, so future runs still work unless GPO overrides.

.AI_PROMPT
Return only PowerShell code:

function UOS-Set-ExecutionPolicy-Restricted {
  param([hashtable]$Config)
  Set-ExecutionPolicy Restricted -Force
  Write-Host "Execution policy set to Restricted."
}
#>
    param([hashtable]$Config)
    # TODO
}
