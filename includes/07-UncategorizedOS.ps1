# includes\07-UncategorizedOS.ps1
# Uncategorized OS � STUBS ONLY (no working commands included)

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
param([hashtable]$Config)
if ($serverSvc -and $serverSvc.Status -ne 'Running') {
    Start-Service -Name LanmanServer
    Set-Service -Name LanmanServer -StartupType Automatic
}
Get-SmbShare | Remove-SmbShare -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "All SMB shares removed."
}




function UOS-Disable-RemoteDesktop {
param([hashtable]$Config)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
Write-Host "Remote Desktop disabled."
}


function UOS-Disable-RemoteAssistance {
param([hashtable]$Config)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
Write-Host "Remote Assistance disabled."
}
function UOS-Set-ExecutionPolicy-Restricted {
param([hashtable]$Config)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Restricted -Force
Write-Host "Execution policy set to Restricted."
}

