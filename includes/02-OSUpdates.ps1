# includes\02-OSUpdates.ps1
# OS Updates � STUBS ONLY (no working commands included)

function Invoke-OSUpdates {
    param([hashtable]$Config)

    Write-Host "[OS Updates] Start" -ForegroundColor Cyan

    OSU-Enable-RecommendAndMicrosoftUpdate   -Config $Config
    OSU-Enable-AutomaticUpdates              -Config $Config
    OSU-Restart-WindowsUpdateService         -Config $Config
    OSU-Ensure-WuauservAutomaticAndRunning   -Config $Config
    OSU-Install-PSWindowsUpdateModule        -Config $Config
    OSU-Run-WindowsUpdate                    -Config $Config

    Write-Host "[OS Updates] Done" -ForegroundColor Cyan
}

function OSU-Enable-RecommendAndMicrosoftUpdate {
<#
.EXPLANATION
Enable receiving updates for other Microsoft products and recommended updates.
#>
    param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'IncludeRecommendedUpdates' -Value 1
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'IncludeRecommendedUpdates' -Value 1
  Write-Host "Enabled Microsoft/recommended updates."
}



function OSU-Enable-AutomaticUpdates {
<#
.EXPLANATION
Ensure Windows automatically checks for updates (AUOptions=4, NoAutoUpdate=0).

.AI_PROMPT
#>
    param([hashtable]$Config)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions' -Value 4
Write-Host "Automatic updates enabled (AUOptions=4)."
}


function OSU-Restart-WindowsUpdateService {
<#
.EXPLANATION
Apply policy changes by restarting Windows Update service.
#>
    param([hashtable]$Config)
   

Restart-Service -Name 'wuauserv'
Write-Host "Restarted Windows Update service."
}



function OSU-Ensure-WuauservAutomaticAndRunning {
<#
.EXPLANATION
Ensure the Windows Update service is Automatic and started; set AUOptions (current user key) to 4 as given.
#>
    param([hashtable]$Config)
   
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'AUOptions' -Value 4 -Type DWORD
  Set-Service -Name 'wuauserv' -StartupType 'Automatic'
  Start-Service -Name 'wuauserv'
  Write-Host "Windows Update service set to Automatic and started."
}



function OSU-Install-PSWindowsUpdateModule {
<#
.EXPLANATION
Install NuGet provider and PSWindowsUpdate module; set execution policy (per your snippet) and import the module.
#>
    param([hashtable]$Config)
  Install-PackageProvider -Name NuGet -Force
  Install-Module -Name PSWindowsUpdate -Force
  Set-ExecutionPolicy RemoteSigned -Force
  Import-Module PSWindowsUpdate -Force
  Write-Host "PSWindowsUpdate installed and imported."
}



function OSU-Run-WindowsUpdate {
<#
.EXPLANATION
Trigger installation of available updates using PSWindowsUpdate with force flags as provided.
#>
    param([hashtable]$Config)
    
  Install-WindowsUpdate -ForceDownload -ForceInstall -Confirm:$False
  Write-Host "Windows updates installation initiated."
}


