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
Installs the NuGet provider and PSWindowsUpdate module safely, with TLS support and error handling.
#>
    param([hashtable]$Config)

    Write-Host "[OS Updates] Installing PowerShell Update Module..." -ForegroundColor Cyan

    # Ensure TLS 1.2 support
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Ensure NuGet provider is available
    if (-not (Get-PackageProvider -ListAvailable | Where-Object Name -eq 'NuGet')) {
        Write-Host "Installing NuGet provider..."
        try {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to install NuGet provider. Check internet connection or install manually."
            return
        }
    } else {
        Write-Host "NuGet provider already installed."
    }

    # Install PSWindowsUpdate
    try {
        Install-Module -Name PSWindowsUpdate -Force -ErrorAction Stop
    } catch {
        Write-Warning "Failed to install PSWindowsUpdate. Check your network or repository settings."
        return
    }

    # Import and set execution policy
    Set-ExecutionPolicy RemoteSigned -Force
    Import-Module PSWindowsUpdate -Force

    Write-Host "PSWindowsUpdate successfully installed and imported." -ForegroundColor Green
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


