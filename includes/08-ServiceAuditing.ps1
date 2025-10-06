# includes\08-ServiceAuditing.ps1
# Service Auditing – STUBS ONLY (no working commands included)

function Invoke-ServiceAuditing {
    param([hashtable]$Config)

    Write-Host "[Service Auditing] Start" -ForegroundColor Cyan

    SA-Ensure-WindowsDefenderRunning -Config $Config
    SA-Ensure-EventLogRunning        -Config $Config
    SA-Disable-ServicesList          -Config $Config


    Write-Host "[Service Auditing] Done" -ForegroundColor Cyan
}

function SA-Ensure-WindowsDefenderRunning {
<#
.EXPLANATION
Ensure Windows Defender service (WinDefend) is started and set to Automatic.

.AI_PROMPT
Return only PowerShell code (no markdown, no comments, no extra text):

function SA-Ensure-WindowsDefenderRunning {
  param([hashtable]$Config)
  Start-Service -Name "WinDefend" ; Set-Service -Name "WinDefend" -StartupType Automatic
  Write-Host "Windows Defender service set to Automatic and started."
}
#>
    param([hashtable]$Config)
    # TODO
}

function SA-Ensure-EventLogRunning {
<#
.EXPLANATION
Ensure Windows Event Log service is started (suppress start errors if already running) and set to Automatic.

.AI_PROMPT
Return only PowerShell code (no markdown, no comments, no extra text):

function SA-Ensure-EventLogRunning {
  param([hashtable]$Config)
  Start-Service -Name EventLog -ErrorAction SilentlyContinue; Set-Service -Name EventLog -StartupType Automatic
  Write-Host "Windows Event Log service set to Automatic and started."
}
#>
    param([hashtable]$Config)
    # TODO
}

function SA-Disable-ServicesList {
<#
.EXPLANATION
Loop through $Config.ServicesToDisable, stop each service, then set StartupType to Disabled.
Use try/catch per service. Suppress noise if a stop fails but continue the loop.

.AI_PROMPT
Return only PowerShell code (no markdown, no comments, no extra text):

function SA-Disable-ServicesList {
  param([hashtable]$Config)
  $services = $Config.ServicesToDisable
  if (-not $services -or -not $services.Count) { Write-Host "No services configured to disable."; return }
  foreach ($service in $services) {
    try {
      Stop-Service -Name $service -Force -ErrorAction Stop
      Write-Host "Stopped service: $service"
    } catch {
      Write-Warning "Failed to stop service: $service. Error: $_"
    }
    try {
      Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
      Write-Host "Set service to Disabled: $service"
    } catch {
      Write-Warning "Failed to disable service: $service. Error: $_"
    }
  }
}
#>
    param([hashtable]$Config)
    # TODO
}
