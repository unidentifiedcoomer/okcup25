# includes\08-ServiceAuditing.ps1
# Service Auditing � STUBS ONLY (no working commands included)

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
[CmdletBinding(SupportsShouldProcess = $true)]
    param([hashtable]$Config)
     $serviceName = "WinDefend"
  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

  if (-not $service) {
    Write-Log "Windows Defender service '$serviceName' not found." 'ERROR' -Config $Config
    return
  }

  if ($PSCmdlet.ShouldProcess($serviceName, "Ensure running and set to Automatic")) {
    if ($service.StartType -ne 'Automatic') {
      Set-Service -Name $serviceName -StartupType Automatic -WhatIf:$WhatIfPreference
      Write-Log "Set $serviceName startup type to Automatic." 'INFO' -Config $Config
    } else {
      Write-Log "$serviceName startup type already Automatic." 'INFO' -Config $Config
    }

    if ($service.Status -ne 'Running') {
      Start-Service -Name $serviceName -WhatIf:$WhatIfPreference
      Write-Log "Started $serviceName service." 'INFO' -Config $Config
    } else {
      Write-Log "$serviceName service already running." 'INFO' -Config $Config
    }
  }
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
[CmdletBinding(SupportsShouldProcess = $true)]
    param([hashtable]$Config)
    $serviceName = "EventLog"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if (-not $service) {
    Write-Log -Message "Event Log service '$serviceName' not found." -Level 'ERROR' -Config $Config
    return
}
if ($PSCmdlet.ShouldProcess($serviceName, "Ensure running and set to Automatic")) {
    if ($service.StartType -ne 'Automatic') {
        Set-Service -Name $serviceName -StartupType Automatic
        Write-Log -Message "Set $serviceName startup type to Automatic." -Level 'INFO' -Config $Config
    } else {
        Write-Log -Message "$serviceName startup type already Automatic." -Level 'INFO' -Config $Config
    }

    if ($service.Status -ne 'Running') {
        Start-Service -Name $serviceName
        Write-Log -Message "Started $serviceName service." -Level 'INFO' -Config $Config
    } else {
        Write-Log -Message "$serviceName service already running." -Level 'INFO' -Config $Config
    }
}

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
[CmdletBinding(SupportsShouldProcess = $true)]
    param([hashtable]$Config)
   $services = $Config.ServicesToDisable
if (-not $services -or -not $services.Count) {
    Write-Log -Message "No services configured to disable." -Level 'WARN' -Config $Config
    return
}

foreach ($service in $services) {
    $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log -Message "Service '$service' not found." -Level 'WARN' -Config $Config
        continue
    }
    if ($PSCmdlet.ShouldProcess($service, "Stop service")) {
        if ($svc.Status -ne 'Stopped') {
            try {
                Stop-Service -Name $service -Force
                Write-Log -Message "Stopped service: $service" -Level 'INFO' -Config $Config
            } catch {
                Write-Log -Message "Failed to stop service: $service. Error: $_" -Level 'ERROR' -Config $Config
            }
        } else {
            Write-Log -Message "Service '$service' already stopped." -Level 'INFO' -Config $Config
        }
    }

    if ($PSCmdlet.ShouldProcess($service, "Disable service")) {
        if ($svc.StartType -ne 'Disabled') {
            try {
                Set-Service -Name $service -StartupType Disabled
                Write-Log -Message "Set service to Disabled: $service" -Level 'INFO' -Config $Config
            } catch {
                Write-Log -Message "Failed to disable service: $service. Error: $_" -Level 'ERROR' -Config $Config
            }
        } else {
            Write-Log -Message "Service '$service' already Disabled." -Level 'INFO' -Config $Config
        }
    }
}

}
