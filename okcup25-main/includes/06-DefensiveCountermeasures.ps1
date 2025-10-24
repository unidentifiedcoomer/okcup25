function DCM-Defender-EnableRealtime {
    param([hashtable]$Config)

    # Ensure the Windows Defender registry paths exist
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Force | Out-Null
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Force | Out-Null

    # Make sure Defender itself isn't disabled by policy
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 0 -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableRealTimeMonitoring' -Value 0 -Force

    # --- Ensure Windows Defender (WinDefend) service is running ---
    Write-Host "Checking Windows Defender service status..." -ForegroundColor Yellow
    try {
        $svc = Get-Service -Name WinDefend -ErrorAction Stop

        if ($svc.StartType -eq 'Disabled') {
            Write-Host "Windows Defender service startup type is Disabled. Re-enabling..." -ForegroundColor Yellow
            Set-Service -Name WinDefend -StartupType Manual
        }

        if ($svc.Status -ne 'Running') {
            Write-Host "Starting Windows Defender service..." -ForegroundColor Cyan
            Start-Service -Name WinDefend
            Start-Sleep -Seconds 2
            Write-Host "Windows Defender service started." -ForegroundColor Green
        } else {
            Write-Host "Windows Defender service already running." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "⚠ Unable to start or access Windows Defender service. It may be removed or restricted by policy." -ForegroundColor Red
    }

    # --- Attempt to enable real-time protection ---
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Write-Host "Windows Defender real-time protection enabled"
    }
    catch {
        Write-Host "⚠ Failed to apply Defender real-time protection settings: $($_.Exception.Message)" -ForegroundColor Red
    }
}
