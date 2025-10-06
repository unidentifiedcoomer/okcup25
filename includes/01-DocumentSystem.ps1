#
function Invoke-DocumentSystem {
    param([hashtable]$Config)

    if ($Config.Verbose) { Write-Host "[DocumentSystem] Starting..." -ForegroundColor Cyan }

$DOCS = if ($Config.DocOutputDir) { $Config.DocOutputDir } else {
  $u = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
  "C:\Users\$u\Desktop\DOCS"
}
DS-Doc-QuickSweep -Config $Config -DocsPath $DOCS


    if ($Config.Verbose) { Write-Host "[DocumentSystem] Complete." -ForegroundColor Cyan }
}

function DS-Doc-QuickSweep {
    param([hashtable]$Config, [Parameter(Mandatory)][string]$DocsPath)

    # Ensure folder
    if (-not (Test-Path $DocsPath)) { New-Item -ItemType Directory -Path $DocsPath -Force | Out-Null }

    # Installed programs (x64 + WOW6432) excluding Microsoft
    $programs = @(
        Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
    ) | Where-Object { $_.DisplayName -and $_.Publisher -ne 'Microsoft Corporation' }
    $programs | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-File -FilePath (Join-Path $DocsPath 'programs.txt')

    # Local users & admins
    Get-LocalUser | Select-Object Name | Out-File -FilePath (Join-Path $DocsPath 'users.txt')
    Get-LocalGroupMember -Group 'Administrators' | Select-Object Name | Out-File -FilePath (Join-Path $DocsPath 'admins.txt')

    # Listening sockets, running services
    netstat -aobn | Out-File -FilePath (Join-Path $DocsPath 'listening.txt')
    Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, DisplayName, Status | Out-File -FilePath (Join-Path $DocsPath 'services.txt')

    # Installed features (Server cmdlet may not exist on client)
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName, Installed | Out-File -FilePath (Join-Path $DocsPath 'features.txt')
    } else {
        'Get-WindowsFeature not available on this SKU.' | Out-File -FilePath (Join-Path $DocsPath 'features.txt')
    }

    # Security policy export
    secedit /export /cfg (Join-Path $DocsPath 'secedit.txt') | Out-Null

    # Defender preferences
    Get-MpPreference | Out-File -FilePath (Join-Path $DocsPath 'WindowsDefenderPreferences.txt')

    # Scheduled tasks
    Get-ScheduledTask | Select-Object TaskName, Author, State | Out-File -FilePath (Join-Path $DocsPath 'scheduled_tasks.txt')

    # Running processes (safe StartTime)
    Get-Process | Select-Object Name, Id, CPU, @{n='StartTime';e={try{$_.StartTime}catch{}}}, Path |
        Out-File -FilePath (Join-Path $DocsPath 'running_processes.txt')

    # Event logs (snapshot)
    Get-WinEvent -LogName Security    -MaxEvents 1000 | Export-Clixml -Path (Join-Path $DocsPath 'security_events.xml')
    Get-WinEvent -LogName System      -MaxEvents 1000 | Export-Clixml -Path (Join-Path $DocsPath 'system_events.xml')
    Get-WinEvent -LogName Application -MaxEvents 1000 | Export-Clixml -Path (Join-Path $DocsPath 'application_events.xml')

    # “Local User Privileges” (admins again, with type)
    Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass | Out-File -FilePath (Join-Path $DocsPath 'admin_privileges.txt')

    # Firewall rules
    Get-NetFirewallRule | Select-Object Name, DisplayName, Enabled, Direction, Action |
        Out-File -FilePath (Join-Path $DocsPath 'firewall_rules.txt')

    # Second listening port list
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess |
        Out-File -FilePath (Join-Path $DocsPath 'listening_ports.txt')

    # Group Policy results (HTML)
    gpresult /h (Join-Path $DocsPath 'group_policy.html') | Out-Null

    # Audit policy
    AuditPol /Get /Category:* | Out-File -FilePath (Join-Path $DocsPath 'audit_policy.txt')

    # Shares
    Get-SmbShare | Select-Object Name, Path, Description | Out-File -FilePath (Join-Path $DocsPath 'shared_folders.txt')

    # Installed updates
    Get-HotFix | Out-File -FilePath (Join-Path $DocsPath 'installed_updates.txt')

    # Defender scan logs
    Get-MpThreatDetection | Out-File -FilePath (Join-Path $DocsPath 'defender_scan_results.txt')

    # Executables under common roots
    $roots = if ($Config.DocExecutableSearchRoots) { $Config.DocExecutableSearchRoots } else { @('C:\Users','C:\Program Files','C:\Program Files (x86)') }
    Get-ChildItem -Path $roots -Filter '*.exe' -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object FullName | Out-File -FilePath (Join-Path $DocsPath 'executables.txt')
}

