# Global configuration and helpers

# Resolve the current user name and Desktop path
$docUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\')[-1]
$desktop = [Environment]::GetFolderPath('Desktop')

$script:GV = [ordered]@{
    WhatIf  = $true
    Verbose = $true
    LogPath = "$env:PUBLIC\Documents\HardeningLog.txt"

    # Document System Variables
    DocOutputDir             = (Join-Path $desktop 'DOCS')
    DocExecutableSearchRoots = @('C:\Users','C:\Program Files','C:\Program Files (x86)')

    # UserAuditing Variables
    TempPassword  = 'P@ssw0rd123!'  # demo value
    AdminRename   = 'nimda'
    GuestRename   = 'tseug'

    # AccountPolicy Variables
    MinPasswordLength          = 10
    MaxPasswordAgeDays         = 60
    MinPasswordAgeDays         = 10
    PasswordHistorySize        = 24
    PasswordComplexityEnabled  = $true
    LockoutThreshold           = 5
    LockoutDurationMinutes     = 20
    ResetLockoutCounterMinutes = 20
    StorePasswordsUsingReversibleEncryptionEnabled = $false

    # LocalPolicy Variables
    LegalNoticeText = 'Authorized Use Only.'

    # DefensiveCountermeasures Variables
    FirewallLogPath      = '%SystemRoot%\System32\logfiles\firewall\allprofilesfw.log'
    FirewallLogMaxSizeKB = 16384

    # Service Auditing Variables
    ServicesToDisable = @(
        'BTAGService','bthserv','Browser','MapsBroker','lfsvc','IISADMIN','irmon','lltdsvc',
        'LxssManager','FTPSVC','MSiSCSI','sshd','PNRPsvc','p2psvc','p2pimsvc','PNRPAutoReg',
        'Spooler','wercplsupport','RasAuto','SessionEnv','TermService','UmRdpService','RpcLocator',
        'RemoteRegistry','RemoteAccess','LanmanServer','simptcp','SNMP','sacsvr','SSDPSRV',
        'upnphost','WMSvc','WerSvc','Wecsvc','WMPNetworkSvc','icssvc','WpnService','PushToInstall',
        'WinRM','W3SVC','XboxGipSvc','XblAuthManager','XblGameSave','XboxNetApiSvc','NetTcpPortSharing',
        'DNS','LPDsvc','RasMan','SNMPTRAP','TlntSvr','TapiSrv','WebClient','LanmanWorkstation'
    )

    # Prohibited Files Variables
    ProhibitedExtensions = @('*.mp3','*.mp4','*.avi','*.mkv','*.ogg','*.flac')
}

# Optional alias so callers can just pass -Config $GV
$GV = $script:GV

# Sanity checks
if ($GV.MinPasswordAgeDays -gt $GV.MaxPasswordAgeDays) {
    Write-Warning "MinPasswordAgeDays ($($GV.MinPasswordAgeDays)) > MaxPasswordAgeDays ($($GV.MaxPasswordAgeDays))."
}
if ($GV.MinPasswordLength -lt 1) {
    Write-Warning "MinPasswordLength should be >= 1."
}

function Write-Log {
    param([string]$Msg,[hashtable]$Config)
    if (-not $Config -or -not $Config.LogPath) { return }
    $ts = (Get-Date).ToString('s')
    $dir = Split-Path $Config.LogPath -Parent
    if (-not (Test-Path $dir)) { try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {} }
    Add-Content -Path $Config.LogPath -Value "$ts`t$Msg"
}