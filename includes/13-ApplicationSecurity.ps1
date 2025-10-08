#
function Invoke-ApplicationSecurity {
    param([hashtable]$Config)
    Write-Host "[ApplicationSecurity] Use the submenu from the main script." -ForegroundColor DarkCyan
}

function Secure-Firefox {
<#
.EXPLANATION
Harden Firefox enterprise preferences (e.g., disable unsafe features, enforce HSTS preload, etc.).
.AI_PROMPT
Write PowerShell that locates Firefox profiles for all users and enforces a minimal secure baseline.
Respect -WhatIf and -Verbose; log to $Config.LogPath.
#>
    param([hashtable]$Config, [switch]$WhatIf, [switch]$Verbose)
    Get-ChildItem 'C:\Users' -Directory | ForEach-Object {
  $ff = "$($_.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles"
  if (Test-Path $ff) {
    Get-ChildItem $ff -Directory | ForEach-Object {
      $ujs = "$($_.FullName)\user.js"
      $bkp = "$($_.FullName)\user.js.bak.$(Get-Date -f yyyyMMddHHmmss)"
      if (Test-Path $ujs) { Copy-Item $ujs $bkp -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference }
      $prefs = @'
user_pref("toolkit.telemetry.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.donottrackheader.enabled", true);
user_pref("network.cookie.cookieBehavior", 1);
user_pref("browser.safebrowsing.phishing.enabled", true);
user_pref("browser.safebrowsing.malware.enabled", true);
user_pref("app.update.enabled", true);
user_pref("browser.formfill.enable", false);
user_pref("signon.rememberSignons", false);
'@
      if ($PSCmdlet.ShouldProcess($ujs,"write baseline")) {
        $prefs | Out-File $ujs -Encoding UTF8 -Force
      }
      Add-Content -Path $Config.LogPath -Value "$(Get-Date) enforced baseline for $ujs"
    }
  }
}

}
function Secure-Chrome {
<#
.EXPLANATION
Configure Chrome policies via registry (HKLM\Software\Policies\Google\Chrome).
.AI_PROMPT
Write idempotent PowerShell to enforce basic security policies (SafeBrowsing, site isolation, etc.).
Use -WhatIf/-Verbose and Write-Log.
#>
    param([hashtable]$Config, [switch]$WhatIf, [switch]$Verbose)
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "$ts [$Level] $Message"
    Write-Verbose $line
    if (!(Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }
    Add-Content -Path $LogPath -Value $line
}

$Policies = @{
    "HKLM:\Software\Policies\Mozilla\Firefox" = @{
        "SafeBrowsing"               = 1
        "SiteIsolation"              = 1
        "DisableTelemetry"           = 1
        "DisablePocket"              = 1
        "DisableFirefoxStudies"      = 1
        "DisableDataSubmission"      = 1
    }
}

foreach ($path in $Policies.Keys) {
    foreach ($key in $Policies[$path].Keys) {
        $value = $Policies[$path][$key]
        if (-not (Test-Path $path)) {
            if ($PSCmdlet.ShouldProcess($path, "Create registry path")) {
                New-Item -Path $path -Force | Out-Null
                Write-Log "Created registry key: $path"
            }
        }
        $current = (Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue).$key
        if ($current -ne $value) {
            if ($PSCmdlet.ShouldProcess("$path\$key", "Set to $value")) {
                Set-ItemProperty -Path $path -Name $key -Value $value -Force
                Write-Log "Set $path\$key = $value"
            }
        } else {
            Write-Log "$path\$key already = $value (no change)" "INFO"
        }
    }
}
Write-Log "Security policy enforcement complete."

    function Write-Log{param([string]$m,[string]$l='INFO');$ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss');$ln="$ts [$l] $m";Write-Verbose $ln;if(!(Test-Path(Split-Path$LogPath))){New-Item -ItemType Directory -Path(Split-Path$LogPath) -Force|Out-Null};Add-Content $LogPath $ln}
 {
<#
.EXPLANATION
Harden RDP: NLA required, strong encryption, disable clipboard/device redirection where appropriate.
.AI_PROMPT
Write PowerShell to enforce secure RDP settings; check before set; idempotent; -WhatIf/-Verbose; Write-Log.
#>
    param([hashtable]$Config, [switch]$WhatIf, [switch]$Verbose)
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "$ts [$Level] $Message"
    Write-Verbose $line
    if (!(Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }
    Add-Content -Path $LogPath -Value $line
}

# RDP Security Baseline
$RdpSettings = @{
    "HKLM:\System\CurrentControlSet\Control\Terminal Server" = @{
        "fDenyTSConnections" = 0    # 0 = Allow RDP
    }
    "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" = @{
        "UserAuthentication" = 1    # Enforce NLA
        "SecurityLayer"      = 2    # SSL (TLS)
        "MinEncryptionLevel" = 3    # High (128-bit)
        "fDisableEncryption" = 0
    }
}

foreach ($path in $RdpSettings.Keys) {
    foreach ($name in $RdpSettings[$path].Keys) {
        $desired = $RdpSettings[$path][$name]
        if (-not (Test-Path $path)) {
            if ($PSCmdlet.ShouldProcess($path, "Create registry path")) {
                New-Item -Path $path -Force | Out-Null
                Write-Log "Created registry key $path"
            }
        }
        $current = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
        if ($current -ne $desired) {
            if ($PSCmdlet.ShouldProcess("$path\$name", "Set to $desired")) {
                Set-ItemProperty -Path $path -Name $name -Value $desired -Force
                Write-Log "Set $path\$name = $desired (was $current)"
            }
        } else {
            Write-Log "$path\$name already $desired (no change)" "INFO"
        }
    }
}

# Verify RDP firewall rule
$rule = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
if ($rule) {
    foreach ($r in $rule) {
        if ($r.Enabled -ne 'True') {
            if ($PSCmdlet.ShouldProcess($r.DisplayName, "Enable firewall rule")) {
                Set-NetFirewallRule -Name $r.Name -Enabled True
                Write-Log "Enabled firewall rule: $($r.DisplayName)"
            }
        } else {
            Write-Log "Firewall rule already enabled: $($r.DisplayName)" "INFO"
        }
    }
} else {
    Write-Log "No RDP firewall rule found" "WARN"
}

Write-Log "Secure RDP baseline enforcement complete."

function Secure-SMB
 {
<#
.EXPLANATION
Disable SMBv1, enforce SMB signing, and tighten guest/anonymous access.
.AI_PROMPT
Write PowerShell to disable SMBv1 features and enforce signing. Idempotent; -WhatIf/-Verbose; Write-Log.
#>
    param([hashtable]$Config, [switch]$WhatIf, [switch]$Verbose)
$SmbSettings=@{
"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"=@{"SMB1"=0;"RequireSecuritySignature"=1}
"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"=@{"RequireSecuritySignature"=1;"EnableSecuritySignature"=1}
"HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"=@{"Start"=4}
"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation"=@{"DependOnService"=@("Bowser","MRxSmb20","NSI")}
}
foreach($path in $SmbSettings.Keys){foreach($name in $SmbSettings[$path].Keys){$desired=$SmbSettings[$path][$name];if(-not(Test-Path$path)){if($PSCmdlet.ShouldProcess($path,"Create registry path")){New-Item -Path $path -Force|Out-Null;Write-Log"Created registry key $path"}}$current=(Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name;$isDifferent=$true;if($current -is [Array]){$isDifferent=-not(@($current)-ceq@($desired))}elseif($current -eq $desired){$isDifferent=$false}if($isDifferent){if($PSCmdlet.ShouldProcess("$path\$name","Set to $desired")){Set-ItemProperty -Path $path -Name $name -Value $desired -Force;Write-Log"Set $path\$name = $desired (was $current)"}}else{Write-Log"$path\$name already = $desired (no change)"}}}
$feature=Get-WindowsOptionalFeature -Online -FeatureName"SMB1Protocol"-ErrorAction SilentlyContinue;if($feature -and $feature.State -ne'Disabled'){if($PSCmdlet.ShouldProcess("SMB1Protocol feature","Disable")){Disable-WindowsOptionalFeature -Online -FeatureName"SMB1Protocol"-NoRestart -ErrorAction SilentlyContinue|Out-Null;Write-Log"Disabled SMB1Protocol feature"}}elseif($feature){Write-Log"SMB1Protocol feature already disabled"}
Write-Log"SMBv1 disablement and SMB signing enforcement complete."}
function Secure-DNS {
<#
.EXPLANATION
Configure secure DNS (e.g., set to approved servers, enable DNS over HTTPS where policy allows).
.AI_PROMPT
Write PowerShell that sets system DNS servers and validates connectivity; idempotent; -WhatIf/-Verbose.
#>
    param([hashtable]$Config, [switch]$WhatIf, [switch]$Verbose)
    $adapters=Get-DnsClient | Where-Object{$_.InterfaceAlias -notmatch "vEthernet|Loopback"}
foreach($adapter in $adapters){$current=$adapter.ServerAddresses;if(@($current)-ne@($DnsServers)){if($PSCmdlet.ShouldProcess($adapter.InterfaceAlias,"Set DNS servers")){Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $DnsServers -ErrorAction SilentlyContinue;Write-Log"Set DNS servers on $($adapter.InterfaceAlias) to $($DnsServers -join ', ')"}}else{Write-Log"DNS servers already set on $($adapter.InterfaceAlias)"}}
try{if(Test-Connection -ComputerName $TestHost -Count 1 -Quiet){Write-Log"DNS connectivity test passed ($TestHost)"}else{Write-Log"DNS connectivity test failed ($TestHost)" "WARN"}}catch{Write-Log"DNS connectivity check error: $_" "ERROR"}

}
function Secure-SSH {
<#
.EXPLANATION
If OpenSSH is installed, harden sshd_config (keys only, strong ciphers, etc.).
.AI_PROMPT
Detect presence of OpenSSH Server and enforce a hardened sshd_config; backup original; restart service as needed.
#>
    param([hashtable]$Config, [switch]$WhatIf, [switch]$Verbose)
    $service=Get-Service -Name sshd -ErrorAction SilentlyContinue
if(-not$service){Write-Log"OpenSSH Server not installed" "WARN";return}
$configFile="$env:ProgramData\ssh\sshd_config"
if(Test-Path$configFile){$backup="$configFile.bak_$(Get-Date -Format yyyyMMddHHmmss)";if($PSCmdlet.ShouldProcess($configFile,"Backup original config")){Copy-Item$configFile$backup -Force;Write-Log"Backed up sshd_config to $backup"}}
$hardened=@"
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
AllowUsers *
"@
if($PSCmdlet.ShouldProcess($configFile,"Apply hardened sshd_config")){Set-Content -Path$configFile -Value$hardened -Encoding UTF8;Write-Log"Applied hardened sshd_config"}
$diff=Compare-Object -ReferenceObject(Get-Content$configFile) -DifferenceObject($hardened.Split("`n")) -SyncWindow 0

if($diff){if($PSCmdlet.ShouldProcess("sshd","Restart to apply changes")){Restart-Service sshd -Force;Write-Log"Restarted sshd service"}}else{Write-Log"sshd_config already hardened; no restart needed"}
}
function Secure-IIS {
<#
.EXPLANATION
If IIS present, harden protocol/cipher suites and request filtering.
.AI_PROMPT
Check if IIS roles/features are present; enforce minimal secure baseline with idempotence; -WhatIf/-Verbose; Write-Log.
#>
    param([hashtable]$Config, [switch]$WhatIf, [switch]$Verbose)
    $roles=@("Web-Server","Web-WebServer","Web-Common-Http","Web-Static-Content","Web-Default-Doc","Web-Http-Errors","Web-Http-Redirect","Web-Health","Web-Http-Logging","Web-Request-Monitor","Web-Performance","Web-Stat-Compression","Web-Security","Web-Filtering","Web-Windows-Auth")
$installed=Get-WindowsFeature|Where-Object{$_.InstallState -eq"Installed"}
if(-not($installed|Where-Object Name -eq"Web-Server")){Write-Log"IIS not installed; baseline skipped" "WARN";return}
foreach($r in$roles){$f=Get-WindowsFeature -Name$r;if($f.InstallState -ne"Installed"){if($PSCmdlet.ShouldProcess($r,"Enable IIS role/feature")){Install-WindowsFeature -Name$r -IncludeManagementTools|Out-Null;Write-Log"Enabled IIS feature $r"}}else{Write-Log"$r already installed"}}
$settings=@{"HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"=@{"MaxConnections"=1000;"MaxKeepAliveRequests"=100;"ConnectionTimeout"=120}}
foreach($path in$settings.Keys){foreach($name in$settings[$path].Keys){$desired=$settings[$path][$name];$current=(Get-ItemProperty -Path$path -Name$name -ErrorAction SilentlyContinue).$name;if($current -ne$desired){if($PSCmdlet.ShouldProcess("$path\$name","Set to $desired")){Set-ItemProperty -Path$path -Name$name -Value$desired -Force;Write-Log"Set $path\$name=$desired"}}else{Write-Log"$path\$name already=$desired"}}}
$appCmd="$env:SystemRoot\System32\inetsrv\appcmd.exe"
if(Test-Path$appCmd){if($PSCmdlet.ShouldProcess("IIS Request Filtering","Apply secure defaults")){&$appCmd set config /section:requestFiltering /requestLimits.maxAllowedContentLength:30000000;Write-Log"Applied request filtering limit"}}
Write-Log"IIS baseline enforcement complete"
}
