# includes\05-LocalPolicy.ps1
# Local Policy – User Rights Assignment (stubs only; uses Export-LocalSecurityPolicy / Set-InfContent / Import-LocalSecurityPolicy)

function Invoke-LocalPolicy {
    param([hashtable]$Config)

    Write-Host "[Local Policy] Start" -ForegroundColor Cyan

    # 1) Export once
    $inf = Export-LocalSecurityPolicy

    # 2) Student tasks edit the SAME $inf
    LP-Disable-CredManTrustedCaller              -Config $Config -InfPath $inf
    LP-Remove-Everyone-From-Delegation           -Config $Config -InfPath $inf
    LP-Remove-Everyone-From-NetworkLogonRight    -Config $Config -InfPath $inf
    LP-Restrict-CreateGlobalObjects              -Config $Config -InfPath $inf
    LP-Deny-NetworkLogon-Include-Guest           -Config $Config -InfPath $inf
    LP-Restrict-RemoteShutdown                   -Config $Config -InfPath $inf
    LP-Restrict-LoadDriverPrivilege              -Config $Config -InfPath $inf
    LP-Restrict-ManageSecurityLog                -Config $Config -InfPath $inf
    LP-Restrict-TakeOwnership                    -Config $Config -InfPath $inf
    
    # 2b) Auditing (does not use INF)
    LP-Enable-AllAuditPolicy                     -Config $Config

    # 2c) Security Options (registry-based)
    LP-SecOpt-LimitBlankPasswordsConsoleOnly     -Config $Config
    LP-SecOpt-PreventPrinterDriverInstall        -Config $Config
    LP-SecOpt-RestrictCDROMToLocal               -Config $Config
    LP-SecOpt-RestrictFloppyToLocal              -Config $Config
    LP-SecOpt-RequireStrongKey                   -Config $Config
    LP-SecOpt-DoNotDisplayLastUser               -Config $Config
    LP-SecOpt-DisableCtrlAltDelRequirement       -Config $Config
    LP-SecOpt-SetLegalNoticeText                 -Config $Config
    LP-SecOpt-ClientRequireSMBSigning            -Config $Config
    LP-SecOpt-ClientDisablePlainTextPassword     -Config $Config
    LP-SecOpt-ServerRequireSMBSigning            -Config $Config
    LP-SecOpt-ServerEnableSMBSigningIfAgreed     -Config $Config
    LP-SecOpt-RestrictAnonymousSamAndShares      -Config $Config
    LP-SecOpt-DisableEveryoneIncludesAnonymous   -Config $Config
    LP-SecOpt-RestrictNullSessionAccess          -Config $Config
    LP-SecOpt-NullSessionSharesNone              -Config $Config
    LP-SecOpt-DoNotStoreLMHash                   -Config $Config
    LP-SecOpt-RecoveryConsoleNoAutoAdminLogon    -Config $Config
    LP-SecOpt-DisableShutdownWithoutLogon        -Config $Config
    LP-SecOpt-ClearPagefileAtShutdown            -Config $Config
    LP-SecOpt-UAC-ConsentPromptBehaviorAdmin     -Config $Config
    LP-SecOpt-UAC-DisableUIAccessNoSecureDesktop -Config $Config
    LP-SecOpt-UAC-RunAllAdminsInAAM              -Config $Config
    LP-SecOpt-UAC-SecureDesktopPrompt            -Config $Config

    # 3) Import once (and clean up)
    Import-LocalSecurityPolicy -InfPath $inf -Cleanup
    Write-Host "[Local Policy] Done" -ForegroundColor Cyan
}

function LP-Disable-CredManTrustedCaller {
<#
.EXPLANATION
“Access Credential Manager as a trusted caller” should be restricted. Replace the entire
SeTrustedCredManAccessPrivilege line so only Administrators retain the right.

.AI_PROMPT
Return only PowerShell code (no prose). Edit an already-exported INF at -InfPath using Set-InfContent:

param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeTrustedCredManAccessPrivilege.*$' -Replacement 'SeTrustedCredManAccessPrivilege = *S-1-5-32-544'
Write-Host "SeTrustedCredManAccessPrivilege restricted to Administrators in INF."
#>
      param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeTrustedCredManAccessPrivilege.*$' -Replacement 'SeTrustedCredManAccessPrivilege = *S-1-5-32-544'
Write-Host "SeTrustedCredManAccessPrivilege restricted to Administrators in INF."

}

function LP-Remove-Everyone-From-Delegation {
<#
.EXPLANATION
“Enable computer and user accounts to be trusted for delegation” should not include Everyone.
Replace the line so only Administrators remain.

.AI_PROMPT
Return only PowerShell code (no prose) that replaces the entire line:

param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeEnableDelegationPrivilege.*$' -Replacement 'SeEnableDelegationPrivilege = *S-1-5-32-544'
Write-Host "SeEnableDelegationPrivilege set to Administrators only in INF."
#>
    param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeEnableDelegationPrivilege.*$' -Replacement 'SeEnableDelegationPrivilege = *S-1-5-32-544'
Write-Host "SeEnableDelegationPrivilege set to Administrators only in INF."

}

function LP-Remove-Everyone-From-NetworkLogonRight {
<#
.EXPLANATION
“Access this computer from the network” should not grant Everyone. Edit ONLY that token out of the
existing value, keeping all other principals unchanged.

.AI_PROMPT
Return only PowerShell code (no prose) that removes the Everyone SID token "*S-1-1-0" from that line:

param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^(SeNetworkLogonRight\s*=.*?)(\*S-1-1-0,?)' -Replacement '$1'
Write-Host "Removed Everyone from SeNetworkLogonRight in INF."
#>
    param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^(SeNetworkLogonRight\s*=.*?)(*S-1-1-0,?)' -Replacement '$1'
Write-Host "Removed Everyone from SeNetworkLogonRight in INF."

}

function LP-Restrict-CreateGlobalObjects {
<#
.EXPLANATION
“Create global objects” should be limited to core service accounts and Administrators. Replace the line
with a constrained SID list (LocalService, NetworkService, Administrators, Service).

.AI_PROMPT
Return only PowerShell code (no prose) that replaces the entire line:

param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeCreateGlobalPrivilege.*$' -Replacement 'SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6'
Write-Host "SeCreateGlobalPrivilege restricted to service accounts and Administrators in INF."
#>
    
    param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeCreateGlobalPrivilege.*$' -Replacement 'SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6'
Write-Host "SeCreateGlobalPrivilege restricted to service accounts and Administrators in INF."

}

function LP-Deny-NetworkLogon-Include-Guest {
<#
.EXPLANATION
“Deny access to this computer from the network” must include the Guest account. Replace the line so it lists Guest.

.AI_PROMPT
Return only PowerShell code (no prose) that replaces the entire line:

param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeDenyNetworkLogonRight.*$' -Replacement 'SeDenyNetworkLogonRight = Guest'
Write-Host "SeDenyNetworkLogonRight set to include Guest in INF."
#>
    
    param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeDenyNetworkLogonRight.*$' -Replacement 'SeDenyNetworkLogonRight = Guest'
Write-Host "SeDenyNetworkLogonRight set to include Guest in INF."

}

function LP-Restrict-RemoteShutdown {
<#
.EXPLANATION
“Force shutdown from a remote system” should be limited to Administrators. Replace the line accordingly.

.AI_PROMPT
Return only PowerShell code (no prose) that replaces the entire line:

param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeRemoteShutdownPrivilege.*$' -Replacement 'SeRemoteShutdownPrivilege = *S-1-5-32-544'
Write-Host "SeRemoteShutdownPrivilege restricted to Administrators in INF."
#>
    param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
    
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeRemoteShutdownPrivilege.*$' -Replacement 'SeRemoteShutdownPrivilege = *S-1-5-32-544'
Write-Host "SeRemoteShutdownPrivilege restricted to Administrators in INF."

}

function LP-Restrict-LoadDriverPrivilege {
<#
.EXPLANATION
“Load and unload device drivers” should be limited to Administrators. Replace the line accordingly.

.AI_PROMPT
Return only PowerShell code (no prose) that replaces the entire line:

param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeLoadDriverPrivilege.*$' -Replacement 'SeLoadDriverPrivilege = *S-1-5-32-544'
Write-Host "SeLoadDriverPrivilege restricted to Administrators in INF."
#>
    param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeLoadDriverPrivilege.*$' -Replacement 'SeLoadDriverPrivilege = *S-1-5-32-544'
Write-Host "SeLoadDriverPrivilege restricted to Administrators in INF."

}

function LP-Restrict-ManageSecurityLog {
<#
.EXPLANATION
“Manage auditing and security log” should be limited to Administrators. Replace the line accordingly.

.AI_PROMPT
Return only PowerShell code (no prose) that replaces the entire line:

param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeSecurityPrivilege.*$' -Replacement 'SeSecurityPrivilege = *S-1-5-32-544'
Write-Host "SeSecurityPrivilege restricted to Administrators in INF."
#>
    param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeSecurityPrivilege.*$' -Replacement 'SeSecurityPrivilege = *S-1-5-32-544'
Write-Host "SeSecurityPrivilege restricted to Administrators in INF."

}

function LP-Restrict-TakeOwnership {
<#
.EXPLANATION
“Take ownership of files or other objects” should be limited to Administrators. Replace the line accordingly.

.AI_PROMPT
Return only PowerShell code (no prose) that replaces the entire line:

param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeTakeOwnershipPrivilege.*$' -Replacement 'SeTakeOwnershipPrivilege = *S-1-5-32-544'
Write-Host "SeTakeOwnershipPrivilege restricted to Administrators in INF."
#>
    param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
Set-InfContent -InfPath $InfPath -Pattern '(?mi)^\s*SeSecurityPrivilege.*$' -Replacement 'SeSecurityPrivilege = *S-1-5-32-544'
Write-Host "SeSecurityPrivilege restricted to Administrators in INF."

}

function LP-Enable-AllAuditPolicy {
<#
.EXPLANATION
Enable Advanced Audit Policy for all categories with both success and failure auditing using `auditpol`.
This does not use the INF; it’s a direct command and should print a brief confirmation.

.AI_PROMPT
Return only PowerShell code (no markdown, no comments, no extra text):

function LP-Enable-AllAuditPolicy {
  param([hashtable]$Config)
  auditpol /set /category:* /failure:enable /success:enable
  Write-Host "Advanced Audit Policy: success and failure enabled for all categories."
}
#>
    function LP-Enable-AllAuditPolicy {
param([hashtable]$Config)
auditpol /set /category:* /failure:enable /success:enable
Write-Host "Advanced Audit Policy: success and failure enabled for all categories."
}

}

function LP-SecOpt-LimitBlankPasswordsConsoleOnly {
<#
.EXPLANATION
Accounts: Limit local use of blank passwords to console only → Enabled (LimitBlankPasswordUse = 1).

.AI_PROMPT
Return only PowerShell code (no prose):

function LP-SecOpt-LimitBlankPasswordsConsoleOnly {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 1 -Force
  Write-Host 'LimitBlankPasswordUse set to 1.'
}
#>
    function LP-SecOpt-LimitBlankPasswordsConsoleOnly {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 1 -Force
    Write-Host 'LimitBlankPasswordUse set to 1.'
}

}
function LP-SecOpt-PreventPrinterDriverInstall {
<#
.EXPLANATION
Devices: Prevent users from installing printer drivers → Enabled (AddPrinterDrivers = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-PreventPrinterDriverInstall {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -Name 'AddPrinterDrivers' -Value 1 -Force
  Write-Host 'AddPrinterDrivers set to 1.'
}
#>
    function LP-SecOpt-PreventPrinterDriverInstall {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -Name 'AddPrinterDrivers' -Value 1 -Force
    Write-Host 'AddPrinterDrivers set to 1.'
}

}

function LP-SecOpt-RestrictCDROMToLocal {
<#
.EXPLANATION
Devices: Restrict CD-ROM access to locally logged on user only → Enabled (AllocateCDRoms = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-RestrictCDROMToLocal {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AllocateCDRoms' -Value 1 -Force
  Write-Host 'AllocateCDRoms set to 1.'
}
#>
    function LP-SecOpt-RestrictCDROMToLocal {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AllocateCDRoms' -Value 1 -Force
    Write-Host 'AllocateCDRoms set to 1.'
}

}

function LP-SecOpt-RestrictFloppyToLocal {
<#
.EXPLANATION
Devices: Restrict floppy access to locally logged on user only → Enabled (AllocateFloppies = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-RestrictFloppyToLocal {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AllocateFloppies' -Value 1 -Force
  Write-Host 'AllocateFloppies set to 1.'
}
#>
    function LP-SecOpt-RestrictFloppyToLocal {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AllocateFloppies' -Value 1 -Force
    Write-Host 'AllocateFloppies set to 1.'
}

}


function LP-SecOpt-RequireStrongKey {
<#
.EXPLANATION
Domain member: Digitally encrypt or sign secure channel data (always) → Enabled (RequireStrongKey = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-RequireStrongKey {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Value 1 -Force
  Write-Host 'RequireStrongKey set to 1.'
}
#>
    function LP-SecOpt-RequireStrongKey {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Value 1 -Force
    Write-Host 'RequireStrongKey set to 1.'
}


function LP-SecOpt-DoNotDisplayLastUser {
<#
.EXPLANATION
Interactive logon: Do not display last user name → Enabled (DontDisplayLastUserName = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-DoNotDisplayLastUser {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1 -Force
  Write-Host 'DontDisplayLastUserName set to 1.'
}
#>
    function LP-SecOpt-DoNotDisplayLastUser {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1 -Force
    Write-Host 'DontDisplayLastUserName set to 1.'
}

}

function LP-SecOpt-DisableCtrlAltDelRequirement {
<#
.EXPLANATION
Interactive logon: Do not require CTRL+ALT+DEL → Disabled (DisableCAD = 0).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-DisableCtrlAltDelRequirement {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DisableCAD' -Value 0 -Force
  Write-Host 'DisableCAD set to 0.'
}
#>
    function LP-SecOpt-DisableCtrlAltDelRequirement {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DisableCAD' -Value 0 -Force
    Write-Host 'DisableCAD set to 0.'
}

}

function LP-SecOpt-SetLegalNoticeText {
<#
.EXPLANATION
Interactive logon: Message text for users attempting to logon → set from $Config.LegalNoticeText (REG_SZ).

.AI_PROMPT
Return only PowerShell code. Use $Config.LegalNoticeText:

function LP-SecOpt-SetLegalNoticeText {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeText' -Value $Config.LegalNoticeText -Force
  Write-Host 'LegalNoticeText updated.'
}
#>
    function LP-SecOpt-SetLegalNoticeText {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeText' -Value $Config.LegalNoticeText -Force
    Write-Host 'LegalNoticeText updated.'
}

}

function LP-SecOpt-ClientRequireSMBSigning {
<#
.EXPLANATION
Microsoft network client: Digitally sign communications (always) → Enabled (RequireSecuritySignature = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-ClientRequireSMBSigning {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Force
  Write-Host 'Workstation RequireSecuritySignature set to 1.'
}
#>
    function LP-SecOpt-ClientRequireSMBSigning {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Force
    Write-Host 'Workstation RequireSecuritySignature set to 1.'
}

}

function LP-SecOpt-ClientDisablePlainTextPassword {
<#
.EXPLANATION
Microsoft network client: Send unencrypted password to third-party SMB servers → Disabled (EnablePlainTextPassword = 0).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-ClientDisablePlainTextPassword {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnablePlainTextPassword' -Value 0 -Force
  Write-Host 'Workstation EnablePlainTextPassword set to 0.'
}
#>
    function LP-SecOpt-ClientDisablePlainTextPassword {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnablePlainTextPassword' -Value 0 -Force
    Write-Host 'Workstation EnablePlainTextPassword set to 0.'
}

}

function LP-SecOpt-ServerRequireSMBSigning {
<#
.EXPLANATION
Microsoft network server: Digitally sign communications (always) → Enabled (RequireSecuritySignature = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-ServerRequireSMBSigning {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Force
  Write-Host 'Server RequireSecuritySignature set to 1.'
}
#>
    function LP-SecOpt-ServerRequireSMBSigning {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Force
    Write-Host 'Server RequireSecuritySignature set to 1.'
}

}

function LP-SecOpt-ServerEnableSMBSigningIfAgreed {
<#
.EXPLANATION
Microsoft network server: Digitally sign communications (if client agrees) → Enabled (EnableSecuritySignature = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-ServerEnableSMBSigningIfAgreed {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'EnableSecuritySignature' -Value 1 -Force
  Write-Host 'Server EnableSecuritySignature set to 1.'
}
#>
    function LP-SecOpt-ServerEnableSMBSigningIfAgreed {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'EnableSecuritySignature' -Value 1 -Force
    Write-Host 'Server EnableSecuritySignature set to 1.'
}

}

function LP-SecOpt-RestrictAnonymousSamAndShares {
<#
.EXPLANATION
Network access: Do not allow anonymous enumeration of SAM accounts and shares → Enabled (RestrictAnonymousSAM = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-RestrictAnonymousSamAndShares {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -Force
  Write-Host 'RestrictAnonymousSAM set to 1.'
}
#>
    function LP-SecOpt-RestrictAnonymousSamAndShares {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -Force
    Write-Host 'RestrictAnonymousSAM set to 1.'
}

}

function LP-SecOpt-DisableEveryoneIncludesAnonymous {
<#
.EXPLANATION
Network access: Let Everyone permissions apply to anonymous users → Disabled (EveryoneIncludesAnonymous = 0).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-DisableEveryoneIncludesAnonymous {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0 -Force
  Write-Host 'EveryoneIncludesAnonymous set to 0.'
}
#>
    function LP-SecOpt-DisableEveryoneIncludesAnonymous {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0 -Force
    Write-Host 'EveryoneIncludesAnonymous set to 0.'
}

}

function LP-SecOpt-RestrictNullSessionAccess {
<#
.EXPLANATION
Network access: Restrict anonymous access to Named Pipes and Shares → Enabled (RestrictNullSessAccess = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-RestrictNullSessionAccess {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1 -Force
  Write-Host 'RestrictNullSessAccess set to 1.'
}
#>
    function LP-SecOpt-RestrictNullSessionAccess {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1 -Force
    Write-Host 'RestrictNullSessAccess set to 1.'
}

}

function LP-SecOpt-NullSessionSharesNone {
<#
.EXPLANATION
Network access: Shares that can be accessed anonymously → None (empty REG_MULTI_SZ).

.AI_PROMPT
Return only PowerShell code. Ensure MultiString type and empty value:

function LP-SecOpt-NullSessionSharesNone {
  param([hashtable]$Config)
  New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'NullSessionShares' -PropertyType MultiString -Value @() -Force | Out-Null
  Write-Host 'NullSessionShares cleared.'
}
#>
    function LP-SecOpt-NullSessionSharesNone {
    param([hashtable]$Config)
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'NullSessionShares' -PropertyType MultiString -Value @() -Force | Out-Null
    Write-Host 'NullSessionShares cleared.'
}

}

function LP-SecOpt-DoNotStoreLMHash {
<#
.EXPLANATION
Network security: Do not store LAN Manager hash value on next password change → Enabled (NoLMHash = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-DoNotStoreLMHash {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -Force
  Write-Host 'NoLMHash set to 1.'
}
#>
    function LP-SecOpt-DoNotStoreLMHash {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -Force
    Write-Host 'NoLMHash set to 1.'
}

}

function LP-SecOpt-RecoveryConsoleNoAutoAdminLogon {
<#
.EXPLANATION
Recovery console: Allow automatic administrative logon → Disabled (SecurityLevel = 0).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-RecoveryConsoleNoAutoAdminLogon {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole' -Name 'SecurityLevel' -Value 0 -Force
  Write-Host 'Recovery Console SecurityLevel set to 0.'
}
#>
    function LP-SecOpt-RecoveryConsoleNoAutoAdminLogon {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole' -Name 'SecurityLevel' -Value 0 -Force
    Write-Host 'Recovery Console SecurityLevel set to 0.'
}

}


function LP-SecOpt-DisableShutdownWithoutLogon {
<#
.EXPLANATION
Shutdown: Allow system to be shut down without logging on → Disabled (ShutdownWithoutLogon = 0).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-DisableShutdownWithoutLogon {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ShutdownWithoutLogon' -Value 0 -Force
  Write-Host 'ShutdownWithoutLogon set to 0.'
}
#>
    function LP-SecOpt-DisableShutdownWithoutLogon {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ShutdownWithoutLogon' -Value 0 -Force
    Write-Host 'ShutdownWithoutLogon set to 0.'
}

}

function LP-SecOpt-ClearPagefileAtShutdown {
<#
.EXPLANATION
Shutdown: Clear virtual memory pagefile → Enabled (ClearPageFileAtShutdown = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-ClearPagefileAtShutdown {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Value 1 -Force
  Write-Host 'ClearPageFileAtShutdown set to 1.'
}
#>
    function LP-SecOpt-ClearPagefileAtShutdown {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Value 1 -Force
    Write-Host 'ClearPageFileAtShutdown set to 1.'
}

}

function LP-SecOpt-UAC-ConsentPromptBehaviorAdmin {
<#
.EXPLANATION
UAC: Admin Approval Mode prompt behavior for administrators → set to 2 (ConsentPromptBehaviorAdmin = 2).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-UAC-ConsentPromptBehaviorAdmin {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Force
  Write-Host 'ConsentPromptBehaviorAdmin set to 2.'
}
#>
    function LP-SecOpt-UAC-ConsentPromptBehaviorAdmin {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Force
    Write-Host 'ConsentPromptBehaviorAdmin set to 2.'
}

}

function LP-SecOpt-UAC-DisableUIAccessNoSecureDesktop {
<#
.EXPLANATION
UAC: Allow UIAccess apps to prompt for elevation without secure desktop → Disabled (EnableUIADesktopToggle = 0).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-UAC-DisableUIAccessNoSecureDesktop {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableUIADesktopToggle' -Value 0 -Force
  Write-Host 'EnableUIADesktopToggle set to 0.'
}
#>
    function LP-SecOpt-UAC-DisableUIAccessNoSecureDesktop {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableUIADesktopToggle' -Value 0 -Force
    Write-Host 'EnableUIADesktopToggle set to 0.'
}

}

function LP-SecOpt-UAC-RunAllAdminsInAAM {
<#
.EXPLANATION
UAC: Run all administrators in Admin Approval Mode → Enabled (FilterAdministratorToken = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-UAC-RunAllAdminsInAAM {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1 -Force
  Write-Host 'FilterAdministratorToken set to 1.'
}
#>
    function LP-SecOpt-UAC-RunAllAdminsInAAM {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1 -Force
    Write-Host 'FilterAdministratorToken set to 1.'
}

}

function LP-SecOpt-UAC-SecureDesktopPrompt {
<#
.EXPLANATION
UAC: Switch to the secure desktop when prompting for elevation → Enabled (PromptOnSecureDesktop = 1).

.AI_PROMPT
Return only PowerShell code:

function LP-SecOpt-UAC-SecureDesktopPrompt {
  param([hashtable]$Config)
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1 -Force
  Write-Host 'PromptOnSecureDesktop set to 1.'
}
#>
    function LP-SecOpt-UAC-SecureDesktopPrompt {
    param([hashtable]$Config)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1 -Force
    Write-Host 'PromptOnSecureDesktop set to 1.'
}

}

