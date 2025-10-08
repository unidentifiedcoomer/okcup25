# includes\04-AccountPolicy.ps1
# Account Policy category – STUBS ONLY (no working commands included)

function Invoke-AccountPolicy {
    param([hashtable]$Config)

    Write-Host "[Account Policy] Start" -ForegroundColor Cyan

    # 1) Export once
    $inf = Export-LocalSecurityPolicy

    # 2) Student tasks call Set-InfContent against the SAME $inf
    Set-AccountPolicy-MinPasswordLength     -Config $Config
    Set-AccountPolicy-MaxPasswordAge        -Config $Config
    Set-AccountPolicy-MinPasswordAge        -Config $Config
    Set-AccountPolicy-PasswordHistory       -Config $Config
    Set-AccountPolicy-PasswordComplexity    -Config $Config -InfPath $inf
    Set-AccountPolicy-LockoutDuration       -Config $Config
    Set-AccountPolicy-ResetLockoutCounter   -Config $Config
    Set-AccountPolicy-StoreReversibleEncryption -Config $Config -InfPath $inf

    # 3) Import once (and clean up)
    Import-LocalSecurityPolicy -InfPath $inf -Cleanup
    Write-Host "[Account Policy] Done" -ForegroundColor Cyan
}

function Set-AccountPolicy-MinPasswordLength {
<#
.EXPLANATION
Set "Minimum password length" to the value in $Config.MinPasswordLength on the local system.

.AI_PROMPT
"Write PowerShell that sets Windows 'Minimum password length' to the integer in $Config.MinPasswordLength
on the local machine. Keep it simple for a scripting class (no idempotence, no -WhatIf/-Verbose).
Use a built-in tool or policy method appropriate for local policy, and emit a one-line confirmation."
#>
    param([hashtable]$Config)
    # Set Windows "Minimum password length" using value from $Config.MinPasswordLength
$MinLength = $Config.MinPasswordLength
secedit /export /cfg "$env:TEMP\secpol.cfg" > $null
(Get-Content "$env:TEMP\secpol.cfg") -replace '^MinimumPasswordLength\s*=\s*\d+', "MinimumPasswordLength = $MinLength" |
    Set-Content "$env:TEMP\secpol.cfg"
secedit /configure /db "$env:TEMP\secpol.sdb" /cfg "$env:TEMP\secpol.cfg" /quiet
Write-Host "Set minimum password length to $MinLength."

}

function Set-AccountPolicy-MaxPasswordAge {
<#
.EXPLANATION
Set "Maximum password age (days)" to $Config.MaxPasswordAgeDays.

.AI_PROMPT
"Write PowerShell to set 'Maximum password age' (in days) to $Config.MaxPasswordAgeDays for local policy.
Prefer a straightforward single-line approach and print a short confirmation."
#>
    param([hashtable]$Config)
    net accounts /maxpwage:$($Config.MaxPasswordAgeDays) | Out-Null; Write-Host "Set maximum password age to $($Config.MaxPasswordAgeDays) days."

}

function Set-AccountPolicy-MinPasswordAge {
<#
.EXPLANATION
Set "Minimum password age (days)" to $Config.MinPasswordAgeDays.

.AI_PROMPT
"Write PowerShell to set 'Minimum password age' (in days) to $Config.MinPasswordAgeDays for the local system.
Keep it minimal and print a short confirmation message."
#>
    param([hashtable]$Config)
    # TODO
}

function Set-AccountPolicy-PasswordHistory {
<#
.EXPLANATION
Set "Enforce password history" to remember $Config.PasswordHistorySize previous passwords.

.AI_PROMPT
"Write a simple PowerShell snippet to set local 'Password history size' to $Config.PasswordHistorySize.
After applying, print a one-line confirmation."
#>
    param([hashtable]$Config)
    # TODO
}

function Set-AccountPolicy-PasswordComplexity {
<#
.EXPLANATION
Edit only the exported INF to enable/disable password complexity based on $Config.PasswordComplexityEnabled.
Export/import are handled in Invoke-AccountPolicy; this function just modifies the INF at -InfPath.

.AI_PROMPT
Return only the PowerShell code (no markdown fences, no comments, no prose). Define exactly:

function Set-AccountPolicy-PasswordComplexity {
  param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
  $value = if ($Config.PasswordComplexityEnabled) { 1 } else { 0 }
  Set-InfContent -InfPath $InfPath -Pattern 'PasswordComplexity\s*=.*' -Replacement "PasswordComplexity = $value"
  Write-Host "Password complexity set to $value in INF."
}

Do not export or import policy. Use exactly the parameter names and the Set-InfContent call shown. Output nothing else.

#>
    param(
        [hashtable]$Config,
        [Parameter(Mandatory)][string]$InfPath
    )
    # TODO: Student implementation
}

function Set-AccountPolicy-LockoutThreshold {
<#
.EXPLANATION
Set "Account lockout threshold" (bad logon attempts) to $Config.LockoutThreshold.

.AI_PROMPT
"Write PowerShell that sets the local 'Account lockout threshold' to the integer in $Config.LockoutThreshold.
Make it a simple one-liner style solution and print a confirmation."
#>
    param([hashtable]$Config)
    # TODO
}

function Set-AccountPolicy-LockoutDuration {
<#
.EXPLANATION
Set "Account lockout duration" to $Config.LockoutDurationMinutes (minutes).

.AI_PROMPT
"Write PowerShell to set 'Account lockout duration' (minutes) to $Config.LockoutDurationMinutes on the local machine.
Keep it concise and print a one-line confirmation."
#>
    param([hashtable]$Config)
    # TODO
}

function Set-AccountPolicy-ResetLockoutCounter {
<#
.EXPLANATION
Set "Reset account lockout counter after" to $Config.ResetLockoutCounterMinutes (minutes).

.AI_PROMPT
"Write PowerShell that sets the local 'Reset account lockout counter after' policy (in minutes) to
$Config.ResetLockoutCounterMinutes. Keep it short and print a one-line confirmation."
#>
    param([hashtable]$Config)
    # TODO
}

function Set-AccountPolicy-StoreReversibleEncryption {
<#
.EXPLANATION
Edit only the exported INF to set 'Store passwords using reversible encryption' based on
$Config.StorePasswordsUsingReversibleEncryptionEnabled (false → 0 [Disabled], true → 1 [Enabled]).
Export/import are handled in Invoke-AccountPolicy.

.AI_PROMPT
Return only PowerShell code (no prose). Define exactly:

function Set-AccountPolicy-StoreReversibleEncryption {
  param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
  $value = if ($Config.StorePasswordsUsingReversibleEncryptionEnabled) { 1 } else { 0 }
  Set-InfContent -InfPath $InfPath -Pattern '(?m)^\s*ClearTextPassword\s*=\s*\d+\s*$' -Replacement "ClearTextPassword = $value"
  Write-Host "Store passwords using reversible encryption set to $value in INF."
}

Do not export or import policy here.
#>
    param([hashtable]$Config, [Parameter(Mandatory)][string]$InfPath)
    # TODO: Student implementation
}
