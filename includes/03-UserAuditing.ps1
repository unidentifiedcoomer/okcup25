# includes\03-UserAuditing.ps1
# User Auditing category � STUBS ONLY (no working commands included)

function Invoke-UserAuditing {
    param([hashtable]$Config)

    Write-Host "[User Auditing] Start" -ForegroundColor Cyan

    Prompt-DisableEnabledLocalUsers          -Config $Config
    Prompt-RemoveAdministratorsMembers       -Config $Config
    Set-AllLocalPasswordsToTempAndExpire     -Config $Config
    Rename-BuiltinAdministrator              -Config $Config
    Rename-BuiltinGuest                      -Config $Config
    Remove-AllDeviceOwnersMembersNoPrompt    -Config $Config

    Write-Host "[User Auditing] Done" -ForegroundColor Cyan
}

function Prompt-DisableEnabledLocalUsers {
<#
.EXPLANATION
Loop through all **enabled** local (non-built-in/system) users and prompt:
"Disable <name>? [y/N]" where the default is **N** (pressing Enter = No).
If the user answers y/Y, disable that account.

.AI_PROMPT
"Write PowerShell to enumerate enabled local users on the machine and, for each,
prompt 'Disable <name>? [y/N]' with a default of N if Enter is pressed.
On 'y' or 'Y', disable the account. Skip well-known built-ins (Administrator/Guest)
and service/virtual accounts. Keep the implementation simple (no idempotence flags)."
#>
    param([hashtable]$Config)
    # TODO: Student implementation
}

function Prompt-RemoveAdministratorsMembers {
<#
.EXPLANATION
Enumerate members of the local **Administrators** group and prompt:
"Remove <member>? [y/N]" with default **N**. On y/Y, remove that member.

.AI_PROMPT
"Write PowerShell to list members of the local 'Administrators' group and, for each,
prompt 'Remove <member>? [y/N]' with default N if Enter is pressed.
On 'y' or 'Y', remove the member from Administrators. Handle both user and group principals.
Avoid removing the current logged-on user to prevent lockout."
#>
    param([hashtable]$Config)
    # TODO
}

function Set-AllLocalPasswordsToTempAndExpire {
<#
.EXPLANATION
Set **all local users' passwords** to `$Config.TempPassword` and mark them to **change at next logon**.
Skip disabled accounts, built-in/system accounts, and any accounts that cannot accept local password changes.

.AI_PROMPT
"Write PowerShell that iterates local users, sets each user's password to $Config.TempPassword,
and configures the account to require a password change at next logon. Skip disabled, built-in
(Administrator/Guest), and service/virtual accounts. Keep it simple and output a brief status per user."
#>
    param([hashtable]$Config)
    # TODO
}

function Rename-BuiltinAdministrator {
<#
.EXPLANATION
Rename the built-in **Administrator** account to the value in `$Config.AdminRename`.
Be careful to target the built-in admin by well-known RID (500) or reliable detection,
not merely by name, to handle systems where it was already renamed.

.AI_PROMPT
"Write PowerShell to rename the built-in Administrator account to the string in $Config.AdminRename.
Select the account by well-known RID 500 (preferred) or a robust method, then perform the rename.
Print a one-line confirmation. Keep it short and straightforward."
#>
    param([hashtable]$Config)
    # TODO
}

function Rename-BuiltinGuest {
<#
.EXPLANATION
Rename the built-in **Guest** account to the value in `$Config.GuestRename`.
Target the actual Guest account reliably (RID 501 or equivalent detection), not just by name.

.AI_PROMPT
"Write PowerShell to rename the built-in Guest account to $Config.GuestRename.
Identify the account by RID 501 (preferred) or a robust method, then rename it.
Print a one-line confirmation. Keep it concise."
#>
    param([hashtable]$Config)
    # TODO
}

function Remove-AllDeviceOwnersMembersNoPrompt {
<#
.EXPLANATION
Enumerate all members of the local group **'Device Owners'** and **remove them without prompting**.

.AI_PROMPT
"Write PowerShell to list all members of local group 'Device Owners' and remove each member with no prompts.
Handle user and group principals gracefully; ignore not-found errors and continue. Print a brief summary."
#>
    param([hashtable]$Config)
    # TODO
}
