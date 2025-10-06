# includes\00-Common.ps1
# Shared helpers for secedit-based local security policy edits (simple, blind-change style).

function Export-LocalSecurityPolicy {
<#
.SYNOPSIS
Export the current local security policy to an INF file.

.PARAMETER InfPath
Optional destination path. If omitted, a timestamped file is created in %TEMP%.

.OUTPUTS
[string] Full path to the exported INF.
#>
    [CmdletBinding()]
    param(
        [string]$InfPath = (Join-Path $env:TEMP ("secpol-{0:yyyyMMdd_HHmmss}.inf" -f (Get-Date)))
    )

    secedit /export /cfg "$InfPath" | Out-Null
    # Normalize to ASCII which INF prefers
    $raw = Get-Content -Path "$InfPath" -Raw
    Set-Content -Path "$InfPath" -Value $raw -Encoding ASCII
    return $InfPath
}

function Set-InfContent {
<#
.SYNOPSIS
Apply one or more regex find/replace edits to an INF file **in place**.

.DESCRIPTION
This does not import/apply policy. It only edits the given INF so you can batch multiple changes,
then call Import-LocalSecurityPolicy once.

.PARAMETER InfPath
Path to the INF file previously exported.

.PARAMETER Pattern
Single regex to replace (e.g., 'PasswordComplexity\s*=.*').

.PARAMETER Replacement
Replacement text for the single regex (e.g., 'PasswordComplexity = 1').

.PARAMETER ReplaceMap
Hashtable of multiple regex→replacement pairs to apply in one go.
Example:
    -ReplaceMap @{ 'MinimumPasswordLength\s*=.*' = 'MinimumPasswordLength = 12'
                   'PasswordHistorySize\s*=.*'   = 'PasswordHistorySize = 24' }

.EXAMPLE
Set-InfContent -InfPath $inf -Pattern 'PasswordComplexity\s*=.*' -Replacement 'PasswordComplexity = 1'

.EXAMPLE
Set-InfContent -InfPath $inf -ReplaceMap @{
  'MaximumPasswordAge\s*=.*' = 'MaximumPasswordAge = 60'
  'MinimumPasswordAge\s*=.*' = 'MinimumPasswordAge = 10'
}
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$InfPath,
        [string]$Pattern,
        [string]$Replacement,
        [hashtable]$ReplaceMap
    )

    if (-not (Test-Path $InfPath)) { throw "INF not found: $InfPath" }
    if (-not $Pattern -and -not $ReplaceMap) {
        throw "Provide either -Pattern/-Replacement or -ReplaceMap."
    }
    if ($Pattern -and -not $Replacement) {
        throw "When using -Pattern, also supply -Replacement."
    }

    $content = Get-Content -Path "$InfPath" -Raw

    if ($ReplaceMap) {
        foreach ($key in $ReplaceMap.Keys) {
            $content = [regex]::Replace($content, $key, [string]$ReplaceMap[$key])
        }
    }
    if ($Pattern) {
        $content = [regex]::Replace($content, $Pattern, $Replacement)
    }

    # Keep INF encoding friendly
    Set-Content -Path "$InfPath" -Value $content -Encoding ASCII
}

function Import-LocalSecurityPolicy {
<#
.SYNOPSIS
Import the modified INF back into local security policy and optionally clean up the INF.

.PARAMETER InfPath
Path to the edited INF file.

.PARAMETER Cleanup
If set, deletes the INF after import.

.PARAMETER Areas
SECEDIT /AREAS value. Default is SECURITYPOLICY.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$InfPath,
        [switch]$Cleanup,
        [ValidateSet('SECURITYPOLICY','REGKEYS','FILESTORE','SERVICES','GROUP_MGMT','USER_RIGHTS','KERNEL')]
        [string]$Areas = 'SECURITYPOLICY'
    )

    if (-not (Test-Path $InfPath)) { throw "INF not found: $InfPath" }

    # /overwrite avoids prompts; import targeted area(s)
    secedit /configure /db "$env:WINDIR\security\local.sdb" /cfg "$InfPath" /overwrite /areas $Areas | Out-Null

    if ($Cleanup) {
        Remove-Item -Path "$InfPath" -Force -ErrorAction SilentlyContinue
    }
}
