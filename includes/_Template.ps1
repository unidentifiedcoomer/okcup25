#
# Include File Template
# Exposes: Invoke-CategoryName
# Student tasks live as functions with EXPLANATION and AI_PROMPT blocks.

function Invoke-CategoryName {
    param([hashtable]$Config)

    if ($Config.Verbose) { Write-Host "[CategoryName] Starting..." -ForegroundColor Cyan }

    # TODO: Call your student task functions here
    # Example:
    # Set-CategoryName-Setting1 -Config $Config -WhatIf:$Config.WhatIf -Verbose:$Config.Verbose

    if ($Config.Verbose) { Write-Host "[CategoryName] Complete." -ForegroundColor Cyan }
}

function Set-CategoryName-Setting1 {
<#
.SYNOPSIS
Student task 1 for this category.

.EXPLANATION
Explain the Windows security rationale in 2–3 lines.

.AI_PROMPT
Write PowerShell that <describe requirement>. Prefer built-in cmdlets; fall back to registry edits if needed.
Make it idempotent, respect -WhatIf and -Verbose, and log to $Config.LogPath.
#>
    param([hashtable]$Config, [switch]$WhatIf, [switch]$Verbose)

    # TODO: Student inserts code below.
    # REQUIREMENTS:
    # - Check current state first
    # - Only change when needed
    # - Use Write-Log for each action
}
