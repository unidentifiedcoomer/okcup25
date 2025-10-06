#
function Invoke-ApplicationUpdates {
    param([hashtable]$Config)

    if ($Config.Verbose) { Write-Host "[ApplicationUpdates] Starting..." -ForegroundColor Cyan }

    # Student tasks (call your task functions here)
    # Example:
    # Set-ApplicationUpdates-Setting1 -Config $Config -WhatIf:$Config.WhatIf -Verbose:$Config.Verbose
    # Set-ApplicationUpdates-Setting2 -Config $Config -WhatIf:$Config.WhatIf -Verbose:$Config.Verbose

    if ($Config.Verbose) { Write-Host "[ApplicationUpdates] Complete." -ForegroundColor Cyan }
}

function Set-ApplicationUpdates-Setting1 {
<#
.SYNOPSIS
First task in ApplicationUpdates.

.EXPLANATION
Describe what and why this setting matters.

.AI_PROMPT
Write PowerShell that enforces <policy> for ApplicationUpdates. Idempotent; respect -WhatIf/-Verbose; log via Write-Log.
#>
    param([hashtable]$Config, [switch]$WhatIf, [switch]$Verbose)
    # TODO
}

function Set-ApplicationUpdates-Setting2 {
<#
.SYNOPSIS
Second task in ApplicationUpdates.

.AI_PROMPT
Given a hashtable $Config, write an idempotent function to enforce <policy>. Use Write-Log.
#>
    param([hashtable]$Config, [switch]$WhatIf, [switch]$Verbose)
    # TODO
}
