# Windows Hardening – Entry Script (Menu + Orchestration)

# --- Self-elevate if not running as Administrator ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $psExe = (Get-Process -Id $PID).Path
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    if (-not $scriptPath) { Write-Error "This script must be run from a file, not pasted interactively."; exit 1 }
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $scriptPath))
    Start-Process -FilePath $psExe -ArgumentList $args -Verb RunAs | Out-Null
    exit
}

# --- Load config and includes ---
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Root 'config.ps1')

$IncludeDir = Join-Path $Root 'includes'
Get-ChildItem $IncludeDir -Filter '*.ps1' | Sort-Object Name | ForEach-Object { . $_.FullName }

# --- Persisted state (robust) ---
$StatePath = Join-Path $Root 'state.json'

# Use script: scope so helpers/submenus see the same hashtable
if (Test-Path $StatePath) {
    try {
        # -Raw for full text; -AsHashtable for native hashtable (avoids PSCustomObject/null surprises)
        $script:completedTasks = Get-Content $StatePath -Raw | ConvertFrom-Json -AsHashtable
        if (-not $script:completedTasks) { $script:completedTasks = @{} }
    } catch {
        $script:completedTasks = @{}
    }
} else {
    $script:completedTasks = @{}
}

# Seed defaults on first run so all lookups are boolean
if (-not $script:completedTasks.Count) {
    $script:completedTasks = @{
        '1'=$false;  '2'=$false;  '3'=$false;  '4'=$false;  '5'=$false;  '6'=$false;  '7'=$false;
        '8'=$false;  '9'=$false; '10'=$false; '11'=$false; '12'=$false; '13'=$false;
        'app1'=$false; 'app2'=$false; 'app3'=$false; 'app4'=$false; 'app5'=$false; 'app6'=$false; 'app7'=$false
    }
}

function Save-State {
    param($State)
    $State | ConvertTo-Json -Depth 5 | Set-Content -Path $StatePath -Encoding UTF8
}

# --- Menu helpers ---
function Write-MenuItem {
    param(
        [int]$Number,
        [string]$Text,
        [AllowNull()][object]$Executed  # tolerate null/"" coming from JSON or missing keys
    )
    $done  = [bool]$Executed
    $color = if ($done) { 'Green' } else { 'White' }
    Write-Host ("{0}. {1}" -f $Number, $Text) -ForegroundColor $color
}

# Convenience getter to ensure a true boolean is used
function Get-Done {
    param([string]$Key)
    return [bool]($script:completedTasks[$Key])
}

# --- App Security submenu (delegates to include-defined secure functions) ---
function Show-AppSecurityMenu {
    param([hashtable]$Config)

    while ($true) {
        Write-Host "`nApplication Security Menu" -ForegroundColor Cyan
        Write-MenuItem 1 "Secure Firefox" (Get-Done 'app1')
        Write-MenuItem 2 "Secure Chrome"  (Get-Done 'app2')
        Write-MenuItem 3 "Secure RDP"     (Get-Done 'app3')
        Write-MenuItem 4 "Secure SMB"     (Get-Done 'app4')
        Write-MenuItem 5 "Secure DNS"     (Get-Done 'app5')
        Write-MenuItem 6 "Secure SSH"     (Get-Done 'app6')
        Write-MenuItem 7 "Secure IIS"     (Get-Done 'app7')
        Write-MenuItem 8 "Return to Main Menu" $false

        $appChoice = Read-Host "`nPlease enter your choice"
        switch ($appChoice) {
            '1' { Secure-Firefox -Config $Config; $script:completedTasks['app1'] = $true }
            '2' { Secure-Chrome  -Config $Config; $script:completedTasks['app2'] = $true }
            '3' { Secure-RDP     -Config $Config; $script:completedTasks['app3'] = $true }
            '4' { Secure-SMB     -Config $Config; $script:completedTasks['app4'] = $true }
            '5' { Secure-DNS     -Config $Config; $script:completedTasks['app5'] = $true }
            '6' { Secure-SSH     -Config $Config; $script:completedTasks['app6'] = $true }
            '7' { Secure-IIS     -Config $Config; $script:completedTasks['app7'] = $true }
            '8' { return }
            default { Write-Host "Invalid option." -ForegroundColor Red }
        }
        Save-State $script:completedTasks
    }
}

# --- Main menu loop ---
:MainMenu while ($true) {
    Write-Host "`nSecurity Hardening Script Menu" -ForegroundColor Cyan
    Write-MenuItem 1  "Document System"                (Get-Done '1')
    Write-MenuItem 2  "OS Updates"                     (Get-Done '2')
    Write-MenuItem 3  "User Auditing"                  (Get-Done '3')
    Write-MenuItem 4  "Account Policy"                 (Get-Done '4')
    Write-MenuItem 5  "Local Policy"                   (Get-Done '5')
    Write-MenuItem 6  "Defensive Countermeasures"      (Get-Done '6')
    Write-MenuItem 7  "Uncategorized OS Settings"      (Get-Done '7')
    Write-MenuItem 8  "Service Auditing"               (Get-Done '8')
    Write-MenuItem 9  "Application Updates"            (Get-Done '9')
    Write-MenuItem 10 "Prohibited Files"               (Get-Done '10')
    Write-MenuItem 11 "Unwanted Software"              (Get-Done '11')
    Write-MenuItem 12 "Malware"                        (Get-Done '12')
    Write-MenuItem 13 "Application Security (submenu)" (Get-Done '13')
    Write-MenuItem 14 "Exit"                           $false

    $choice = Read-Host "`nPlease enter your choice"
    switch ($choice) {
        '1'  { Invoke-DocumentSystem          -Config $GV; $script:completedTasks['1']  = $true }
        '2'  { Invoke-OSUpdates               -Config $GV; $script:completedTasks['2']  = $true }
        '3'  { Invoke-UserAuditing            -Config $GV; $script:completedTasks['3']  = $true }
        '4'  { Invoke-AccountPolicy           -Config $GV; $script:completedTasks['4']  = $true }
        '5'  { Invoke-LocalPolicy             -Config $GV; $script:completedTasks['5']  = $true }
        '6'  { Invoke-DefensiveCountermeasures -Config $GV; $script:completedTasks['6'] = $true }
        '7'  { Invoke-UncategorizedOS         -Config $GV; $script:completedTasks['7']  = $true }
        '8'  { Invoke-ServiceAuditing         -Config $GV; $script:completedTasks['8']  = $true }
        '9'  { Invoke-ApplicationUpdates      -Config $GV; $script:completedTasks['9']  = $true }
        '10' { Invoke-ProhibitedFiles         -Config $GV; $script:completedTasks['10'] = $true }
        '11' { Invoke-UnwantedSoftware        -Config $GV; $script:completedTasks['11'] = $true }
        '12' { Invoke-Malware                 -Config $GV; $script:completedTasks['12'] = $true }
        '13' { Show-AppSecurityMenu           -Config $GV; $script:completedTasks['13'] = $true }
        '14' { Save-State $script:completedTasks; break MainMenu }
        default { Write-Host "Invalid option." -ForegroundColor Red }
    }
    Save-State $script:completedTasks
}
