# includes\11-UnwantedSoftware.ps1
# Unwanted Software � PROVIDED SOLUTION

function Invoke-UnwantedSoftware {
    param([hashtable]$Config)

    Write-Host "[Unwanted Software] Start" -ForegroundColor Cyan
    US-Interactive-Uninstall -Config $Config
    Write-Host "[Unwanted Software] Done" -ForegroundColor Cyan
}

function US-Interactive-Uninstall {
    param([hashtable]$Config)

    # Collect installed program entries (64-bit, 32-bit, and current user)
    $entries = @(
        Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
        Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
    ) | Where-Object {
        $_.DisplayName -and $_.DisplayName.Trim() -ne '' -and $_.Publisher -ne 'Microsoft Corporation'
    }

    # De-duplicate by DisplayName to reduce noise
    $programs = $entries | Sort-Object DisplayName -Unique

    foreach ($program in $programs) {
        Write-Host "Program: $($program.DisplayName)" -ForegroundColor Cyan
        if ($program.Publisher) { Write-Host "Publisher: $($program.Publisher)" }
        if ($program.DisplayVersion) { Write-Host "Version: $($program.DisplayVersion)" }

        $response = Read-Host "Do you want to uninstall this program? (y/N)"
        if ($response -notmatch '^(y|Y)$') {
            Write-Host "Skipping $($program.DisplayName)."
            continue
        }

        if (-not $program.UninstallString) {
            Write-Host "No uninstall command found for $($program.DisplayName)." -ForegroundColor Yellow
            continue
        }

        try {
            Invoke-UninstallString -UninstallString $program.UninstallString
            Write-Host "$($program.DisplayName) uninstall initiated." -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to uninstall $($program.DisplayName): $_"
        }
    }
}

function Invoke-UninstallString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UninstallString
    )

    $s = $UninstallString.Trim()

    # Handle MSI uninstalls: normalize to /x {GUID} /qn /norestart
    if ($s -match '(?i)msiexec(\.exe)?\s+/[IX]\s*{([0-9A-F\-]{36})}') {
        $guid = $Matches[2]
        Start-Process -FilePath 'msiexec.exe' -ArgumentList "/x {$guid} /qn /norestart" -Wait
        return
    }

    # Parse EXE path + args (handles quoted and unquoted forms)
    $exe = $null; $args = $null
    if ($s -match '^\s*"(.*?)"\s*(.*)$') {
        $exe  = $Matches[1]
        $args = $Matches[2]
    } elseif ($s -match '^\s*(\S+)\s*(.*)$') {
        $exe  = $Matches[1]
        $args = $Matches[2]
    }

    if (-not $exe) {
        # Fallback: let cmd parse the string
        Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $s" -Wait
        return
    }

    # Rundll-style uninstallers: execute as-is via cmd to avoid quoting issues
    if ($exe -match '(?i)\\?rundll32\.exe$') {
        Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $s" -Wait
        return
    }

    # If no quiet/silent flag present, add a common quiet switch
    if ($args -notmatch '(?i)(/quiet|/qn|/s(?!r)|/silent)') {
        $args = ($args + ' /quiet').Trim()
    }

    Start-Process -FilePath $exe -ArgumentList $args -Wait
}
