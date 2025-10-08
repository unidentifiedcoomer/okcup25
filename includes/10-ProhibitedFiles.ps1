# includes\10-ProhibitedFiles.ps1
# Prohibited Files � STUBS ONLY (no working commands included)

function Invoke-ProhibitedFiles {
    param([hashtable]$Config)

    Write-Host "[Prohibited Files] Start" -ForegroundColor Cyan
    
    PF-Remove-ProhibitedExtensions -Config $Config

    Write-Host "[Prohibited Files] Done" -ForegroundColor Cyan
}

function PF-Remove-ProhibitedExtensions {
<#
.EXPLANATION
Loop over $Config.ProhibitedExtensions, search C:\ recursively, and remove matching files.
Print progress and handle errors so the loop continues.

.AI_PROMPT
Return only PowerShell code (no markdown, no comments, no extra text). Define a function named
PF-Remove-ProhibitedExtensions with this signature:

param([hashtable]$Config)

Behavior requirements:
- Read the array $Config.ProhibitedExtensions.
- If it is null or empty, print "No prohibited extensions configured." and return.
- For each extension in the array:
  - Print a progress line: Searching for files with extension <ext> in C:\...
  - Recursively search under C:\ for matching **files** only.
  - For each match, print "Removing file: <full path>" and delete it.
  - Use try/catch so failures (e.g., access denied) do not stop the loop.
- Suppress noisy errors on enumeration and deletion so the loop continues:
  - Enumeration uses an error-suppression approach.
  - Deletion uses an error-suppression approach.
- Keep the implementation simple (no idempotence, no logging beyond Write-Host).

Constraints:
- Use built-in PowerShell cmdlets only.
- Do not hardcode the list of extensions; use $Config.ProhibitedExtensions.
- Target drive root C:\.
- Produce a single function that performs the whole task.

#>
    param([hashtable]$Config)
    if (-not $Config.ProhibitedExtensions -or $Config.ProhibitedExtensions.Count -eq 0) {
Write-Host "No prohibited extensions configured."
return
}
foreach ($ext in $Config.ProhibitedExtensions) {
Write-Host "Searching for files with extension $ext in C:..."
try {
$files = Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq $ext }
foreach ($file in $files) {
try {
Write-Host "Removing file: $($file.FullName)"
Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
} catch {}
}
} catch {}
}
}
