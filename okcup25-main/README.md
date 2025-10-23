
# Windows Hardening – Teaching Template (PowerShell)

This repository is a **template** for students to learn Windows hardening with a guided, menu‑driven PowerShell script.
- The **entry point** is `harden.ps1`.
- All configurable values live in `config.ps1`.
- All student work happens in `includes\` files (one per category).

## How to use as a Template Repository
1. On GitHub, go to **Settings → Template repository** and enable it.
2. Students click **Use this template → Create a new repository** to get their own copy.
3. They clone their copy and work locally.

## Quick start (local)
```powershell
git clone <your-student-repo-url>.git
cd WindowsHardening-Starter
# Optional: allow script this session only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
# Unblock if downloaded from the web
Get-ChildItem -Recurse *.ps1 | Unblock-File
# Run
.\harden.ps1
```

## Project layout
```
WindowsHardening-Starter/
│  harden.ps1           # Entry point: elevation guard, config, includes, menu
│  config.ps1           # Global settings & logging helper
│  state.json           # Run state for menu completion (auto-created)
│  README.md            # This file
│  LICENSE              # MIT license
│  .editorconfig        # Basic whitespace/indent settings
│  .gitignore           # Common ignores
└─ includes/            # One include per category (student work)
   │  01-DocumentSystem.ps1
   │  02-OSUpdates.ps1
   │  03-UserAuditing.ps1
   │  04-AccountPolicy.ps1
   │  05-LocalPolicy.ps1
   │  06-DefensiveCountermeasures.ps1
   │  07-UncategorizedOS.ps1
   │  08-ServiceAuditing.ps1
   │  09-ApplicationUpdates.ps1
   │  10-ProhibitedFiles.ps1
   │  11-UnwantedSoftware.ps1
   │  12-Malware.ps1
   │  13-ApplicationSecurity.ps1
   └─ _Template.ps1
```

## Teaching approach
Each include file exposes a single **entry function** (`Invoke-<Category>`) and contains multiple **student tasks** with:
- A short explanation of the control/policy
- An **AI prompt** students can paste to generate a starting point
- A TODO section where students paste/author code
- Required patterns: idempotence, `-WhatIf`, `-Verbose`, and logging to `LogPath`

## Notes
- Keep orchestrator files (`harden.ps1`, `config.ps1`) unchanged so grading stays consistent.
- Execution Policy for lab boxes can be pre‑set by instructors; students can use Process‑scope bypass as above.
