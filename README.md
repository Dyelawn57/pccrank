# PCCrank
Keep your PC Cranked. Forever.

This repo contains PowerShell scripts and a GUI to harden Windows against sleep/hibernate/shutdown. Use with care.

## Folders
- src/ — PowerShell sources (PCCrank.ps1, GUI script, helpers)
- ssets/ — icons/images (not required to run)
- dist/ — optional compiled EXEs (ignored by git by default)

## Build
Requires PowerShell 5+ and PS2EXE module.

`powershell
Install-Module ps2exe -Scope CurrentUser -Force
# GUI build (outputs to dist)
 = Join-Path  'src\PCCrank_v2.ps1'
 = Join-Path  'dist\PCCrank.exe'
Invoke-PS2EXE -InputFile  -OutputFile  -NoConsole -Title 'PCCrank' -RequireAdmin
`

## WARNING
Reversing the lockdown may require Safe Mode or recovery media.
