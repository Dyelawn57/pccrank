# PCCrank
Keep your PC Cranked. Forever.

**[⬇️ Download PCCrank.exe](https://github.com/Dyelawn57/pccrank/releases/latest/download/PCCrank.exe)**

A Windows tool that prevents your PC from ever sleeping, hibernating, or shutting down.

## Usage
1. Download `PCCrank.exe` from the link above
2. Run as Administrator
3. Select Local or Remote target
4. Click **CRANK**

## ⚠️ Warning
This tool applies **irreversible** changes. Reversal may require Safe Mode or recovery media.

## Building from Source
Requires PowerShell 5+ and PS2EXE module.

```powershell
Install-Module ps2exe -Scope CurrentUser -Force
Invoke-PS2EXE -InputFile src\PCCrank.ps1 -OutputFile PCCrank.exe -NoConsole -RequireAdmin
```
