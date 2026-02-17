# PCCrank
Keep your PC Cranked. Forever.

**[⬇️ Download PCCrank.exe](https://github.com/Dyelawn57/pccrank/releases/latest/download/PCCrank.exe)**

A Windows tool that prevents a PC from ever sleeping, hibernating, or shutting down. Works on the local machine or remote targets over the network.

## Features
- **Local or Remote** — Target the local machine or any remote Windows PC by hostname
- **Comprehensive lockdown** — Disables sleep, hibernate, shutdown, and automatic restarts at multiple levels (power settings, registry, scheduled tasks, user rights, and more)
- **Overrides Group Policy** — Locks registry keys to prevent GPO from reverting changes
- **Portable** — Single .exe, no installation required

## Requirements
- Windows 10/11 or Windows Server
- Run as Administrator
- **For remote targets:** PowerShell Remoting must be enabled on the target machine (`Enable-PSRemoting -Force`)

## Usage
1. Download `PCCrank.exe` from the link above
2. Run as Administrator
3. Select **Local** or **Remote** target (enter hostname if remote)
4. Click **CRANK**
5. **Reboot the target machine** for changes to take full effect

## How It Works
PCCrank applies 10 layers of lockdown:
1. Power settings (powercfg)
2. Registry policies for power, Windows Update, and Explorer
3. Disables scheduled reboot tasks
4. Removes shutdown user rights (secedit)
5. Blocks shutdown.exe with deny ACLs
6. Creates watchdog scripts to prevent sleep
7. Scheduled tasks to run watchdog scripts
8. WMI event subscription to abort shutdown attempts
9. Locks registry keys against Group Policy override
10. Protects scripts and task files from modification

## Limitations
This tool cannot prevent:
- Physical power button hold (4+ seconds)
- Power loss / unplugging
- Hardware failure or BSOD
- Hypervisor-level shutdown (if running as a VM)

## ⚠️ Warning
- This tool applies **irreversible** changes. Reversal requires Safe Mode or recovery media.
- **Test on a non-production machine first.**
- In domain environments, this will override Group Policy
- Use at your own risk.

## Building from Source
Requires PowerShell 5+ and PS2EXE module.

```powershell
Install-Module ps2exe -Scope CurrentUser -Force
Invoke-PS2EXE -InputFile src\PCCrank.ps1 -OutputFile PCCrank.exe -NoConsole -RequireAdmin
```
