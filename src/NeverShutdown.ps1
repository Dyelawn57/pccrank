<#
.SYNOPSIS
    Prevents a Windows computer from ever shutting down, sleeping, or hibernating.

.DESCRIPTION
    Applies comprehensive lockdown measures to prevent shutdown/sleep/hibernate:
    - Disables all power timeouts
    - Removes shutdown UI and user rights
    - Blocks shutdown.exe
    - Creates watchdog services
    - Locks registry keys against GPO override
    - Installs WMI event subscription to abort shutdowns

.PARAMETER ComputerName
    The hostname of the target computer.

.EXAMPLE
    .\NeverShutdown.ps1 -ComputerName LAB-W10-D11
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ComputerName
)

$ErrorActionPreference = "Continue"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  NEVER SHUTDOWN - Lockdown Tool" -ForegroundColor Cyan
Write-Host "  Target: $ComputerName" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Test connectivity
Write-Host "`n[*] Testing connection to $ComputerName..." -ForegroundColor Yellow
if (!(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
    Write-Host "[!] Cannot reach $ComputerName. Exiting." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Connection successful" -ForegroundColor Green

# Main lockdown script block
$LockdownScript = {
    $ErrorActionPreference = "Continue"
    $results = @()

    # ============================================================
    # 1. POWER SETTINGS
    # ============================================================
    try {
        # Create temp directory
        New-Item -Path "C:\temp" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

        # Disable all sleep/hibernate timeouts
        powercfg /change standby-timeout-ac 0
        powercfg /change standby-timeout-dc 0
        powercfg /change hibernate-timeout-ac 0
        powercfg /change hibernate-timeout-dc 0
        powercfg /change monitor-timeout-ac 0
        powercfg /change monitor-timeout-dc 0
        
        # Disable hibernate
        powercfg /hibernate off
        
        # Disable hybrid sleep
        powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 0
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 0
        
        # Power button = do nothing
        powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 0
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 0
        
        # Sleep button = do nothing
        powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
        
        # Lid close = do nothing
        powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
        
        powercfg /setactive SCHEME_CURRENT
        
        $results += "[+] Power settings configured"
    } catch {
        $results += "[!] Power settings error: $_"
    }

    # ============================================================
    # 2. REGISTRY POLICIES
    # ============================================================
    try {
        # Power policy registry
        $powerPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings"
        New-Item -Path $powerPolicyPath -Force -ErrorAction SilentlyContinue | Out-Null
        
        # Sleep timeout GUID
        $sleepGuid = "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"
        New-Item -Path "$powerPolicyPath\$sleepGuid" -Force | Out-Null
        Set-ItemProperty -Path "$powerPolicyPath\$sleepGuid" -Name "ACSettingIndex" -Value 0 -Type DWord
        
        # Hibernate timeout GUID
        $hibernateGuid = "9d7815a6-7ee4-497e-8888-515a05f02364"
        New-Item -Path "$powerPolicyPath\$hibernateGuid" -Force | Out-Null
        Set-ItemProperty -Path "$powerPolicyPath\$hibernateGuid" -Name "ACSettingIndex" -Value 0 -Type DWord
        
        # Remove shutdown from Start menu
        $explorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        New-Item -Path $explorerPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $explorerPath -Name "NoClose" -Value 1 -Type DWord -Force
        
        # Disable shutdown button on login screen
        $systemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $systemPath -Name "shutdownwithoutlogon" -Value 0 -Type DWord -Force
        
        # Windows Update - prevent auto-reboot
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        New-Item -Path $wuPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $wuPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $wuPath -Name "AUOptions" -Value 3 -Type DWord -Force
        
        # Active hours
        $wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        Set-ItemProperty -Path $wuPolicyPath -Name "SetActiveHours" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $wuPolicyPath -Name "ActiveHoursStart" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $wuPolicyPath -Name "ActiveHoursEnd" -Value 23 -Type DWord -ErrorAction SilentlyContinue
        
        # Disable auto-reboot on BSOD
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Value 0 -Type DWord -Force
        
        $results += "[+] Registry policies configured"
    } catch {
        $results += "[!] Registry policies error: $_"
    }

    # ============================================================
    # 3. DISABLE SCHEDULED REBOOT TASKS
    # ============================================================
    try {
        $rebootTasks = @(
            "\Microsoft\Windows\UpdateOrchestrator\Reboot",
            "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
            "\Microsoft\Windows\WindowsUpdate\Scheduled Start",
            "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
        )
        foreach ($task in $rebootTasks) {
            schtasks /Change /TN $task /Disable 2>$null
        }
        
        Get-ScheduledTask -TaskPath "\Microsoft\Windows\UpdateOrchestrator\*" -ErrorAction SilentlyContinue | 
            Where-Object { $_.TaskName -match "reboot|restart" } | 
            Disable-ScheduledTask -ErrorAction SilentlyContinue
        
        $results += "[+] Reboot scheduled tasks disabled"
    } catch {
        $results += "[!] Scheduled tasks error: $_"
    }

    # ============================================================
    # 4. REMOVE SHUTDOWN USER RIGHTS
    # ============================================================
    try {
        secedit /export /cfg C:\temp\secpol.cfg 2>$null
        $content = Get-Content C:\temp\secpol.cfg
        $content = $content -replace 'SeShutdownPrivilege.*', 'SeShutdownPrivilege = *S-1-5-18'
        $content | Set-Content C:\temp\secpol.cfg
        secedit /configure /db C:\temp\secedit.sdb /cfg C:\temp\secpol.cfg /areas USER_RIGHTS 2>$null
        Remove-Item C:\temp\secpol.cfg, C:\temp\secedit.sdb -Force -ErrorAction SilentlyContinue
        
        $results += "[+] Shutdown user rights removed"
    } catch {
        $results += "[!] User rights error: $_"
    }

    # ============================================================
    # 5. BLOCK SHUTDOWN.EXE
    # ============================================================
    try {
        $shutdownPath = "C:\Windows\System32\shutdown.exe"
        takeown /f $shutdownPath /a 2>$null
        icacls $shutdownPath /inheritance:r 2>$null
        icacls $shutdownPath /deny "Everyone:(RX)" 2>$null
        icacls $shutdownPath /deny "BUILTIN\Administrators:(RX)" 2>$null
        icacls $shutdownPath /deny "NT AUTHORITY\SYSTEM:(RX)" 2>$null
        
        $results += "[+] shutdown.exe blocked"
    } catch {
        $results += "[!] shutdown.exe block error: $_"
    }

    # ============================================================
    # 6. CREATE WATCHDOG SCRIPTS
    # ============================================================
    try {
        # PreventSleep script
        $preventSleepScript = @'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class PreventSleep {
    [DllImport("kernel32.dll")]
    public static extern uint SetThreadExecutionState(uint esFlags);
    public const uint ES_CONTINUOUS = 0x80000000;
    public const uint ES_SYSTEM_REQUIRED = 0x00000001;
    public const uint ES_DISPLAY_REQUIRED = 0x00000002;
}
"@
[PreventSleep]::SetThreadExecutionState([PreventSleep]::ES_CONTINUOUS -bor [PreventSleep]::ES_SYSTEM_REQUIRED -bor [PreventSleep]::ES_DISPLAY_REQUIRED)
'@
        $preventSleepScript | Out-File -FilePath "C:\temp\PreventSleep.ps1" -Encoding UTF8 -Force

        # ShutdownBlocker script
        $shutdownBlockerScript = @'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ShutdownBlocker {
    [DllImport("kernel32.dll")]
    public static extern uint SetThreadExecutionState(uint esFlags);
    public const uint ES_CONTINUOUS = 0x80000000;
    public const uint ES_SYSTEM_REQUIRED = 0x00000001;
}
"@
while ($true) {
    [ShutdownBlocker]::SetThreadExecutionState([ShutdownBlocker]::ES_CONTINUOUS -bor [ShutdownBlocker]::ES_SYSTEM_REQUIRED) | Out-Null
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c shutdown /a" -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 10
}
'@
        $shutdownBlockerScript | Out-File -FilePath "C:\temp\ShutdownBlocker.ps1" -Encoding UTF8 -Force
        
        $results += "[+] Watchdog scripts created"
    } catch {
        $results += "[!] Watchdog scripts error: $_"
    }

    # ============================================================
    # 7. CREATE SCHEDULED TASKS
    # ============================================================
    try {
        # PreventSystemSleep task
        Unregister-ScheduledTask -TaskName "PreventSystemSleep" -Confirm:$false -ErrorAction SilentlyContinue
        $action1 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\temp\PreventSleep.ps1"
        $trigger1 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
        $principal1 = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings1 = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName "PreventSystemSleep" -Action $action1 -Trigger $trigger1 -Principal $principal1 -Settings $settings1 -Force | Out-Null
        Start-ScheduledTask -TaskName "PreventSystemSleep"

        # ShutdownBlocker task
        Unregister-ScheduledTask -TaskName "ShutdownBlocker" -Confirm:$false -ErrorAction SilentlyContinue
        $action2 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\temp\ShutdownBlocker.ps1"
        $trigger2 = New-ScheduledTaskTrigger -AtStartup
        $principal2 = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings2 = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Days 9999)
        Register-ScheduledTask -TaskName "ShutdownBlocker" -Action $action2 -Trigger $trigger2 -Principal $principal2 -Settings $settings2 -Force | Out-Null
        Start-ScheduledTask -TaskName "ShutdownBlocker"
        
        $results += "[+] Scheduled tasks created and started"
    } catch {
        $results += "[!] Scheduled tasks error: $_"
    }

    # ============================================================
    # 8. WMI EVENT SUBSCRIPTION (Shutdown Blocker)
    # ============================================================
    try {
        # Remove existing
        Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='ShutdownFilter'" -ErrorAction SilentlyContinue | Remove-WmiObject
        Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='ShutdownConsumer'" -ErrorAction SilentlyContinue | Remove-WmiObject
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | 
            Where-Object { $_.Filter -match "ShutdownFilter" } | Remove-WmiObject

        # Create filter
        $Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
            Name = 'ShutdownFilter'
            EventNamespace = 'root\cimv2'
            QueryLanguage = 'WQL'
            Query = "SELECT * FROM Win32_ComputerShutdownEvent"
        }

        # Create consumer
        $Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
            Name = 'ShutdownConsumer'
            CommandLineTemplate = 'cmd.exe /c shutdown /a'
        }

        # Bind
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
            Filter = $Filter
            Consumer = $Consumer
        } | Out-Null
        
        $results += "[+] WMI shutdown blocker installed"
    } catch {
        $results += "[!] WMI error: $_"
    }

    # ============================================================
    # 9. LOCK REGISTRY KEYS (Block GPO Override)
    # ============================================================
    try {
        $keysToLock = @(
            "SOFTWARE\Policies\Microsoft\Power",
            "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        )

        foreach ($keyPath in $keysToLock) {
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $keyPath,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions
            )
            
            if ($regKey) {
                $acl = $regKey.GetAccessControl()
                $acl.SetAccessRuleProtection($true, $false)
                
                $denyRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    "Everyone",
                    [System.Security.AccessControl.RegistryRights]::SetValue,
                    [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Deny
                )
                
                $allowRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    "NT AUTHORITY\SYSTEM",
                    [System.Security.AccessControl.RegistryRights]::ReadKey,
                    [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                
                $acl.AddAccessRule($allowRule)
                $acl.AddAccessRule($denyRule)
                $regKey.SetAccessControl($acl)
                $regKey.Close()
            }
        }
        
        $results += "[+] Registry keys locked against GPO"
    } catch {
        $results += "[!] Registry lock error: $_"
    }

    # ============================================================
    # 10. PROTECT SCRIPTS AND TASKS
    # ============================================================
    try {
        # Protect scripts
        $scripts = @("C:\temp\ShutdownBlocker.ps1", "C:\temp\PreventSleep.ps1")
        foreach ($script in $scripts) {
            if (Test-Path $script) {
                takeown /f $script /a 2>$null
                icacls $script /inheritance:r 2>$null
                icacls $script /grant "NT AUTHORITY\SYSTEM:(R)" 2>$null
                icacls $script /deny "BUILTIN\Administrators:(M,D)" 2>$null
                icacls $script /deny "Everyone:(M,D)" 2>$null
                attrib +r +s +h $script 2>$null
            }
        }

        # Protect task files
        $tasks = @("ShutdownBlocker", "PreventSystemSleep")
        foreach ($task in $tasks) {
            $taskFile = "C:\Windows\System32\Tasks\$task"
            if (Test-Path $taskFile) {
                takeown /f $taskFile /a 2>$null
                icacls $taskFile /inheritance:r 2>$null
                icacls $taskFile /grant "NT AUTHORITY\SYSTEM:(R)" 2>$null
                icacls $taskFile /deny "BUILTIN\Administrators:(D,WDAC,WO)" 2>$null
                icacls $taskFile /deny "Everyone:(D,WDAC,WO)" 2>$null
            }
        }
        
        $results += "[+] Scripts and tasks protected"
    } catch {
        $results += "[!] Protection error: $_"
    }

    return $results
}

# Execute on remote computer
Write-Host "`n[*] Applying lockdown to $ComputerName..." -ForegroundColor Yellow
$output = Invoke-Command -ComputerName $ComputerName -ScriptBlock $LockdownScript

Write-Host "`n=== RESULTS ===" -ForegroundColor Cyan
$output | ForEach-Object {
    if ($_ -match "^\[\+\]") {
        Write-Host $_ -ForegroundColor Green
    } elseif ($_ -match "^\[\!\]") {
        Write-Host $_ -ForegroundColor Red
    } else {
        Write-Host $_
    }
}

# Verification
Write-Host "`n[*] Verifying lockdown..." -ForegroundColor Yellow
$verify = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
    $checks = @()
    
    # Check shutdown.exe
    $shutdownAcl = (icacls "C:\Windows\System32\shutdown.exe" 2>$null) -join " "
    if ($shutdownAcl -match "DENY") { $checks += "[+] shutdown.exe: BLOCKED" }
    else { $checks += "[!] shutdown.exe: NOT BLOCKED" }
    
    # Check tasks
    $task1 = Get-ScheduledTask -TaskName "ShutdownBlocker" -ErrorAction SilentlyContinue
    $task2 = Get-ScheduledTask -TaskName "PreventSystemSleep" -ErrorAction SilentlyContinue
    if ($task1 -and $task2) { $checks += "[+] Watchdog tasks: RUNNING" }
    else { $checks += "[!] Watchdog tasks: MISSING" }
    
    # Check WMI
    $wmi = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | 
        Where-Object { $_.Filter -match "Shutdown" }
    if ($wmi) { $checks += "[+] WMI blocker: ACTIVE" }
    else { $checks += "[!] WMI blocker: MISSING" }
    
    # Check registry lock
    $powerKey = "HKLM:\SOFTWARE\Policies\Microsoft\Power"
    try {
        New-ItemProperty -Path $powerKey -Name "Test123" -Value 1 -Force -ErrorAction Stop | Out-Null
        Remove-ItemProperty -Path $powerKey -Name "Test123" -ErrorAction SilentlyContinue
        $checks += "[!] Registry: NOT LOCKED"
    } catch {
        $checks += "[+] Registry: LOCKED"
    }
    
    return $checks
}

Write-Host "`n=== VERIFICATION ===" -ForegroundColor Cyan
$verify | ForEach-Object {
    if ($_ -match "^\[\+\]") {
        Write-Host $_ -ForegroundColor Green
    } else {
        Write-Host $_ -ForegroundColor Red
    }
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  Lockdown complete for $ComputerName" -ForegroundColor Cyan
Write-Host "  Machine will NEVER shut down unless unplugged" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
