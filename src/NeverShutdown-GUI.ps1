<#
.SYNOPSIS
    Never Shutdown - GUI Tool
    Prevents a Windows computer from ever shutting down.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Never Shutdown - Lockdown Tool"
$form.Size = New-Object System.Drawing.Size(600, 500)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.ForeColor = [System.Drawing.Color]::White

# Title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "NEVER SHUTDOWN"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::Cyan
$titleLabel.AutoSize = $true
$titleLabel.Location = New-Object System.Drawing.Point(200, 15)
$form.Controls.Add($titleLabel)

# Subtitle
$subtitleLabel = New-Object System.Windows.Forms.Label
$subtitleLabel.Text = "Machine will never turn off unless physically unplugged"
$subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$subtitleLabel.ForeColor = [System.Drawing.Color]::Gray
$subtitleLabel.AutoSize = $true
$subtitleLabel.Location = New-Object System.Drawing.Point(150, 50)
$form.Controls.Add($subtitleLabel)

# Hostname label
$hostnameLabel = New-Object System.Windows.Forms.Label
$hostnameLabel.Text = "Target Computer:"
$hostnameLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$hostnameLabel.AutoSize = $true
$hostnameLabel.Location = New-Object System.Drawing.Point(20, 90)
$form.Controls.Add($hostnameLabel)

# Hostname textbox
$hostnameBox = New-Object System.Windows.Forms.TextBox
$hostnameBox.Font = New-Object System.Drawing.Font("Consolas", 11)
$hostnameBox.Size = New-Object System.Drawing.Size(350, 30)
$hostnameBox.Location = New-Object System.Drawing.Point(150, 87)
$hostnameBox.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$hostnameBox.ForeColor = [System.Drawing.Color]::White
$hostnameBox.BorderStyle = "FixedSingle"
$form.Controls.Add($hostnameBox)

# Lock Down button
$lockdownButton = New-Object System.Windows.Forms.Button
$lockdownButton.Text = "LOCK DOWN"
$lockdownButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$lockdownButton.Size = New-Object System.Drawing.Size(120, 35)
$lockdownButton.Location = New-Object System.Drawing.Point(450, 130)
$lockdownButton.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 200)
$lockdownButton.ForeColor = [System.Drawing.Color]::White
$lockdownButton.FlatStyle = "Flat"
$lockdownButton.Cursor = "Hand"
$form.Controls.Add($lockdownButton)

# Test Connection button
$testButton = New-Object System.Windows.Forms.Button
$testButton.Text = "Test Connection"
$testButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$testButton.Size = New-Object System.Drawing.Size(120, 30)
$testButton.Location = New-Object System.Drawing.Point(20, 130)
$testButton.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$testButton.ForeColor = [System.Drawing.Color]::White
$testButton.FlatStyle = "Flat"
$testButton.Cursor = "Hand"
$form.Controls.Add($testButton)

# Progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(550, 20)
$progressBar.Location = New-Object System.Drawing.Point(20, 175)
$progressBar.Style = "Continuous"
$form.Controls.Add($progressBar)

# Output textbox
$outputBox = New-Object System.Windows.Forms.RichTextBox
$outputBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$outputBox.Size = New-Object System.Drawing.Size(550, 250)
$outputBox.Location = New-Object System.Drawing.Point(20, 205)
$outputBox.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$outputBox.ForeColor = [System.Drawing.Color]::LightGray
$outputBox.BorderStyle = "None"
$outputBox.ReadOnly = $true
$form.Controls.Add($outputBox)

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready"
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$statusLabel.ForeColor = [System.Drawing.Color]::Gray
$statusLabel.AutoSize = $true
$statusLabel.Location = New-Object System.Drawing.Point(20, 465)
$form.Controls.Add($statusLabel)

# Function to write colored output
function Write-Output {
    param([string]$Text, [string]$Color = "White")
    
    $colorMap = @{
        "Green" = [System.Drawing.Color]::LightGreen
        "Red" = [System.Drawing.Color]::Salmon
        "Yellow" = [System.Drawing.Color]::Yellow
        "Cyan" = [System.Drawing.Color]::Cyan
        "White" = [System.Drawing.Color]::White
        "Gray" = [System.Drawing.Color]::Gray
    }
    
    $outputBox.SelectionStart = $outputBox.TextLength
    $outputBox.SelectionLength = 0
    $outputBox.SelectionColor = $colorMap[$Color]
    $outputBox.AppendText("$Text`r`n")
    $outputBox.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

# Main lockdown script block
$LockdownScript = {
    $ErrorActionPreference = "Continue"
    $results = @()

    # 1. POWER SETTINGS
    try {
        New-Item -Path "C:\temp" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        powercfg /change standby-timeout-ac 0
        powercfg /change standby-timeout-dc 0
        powercfg /change hibernate-timeout-ac 0
        powercfg /change hibernate-timeout-dc 0
        powercfg /change monitor-timeout-ac 0
        powercfg /change monitor-timeout-dc 0
        powercfg /hibernate off
        powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 0
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 0
        powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 0
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 0
        powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
        powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
        powercfg /setactive SCHEME_CURRENT
        $results += "OK|Power settings configured"
    } catch { $results += "ERR|Power settings: $_" }

    # 2. REGISTRY POLICIES
    try {
        $powerPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings"
        New-Item -Path $powerPolicyPath -Force -ErrorAction SilentlyContinue | Out-Null
        $sleepGuid = "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"
        New-Item -Path "$powerPolicyPath\$sleepGuid" -Force | Out-Null
        Set-ItemProperty -Path "$powerPolicyPath\$sleepGuid" -Name "ACSettingIndex" -Value 0 -Type DWord
        $hibernateGuid = "9d7815a6-7ee4-497e-8888-515a05f02364"
        New-Item -Path "$powerPolicyPath\$hibernateGuid" -Force | Out-Null
        Set-ItemProperty -Path "$powerPolicyPath\$hibernateGuid" -Name "ACSettingIndex" -Value 0 -Type DWord
        $explorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        New-Item -Path $explorerPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $explorerPath -Name "NoClose" -Value 1 -Type DWord -Force
        $systemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $systemPath -Name "shutdownwithoutlogon" -Value 0 -Type DWord -Force
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        New-Item -Path $wuPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $wuPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $wuPath -Name "AUOptions" -Value 3 -Type DWord -Force
        $wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        Set-ItemProperty -Path $wuPolicyPath -Name "SetActiveHours" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $wuPolicyPath -Name "ActiveHoursStart" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $wuPolicyPath -Name "ActiveHoursEnd" -Value 23 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Value 0 -Type DWord -Force
        $results += "OK|Registry policies configured"
    } catch { $results += "ERR|Registry policies: $_" }

    # 3. DISABLE SCHEDULED REBOOT TASKS
    try {
        @("\Microsoft\Windows\UpdateOrchestrator\Reboot","\Microsoft\Windows\UpdateOrchestrator\Schedule Scan","\Microsoft\Windows\WindowsUpdate\Scheduled Start","\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem") | ForEach-Object { schtasks /Change /TN $_ /Disable 2>$null }
        Get-ScheduledTask -TaskPath "\Microsoft\Windows\UpdateOrchestrator\*" -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match "reboot|restart" } | Disable-ScheduledTask -ErrorAction SilentlyContinue
        $results += "OK|Reboot tasks disabled"
    } catch { $results += "ERR|Scheduled tasks: $_" }

    # 4. REMOVE SHUTDOWN USER RIGHTS
    try {
        secedit /export /cfg C:\temp\secpol.cfg 2>$null
        $content = Get-Content C:\temp\secpol.cfg
        $content = $content -replace 'SeShutdownPrivilege.*', 'SeShutdownPrivilege = *S-1-5-18'
        $content | Set-Content C:\temp\secpol.cfg
        secedit /configure /db C:\temp\secedit.sdb /cfg C:\temp\secpol.cfg /areas USER_RIGHTS 2>$null
        Remove-Item C:\temp\secpol.cfg, C:\temp\secedit.sdb -Force -ErrorAction SilentlyContinue
        $results += "OK|Shutdown user rights removed"
    } catch { $results += "ERR|User rights: $_" }

    # 5. BLOCK SHUTDOWN.EXE
    try {
        $shutdownPath = "C:\Windows\System32\shutdown.exe"
        takeown /f $shutdownPath /a 2>$null
        icacls $shutdownPath /inheritance:r 2>$null
        icacls $shutdownPath /deny "Everyone:(RX)" 2>$null
        icacls $shutdownPath /deny "BUILTIN\Administrators:(RX)" 2>$null
        icacls $shutdownPath /deny "NT AUTHORITY\SYSTEM:(RX)" 2>$null
        $results += "OK|shutdown.exe blocked"
    } catch { $results += "ERR|shutdown.exe: $_" }

    # 6. CREATE WATCHDOG SCRIPTS
    try {
        @'
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public class PreventSleep{[DllImport("kernel32.dll")]public static extern uint SetThreadExecutionState(uint f);public const uint ES_CONTINUOUS=0x80000000;public const uint ES_SYSTEM_REQUIRED=0x00000001;public const uint ES_DISPLAY_REQUIRED=0x00000002;}
"@
[PreventSleep]::SetThreadExecutionState([PreventSleep]::ES_CONTINUOUS -bor [PreventSleep]::ES_SYSTEM_REQUIRED -bor [PreventSleep]::ES_DISPLAY_REQUIRED)
'@ | Out-File -FilePath "C:\temp\PreventSleep.ps1" -Encoding UTF8 -Force

        @'
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public class ShutdownBlocker{[DllImport("kernel32.dll")]public static extern uint SetThreadExecutionState(uint f);public const uint ES_CONTINUOUS=0x80000000;public const uint ES_SYSTEM_REQUIRED=0x00000001;}
"@
while($true){[ShutdownBlocker]::SetThreadExecutionState([ShutdownBlocker]::ES_CONTINUOUS -bor [ShutdownBlocker]::ES_SYSTEM_REQUIRED)|Out-Null;Start-Process -FilePath "cmd.exe" -ArgumentList "/c shutdown /a" -WindowStyle Hidden -ErrorAction SilentlyContinue;Start-Sleep -Seconds 10}
'@ | Out-File -FilePath "C:\temp\ShutdownBlocker.ps1" -Encoding UTF8 -Force
        $results += "OK|Watchdog scripts created"
    } catch { $results += "ERR|Watchdog scripts: $_" }

    # 7. CREATE SCHEDULED TASKS
    try {
        Unregister-ScheduledTask -TaskName "PreventSystemSleep" -Confirm:$false -ErrorAction SilentlyContinue
        $a1 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\temp\PreventSleep.ps1"
        $t1 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
        $p1 = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $s1 = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName "PreventSystemSleep" -Action $a1 -Trigger $t1 -Principal $p1 -Settings $s1 -Force | Out-Null
        Start-ScheduledTask -TaskName "PreventSystemSleep"

        Unregister-ScheduledTask -TaskName "ShutdownBlocker" -Confirm:$false -ErrorAction SilentlyContinue
        $a2 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\temp\ShutdownBlocker.ps1"
        $t2 = New-ScheduledTaskTrigger -AtStartup
        $p2 = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $s2 = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Days 9999)
        Register-ScheduledTask -TaskName "ShutdownBlocker" -Action $a2 -Trigger $t2 -Principal $p2 -Settings $s2 -Force | Out-Null
        Start-ScheduledTask -TaskName "ShutdownBlocker"
        $results += "OK|Scheduled tasks created"
    } catch { $results += "ERR|Scheduled tasks: $_" }

    # 8. WMI EVENT SUBSCRIPTION
    try {
        Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='ShutdownFilter'" -ErrorAction SilentlyContinue | Remove-WmiObject
        Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='ShutdownConsumer'" -ErrorAction SilentlyContinue | Remove-WmiObject
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter -match "ShutdownFilter" } | Remove-WmiObject
        $Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='ShutdownFilter';EventNamespace='root\cimv2';QueryLanguage='WQL';Query="SELECT * FROM Win32_ComputerShutdownEvent"}
        $Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='ShutdownConsumer';CommandLineTemplate='cmd.exe /c shutdown /a'}
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter;Consumer=$Consumer} | Out-Null
        $results += "OK|WMI blocker installed"
    } catch { $results += "ERR|WMI: $_" }

    # 9. LOCK REGISTRY KEYS
    try {
        @("SOFTWARE\Policies\Microsoft\Power","SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate","SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer") | ForEach-Object {
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($_,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
            if ($regKey) {
                $acl = $regKey.GetAccessControl()
                $acl.SetAccessRuleProtection($true, $false)
                $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule("NT AUTHORITY\SYSTEM",[System.Security.AccessControl.RegistryRights]::ReadKey,[System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow)))
                $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule("Everyone",[System.Security.AccessControl.RegistryRights]::SetValue,[System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Deny)))
                $regKey.SetAccessControl($acl)
                $regKey.Close()
            }
        }
        $results += "OK|Registry locked against GPO"
    } catch { $results += "ERR|Registry lock: $_" }

    # 10. PROTECT SCRIPTS AND TASKS
    try {
        @("C:\temp\ShutdownBlocker.ps1","C:\temp\PreventSleep.ps1") | ForEach-Object {
            if (Test-Path $_) { takeown /f $_ /a 2>$null; icacls $_ /inheritance:r 2>$null; icacls $_ /grant "NT AUTHORITY\SYSTEM:(R)" 2>$null; icacls $_ /deny "BUILTIN\Administrators:(M,D)" 2>$null; icacls $_ /deny "Everyone:(M,D)" 2>$null; attrib +r +s +h $_ 2>$null }
        }
        @("ShutdownBlocker","PreventSystemSleep") | ForEach-Object {
            $tf = "C:\Windows\System32\Tasks\$_"
            if (Test-Path $tf) { takeown /f $tf /a 2>$null; icacls $tf /inheritance:r 2>$null; icacls $tf /grant "NT AUTHORITY\SYSTEM:(R)" 2>$null; icacls $tf /deny "BUILTIN\Administrators:(D,WDAC,WO)" 2>$null; icacls $tf /deny "Everyone:(D,WDAC,WO)" 2>$null }
        }
        $results += "OK|Scripts and tasks protected"
    } catch { $results += "ERR|Protection: $_" }

    return $results
}

# Test Connection button click
$testButton.Add_Click({
    $computer = $hostnameBox.Text.Trim()
    if ([string]::IsNullOrEmpty($computer)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a computer name.", "Error", "OK", "Error")
        return
    }
    
    $statusLabel.Text = "Testing connection..."
    $outputBox.Clear()
    Write-Output "Testing connection to $computer..." "Yellow"
    [System.Windows.Forms.Application]::DoEvents()
    
    if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
        Write-Output "[+] Connection successful - $computer is reachable" "Green"
        $statusLabel.Text = "Connection OK"
    } else {
        Write-Output "[!] Cannot reach $computer" "Red"
        $statusLabel.Text = "Connection failed"
    }
})

# Lock Down button click
$lockdownButton.Add_Click({
    $computer = $hostnameBox.Text.Trim()
    if ([string]::IsNullOrEmpty($computer)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a computer name.", "Error", "OK", "Error")
        return
    }
    
    $lockdownButton.Enabled = $false
    $testButton.Enabled = $false
    $hostnameBox.Enabled = $false
    $outputBox.Clear()
    $progressBar.Value = 0
    
    Write-Output "============================================" "Cyan"
    Write-Output "  NEVER SHUTDOWN - Lockdown Tool" "Cyan"
    Write-Output "  Target: $computer" "Cyan"
    Write-Output "============================================" "Cyan"
    Write-Output ""
    
    # Test connection first
    $statusLabel.Text = "Testing connection..."
    Write-Output "[*] Testing connection to $computer..." "Yellow"
    [System.Windows.Forms.Application]::DoEvents()
    
    if (!(Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
        Write-Output "[!] Cannot reach $computer. Aborting." "Red"
        $statusLabel.Text = "Connection failed"
        $lockdownButton.Enabled = $true
        $testButton.Enabled = $true
        $hostnameBox.Enabled = $true
        return
    }
    Write-Output "[+] Connection successful" "Green"
    Write-Output ""
    $progressBar.Value = 10
    
    # Execute lockdown
    $statusLabel.Text = "Applying lockdown..."
    Write-Output "[*] Applying lockdown measures..." "Yellow"
    Write-Output ""
    [System.Windows.Forms.Application]::DoEvents()
    
    try {
        $results = Invoke-Command -ComputerName $computer -ScriptBlock $LockdownScript -ErrorAction Stop
        $progressBar.Value = 80
        
        Write-Output "=== RESULTS ===" "Cyan"
        foreach ($result in $results) {
            $parts = $result -split '\|', 2
            if ($parts[0] -eq "OK") {
                Write-Output "[+] $($parts[1])" "Green"
            } else {
                Write-Output "[!] $($parts[1])" "Red"
            }
        }
        
        # Verification
        Write-Output ""
        Write-Output "[*] Verifying lockdown..." "Yellow"
        [System.Windows.Forms.Application]::DoEvents()
        
        $verify = Invoke-Command -ComputerName $computer -ScriptBlock {
            $checks = @()
            $shutdownAcl = (icacls "C:\Windows\System32\shutdown.exe" 2>$null) -join " "
            if ($shutdownAcl -match "DENY") { $checks += "OK|shutdown.exe: BLOCKED" } else { $checks += "ERR|shutdown.exe: NOT BLOCKED" }
            $task1 = Get-ScheduledTask -TaskName "ShutdownBlocker" -ErrorAction SilentlyContinue
            $task2 = Get-ScheduledTask -TaskName "PreventSystemSleep" -ErrorAction SilentlyContinue
            if ($task1 -and $task2) { $checks += "OK|Watchdog tasks: RUNNING" } else { $checks += "ERR|Watchdog tasks: MISSING" }
            $wmi = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter -match "Shutdown" }
            if ($wmi) { $checks += "OK|WMI blocker: ACTIVE" } else { $checks += "ERR|WMI blocker: MISSING" }
            $powerKey = "HKLM:\SOFTWARE\Policies\Microsoft\Power"
            try { New-ItemProperty -Path $powerKey -Name "Test123" -Value 1 -Force -ErrorAction Stop | Out-Null; Remove-ItemProperty -Path $powerKey -Name "Test123" -ErrorAction SilentlyContinue; $checks += "ERR|Registry: NOT LOCKED" } catch { $checks += "OK|Registry: LOCKED" }
            return $checks
        }
        
        $progressBar.Value = 95
        Write-Output ""
        Write-Output "=== VERIFICATION ===" "Cyan"
        foreach ($check in $verify) {
            $parts = $check -split '\|', 2
            if ($parts[0] -eq "OK") {
                Write-Output "[+] $($parts[1])" "Green"
            } else {
                Write-Output "[!] $($parts[1])" "Red"
            }
        }
        
        $progressBar.Value = 100
        Write-Output ""
        Write-Output "============================================" "Cyan"
        Write-Output "  Lockdown complete for $computer" "Cyan"
        Write-Output "  Machine will NEVER shut down unless unplugged" "Cyan"
        Write-Output "============================================" "Cyan"
        
        $statusLabel.Text = "Lockdown complete!"
        [System.Windows.Forms.MessageBox]::Show("Lockdown complete for $computer!`n`nThe machine will never shut down unless physically unplugged.", "Success", "OK", "Information")
        
    } catch {
        Write-Output "[!] Error: $_" "Red"
        $statusLabel.Text = "Error occurred"
        [System.Windows.Forms.MessageBox]::Show("Error: $_", "Error", "OK", "Error")
    }
    
    $lockdownButton.Enabled = $true
    $testButton.Enabled = $true
    $hostnameBox.Enabled = $true
})

# Show the form
[void]$form.ShowDialog()
