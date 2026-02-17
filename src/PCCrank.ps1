<#
.SYNOPSIS
    PCCrank - Keeps your PC cranked and running forever
    Prevents a Windows computer from ever shutting down, sleeping, or hibernating.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "PCCrank"
$form.Size = New-Object System.Drawing.Size(620, 560)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
$form.ForeColor = [System.Drawing.Color]::White

# Title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "PCCrank"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 24, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 90, 60)
$titleLabel.AutoSize = $true
$titleLabel.Location = New-Object System.Drawing.Point(240, 12)
$form.Controls.Add($titleLabel)

# Subtitle
$subtitleLabel = New-Object System.Windows.Forms.Label
$subtitleLabel.Text = "Keep your PC cranked. Forever."
$subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$subtitleLabel.ForeColor = [System.Drawing.Color]::Gray
$subtitleLabel.AutoSize = $true
$subtitleLabel.Location = New-Object System.Drawing.Point(210, 55)
$form.Controls.Add($subtitleLabel)

# Warning panel
$warningPanel = New-Object System.Windows.Forms.Panel
$warningPanel.Size = New-Object System.Drawing.Size(570, 60)
$warningPanel.Location = New-Object System.Drawing.Point(20, 85)
$warningPanel.BackColor = [System.Drawing.Color]::FromArgb(60, 30, 30)
$form.Controls.Add($warningPanel)

$warningLabel = New-Object System.Windows.Forms.Label
$warningLabel.Text = "WARNING: This process is extremely difficult to reverse. Once applied, the target`nmachine will resist all shutdown attempts. Reversal requires Safe Mode or recovery`nenvironment access. Only proceed if you understand the consequences."
$warningLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$warningLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 180, 180)
$warningLabel.AutoSize = $true
$warningLabel.Location = New-Object System.Drawing.Point(10, 8)
$warningPanel.Controls.Add($warningLabel)

# Target selection group
$targetGroup = New-Object System.Windows.Forms.GroupBox
$targetGroup.Text = "Target"
$targetGroup.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$targetGroup.ForeColor = [System.Drawing.Color]::White
$targetGroup.Size = New-Object System.Drawing.Size(570, 75)
$targetGroup.Location = New-Object System.Drawing.Point(20, 155)
$form.Controls.Add($targetGroup)

# Local machine radio
$localRadio = New-Object System.Windows.Forms.RadioButton
$localRadio.Text = "This Machine (Local)"
$localRadio.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$localRadio.AutoSize = $true
$localRadio.Location = New-Object System.Drawing.Point(15, 25)
$localRadio.Checked = $false
$targetGroup.Controls.Add($localRadio)

# Remote machine radio
$remoteRadio = New-Object System.Windows.Forms.RadioButton
$remoteRadio.Text = "Remote Machine:"
$remoteRadio.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$remoteRadio.AutoSize = $true
$remoteRadio.Location = New-Object System.Drawing.Point(15, 48)
$remoteRadio.Checked = $true
$targetGroup.Controls.Add($remoteRadio)

# Hostname textbox
$hostnameBox = New-Object System.Windows.Forms.TextBox
$hostnameBox.Font = New-Object System.Drawing.Font("Consolas", 11)
$hostnameBox.Size = New-Object System.Drawing.Size(350, 30)
$hostnameBox.Location = New-Object System.Drawing.Point(175, 45)
$hostnameBox.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$hostnameBox.ForeColor = [System.Drawing.Color]::White
$hostnameBox.BorderStyle = "FixedSingle"
$targetGroup.Controls.Add($hostnameBox)

# Toggle hostname box based on radio selection
$localRadio.Add_CheckedChanged({
    $hostnameBox.Enabled = -not $localRadio.Checked
    if ($localRadio.Checked) {
        $hostnameBox.Text = $env:COMPUTERNAME
        $hostnameBox.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
    } else {
        $hostnameBox.Text = ""
        $hostnameBox.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    }
})

# Buttons panel
$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Size = New-Object System.Drawing.Size(570, 40)
$buttonPanel.Location = New-Object System.Drawing.Point(20, 235)
$form.Controls.Add($buttonPanel)

# Test Connection button
$testButton = New-Object System.Windows.Forms.Button
$testButton.Text = "Test Connection"
$testButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$testButton.Size = New-Object System.Drawing.Size(130, 35)
$testButton.Location = New-Object System.Drawing.Point(0, 0)
$testButton.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$testButton.ForeColor = [System.Drawing.Color]::White
$testButton.FlatStyle = "Flat"
$testButton.Cursor = "Hand"
$buttonPanel.Controls.Add($testButton)

# CRANK IT button
$crankButton = New-Object System.Windows.Forms.Button
$crankButton.Text = "CRANK IT"
$crankButton.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$crankButton.Size = New-Object System.Drawing.Size(140, 35)
$crankButton.Location = New-Object System.Drawing.Point(430, 0)
$crankButton.BackColor = [System.Drawing.Color]::FromArgb(180, 50, 30)
$crankButton.ForeColor = [System.Drawing.Color]::White
$crankButton.FlatStyle = "Flat"
$crankButton.Cursor = "Hand"
$buttonPanel.Controls.Add($crankButton)

# Progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(570, 18)
$progressBar.Location = New-Object System.Drawing.Point(20, 280)
$progressBar.Style = "Continuous"
$form.Controls.Add($progressBar)

# Output textbox
$outputBox = New-Object System.Windows.Forms.RichTextBox
$outputBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$outputBox.Size = New-Object System.Drawing.Size(570, 200)
$outputBox.Location = New-Object System.Drawing.Point(20, 305)
$outputBox.BackColor = [System.Drawing.Color]::FromArgb(15, 15, 15)
$outputBox.ForeColor = [System.Drawing.Color]::LightGray
$outputBox.BorderStyle = "None"
$outputBox.ReadOnly = $true
$form.Controls.Add($outputBox)

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready to crank"
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$statusLabel.ForeColor = [System.Drawing.Color]::Gray
$statusLabel.AutoSize = $true
$statusLabel.Location = New-Object System.Drawing.Point(20, 515)
$form.Controls.Add($statusLabel)

# Version label
$versionLabel = New-Object System.Windows.Forms.Label
$versionLabel.Text = "v1.0"
$versionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$versionLabel.ForeColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$versionLabel.AutoSize = $true
$versionLabel.Location = New-Object System.Drawing.Point(560, 515)
$form.Controls.Add($versionLabel)

# Function to write colored output
function Write-Output {
    param([string]$Text, [string]$Color = "White")
    
    $colorMap = @{
        "Green" = [System.Drawing.Color]::FromArgb(100, 255, 100)
        "Red" = [System.Drawing.Color]::FromArgb(255, 100, 100)
        "Yellow" = [System.Drawing.Color]::FromArgb(255, 220, 100)
        "Orange" = [System.Drawing.Color]::FromArgb(255, 150, 80)
        "Cyan" = [System.Drawing.Color]::FromArgb(100, 220, 255)
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
        powercfg /change standby-timeout-ac 0; powercfg /change standby-timeout-dc 0
        powercfg /change hibernate-timeout-ac 0; powercfg /change hibernate-timeout-dc 0
        powercfg /change monitor-timeout-ac 0; powercfg /change monitor-timeout-dc 0
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

# Get target computer name
function Get-TargetComputer {
    if ($localRadio.Checked) {
        return $env:COMPUTERNAME
    } else {
        return $hostnameBox.Text.Trim()
    }
}

# Test Connection button click
$testButton.Add_Click({
    $computer = Get-TargetComputer
    if ([string]::IsNullOrEmpty($computer)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a computer name.", "Error", "OK", "Error")
        return
    }
    
    $statusLabel.Text = "Testing connection..."
    $outputBox.Clear()
    Write-Output "Testing connection to $computer..." "Yellow"
    [System.Windows.Forms.Application]::DoEvents()
    
    if ($localRadio.Checked) {
        Write-Output "[+] Local machine selected - $computer" "Green"
        $statusLabel.Text = "Local machine ready"
    } elseif (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
        Write-Output "[+] Connection successful - $computer is reachable" "Green"
        $statusLabel.Text = "Connection OK"
    } else {
        Write-Output "[!] Cannot reach $computer" "Red"
        $statusLabel.Text = "Connection failed"
    }
})

# CRANK IT button click
$crankButton.Add_Click({
    $computer = Get-TargetComputer
    if ([string]::IsNullOrEmpty($computer)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a computer name.", "Error", "OK", "Error")
        return
    }
    
    # Confirmation dialog
    $confirmMsg = "You are about to CRANK: $computer`n`n"
    $confirmMsg += "This will make the machine extremely resistant to shutdown.`n"
    $confirmMsg += "Reversal requires Safe Mode or recovery environment access.`n`n"
    $confirmMsg += "Are you absolutely sure you want to proceed?"
    
    $confirm = [System.Windows.Forms.MessageBox]::Show($confirmMsg, "Confirm Crank", "YesNo", "Warning")
    if ($confirm -ne "Yes") {
        return
    }
    
    $crankButton.Enabled = $false
    $testButton.Enabled = $false
    $hostnameBox.Enabled = $false
    $localRadio.Enabled = $false
    $remoteRadio.Enabled = $false
    $outputBox.Clear()
    $progressBar.Value = 0
    
    Write-Output "============================================" "Orange"
    Write-Output "  PCCrank - Initiating Lockdown" "Orange"
    Write-Output "  Target: $computer" "Orange"
    Write-Output "============================================" "Orange"
    Write-Output ""
    
    # Test connection first (for remote)
    if (-not $localRadio.Checked) {
        $statusLabel.Text = "Testing connection..."
        Write-Output "[*] Testing connection to $computer..." "Yellow"
        [System.Windows.Forms.Application]::DoEvents()
        
        if (!(Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
            Write-Output "[!] Cannot reach $computer. Aborting." "Red"
            $statusLabel.Text = "Connection failed"
            $crankButton.Enabled = $true
            $testButton.Enabled = $true
            $hostnameBox.Enabled = $true
            $localRadio.Enabled = $true
            $remoteRadio.Enabled = $true
            return
        }
        Write-Output "[+] Connection successful" "Green"
    } else {
        Write-Output "[*] Running on local machine: $computer" "Yellow"
    }
    
    Write-Output ""
    $progressBar.Value = 10
    
    # Execute lockdown
    $statusLabel.Text = "Cranking..."
    Write-Output "[*] Applying lockdown measures..." "Yellow"
    Write-Output ""
    [System.Windows.Forms.Application]::DoEvents()
    
    try {
        if ($localRadio.Checked) {
            # Run locally
            $results = & $LockdownScript
        } else {
            # Run remotely
            $results = Invoke-Command -ComputerName $computer -ScriptBlock $LockdownScript -ErrorAction Stop
        }
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
        
        $verifyScript = {
            $checks = @()
            $shutdownAcl = (icacls "C:\Windows\System32\shutdown.exe" 2>$null) -join " "
            if ($shutdownAcl -match "DENY") { $checks += "OK|shutdown.exe: BLOCKED" } else { $checks += "ERR|shutdown.exe: NOT BLOCKED" }
            $task1 = Get-ScheduledTask -TaskName "ShutdownBlocker" -ErrorAction SilentlyContinue
            $task2 = Get-ScheduledTask -TaskName "PreventSystemSleep" -ErrorAction SilentlyContinue
            if ($task1 -and $task2) { $checks += "OK|Watchdog tasks: ACTIVE" } else { $checks += "ERR|Watchdog tasks: MISSING" }
            $wmi = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter -match "Shutdown" }
            if ($wmi) { $checks += "OK|WMI blocker: ACTIVE" } else { $checks += "ERR|WMI blocker: MISSING" }
            $powerKey = "HKLM:\SOFTWARE\Policies\Microsoft\Power"
            try { New-ItemProperty -Path $powerKey -Name "Test123" -Value 1 -Force -ErrorAction Stop | Out-Null; Remove-ItemProperty -Path $powerKey -Name "Test123" -ErrorAction SilentlyContinue; $checks += "ERR|Registry: NOT LOCKED" } catch { $checks += "OK|Registry: LOCKED" }
            return $checks
        }
        
        if ($localRadio.Checked) {
            $verify = & $verifyScript
        } else {
            $verify = Invoke-Command -ComputerName $computer -ScriptBlock $verifyScript
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
        Write-Output "============================================" "Orange"
        Write-Output "  $computer is now CRANKED" "Orange"
        Write-Output "  Only way to stop it: PULL THE PLUG" "Orange"
        Write-Output "============================================" "Orange"
        
        $statusLabel.Text = "CRANKED!"
        [System.Windows.Forms.MessageBox]::Show("$computer is now CRANKED!`n`nThe only way to turn it off is to physically unplug it.", "PCCrank Complete", "OK", "Information")
        
    } catch {
        Write-Output "[!] Error: $_" "Red"
        $statusLabel.Text = "Error occurred"
        [System.Windows.Forms.MessageBox]::Show("Error: $_", "Error", "OK", "Error")
    }
    
    $crankButton.Enabled = $true
    $testButton.Enabled = $true
    $hostnameBox.Enabled = -not $localRadio.Checked
    $localRadio.Enabled = $true
    $remoteRadio.Enabled = $true
})

# Show the form
[void]$form.ShowDialog()
