Write-Host "Synchronizing system time..."
w32tm /resync

# Prompt for new administrator password
$newAdminPassword = Read-Host -AsSecureString "Enter new password for the local administrator account"

# Change local administrator password
$adminAccount = Get-LocalUser -Name "Administrator"
Set-LocalUser -Name "Administrator" -Password $newAdminPassword

# Rename administrator account for security
$newAdminName = Read-Host "Enter a new name for the administrator account"
Rename-LocalUser -Name "Administrator" -NewName $newAdminName
Write-Host "Administrator account renamed to $newAdminName."

# List all user accounts
Write-Host "Listing all user accounts:"
Get-LocalUser | Format-Table -Property Name, Enabled, LastLogon

# Disable guest account
$guestAccount = Get-LocalUser -Name "Guest"
if ($guestAccount.Enabled) {
    Disable-LocalUser -Name "Guest"
    Write-Host "Guest account has been disabled."
} else {
    Write-Host "Guest account is already disabled."
}

# Set strong password policies
Write-Host "Setting strong password policies..."
net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /uniquepw:5 /lockoutthreshold:5

# Disable unnecessary services
$servicesToDisable = @("Spooler", "RemoteRegistry", "Fax")
foreach ($service in $servicesToDisable) {
    Write-Host "Disabling service: $service"
    Stop-Service -Name $service -Force
    Set-Service -Name $service -StartupType Disabled
}

# Enable Windows Defender with real-time protection and PUA protection
Write-Host "Enabling Windows Defender and configuring protection settings..."
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -PUAProtection Enabled

# Enable Windows Firewall with basic rules
Write-Host "Configuring Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# Disable SMBv1 to mitigate vulnerabilities
Write-Host "Disabling SMBv1 protocol..."
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Configure Remote Desktop settings (disable if not needed)
Write-Host "Disabling Remote Desktop Protocol..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1

# Set account lockout policies
Write-Host "Configuring account lockout policies..."
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30

# Enable audit policies for key events
Write-Host "Enabling audit policies for login and account management..."
AuditPol.exe /set /subcategory:"Logon" /success:enable /failure:enable
AuditPol.exe /set /subcategory:"Account Management" /success:enable /failure:enable

# Remove unnecessary network shares
Write-Host "Removing unnecessary network shares..."
Get-SmbShare | Where-Object { $_.Name -ne "ADMIN$" -and $_.Name -ne "C$" } | ForEach-Object {
    Write-Host "Removing share: $($_.Name)"
    Remove-SmbShare -Name $_.Name -Force
}

# Enable Windows Firewall (reaffirm if previously configured)
Write-Host "Reaffirming Windows Firewall enabled..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Disable IPv6 if not needed
Write-Host "Disabling IPv6..."
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
Set-NetIPv6Protocol -State Disabled

# Ensure Windows Update is set to automatic
Write-Host "Setting Windows Update to automatic..."
Set-Service -Name wuauserv -StartupType Automatic
Write-Host "Checking for Windows updates..."
Install-WindowsUpdate -AcceptAll 


# FIREFOX

# Download and install Firefox
$firefoxInstallerPath = "$env:TEMP\FirefoxInstaller.exe"
Write-Host "Downloading Firefox installer..."
Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US" -OutFile $firefoxInstallerPath

Write-Host "Installing Firefox..."
Start-Process -FilePath $firefoxInstallerPath -ArgumentList "/S" -Wait


# CLAM AV

# Download and install ClamAV
$clamavInstallerPath = "$env:TEMP\clamav-win-x64.msi"
Write-Host "Downloading ClamAV installer..."
Invoke-WebRequest -Uri "https://www.clamav.net/downloads/production/clamav-1.4.1.win.x64.msi" -OutFile $clamavInstallerPath

Write-Host "Installing ClamAV..."
Start-Process -FilePath $clamavInstallerPath -ArgumentList "/quiet /norestart" -Wait

# Configure ClamAV for regular scans
Write-Host "Scheduling ClamAV scans..."
$clamAVConfigPath = "C:\Program Files\ClamAV\clamd.conf"
Set-Content -Path $clamAVConfigPath -Value 'LogFile "C:\Program Files\ClamAV\clamd.log"'
schtasks /create /sc daily /tn "ClamAV Scan" /tr "C:\Program Files\ClamAV\clamscan.exe -r C:\" /st 02:00


# Wazuh (OSSEC)

# Download and install Wazuh Agent (includes OSSEC functionality)
$wazuhInstallerPath = "$env:TEMP\wazuh-agent-4.3.10.msi"
Write-Host "Downloading Wazuh Agent installer..."
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.1-1.msi" -OutFile $wazuhInstallerPath

Write-Host "Installing Wazuh Agent..."
Start-Process -FilePath $wazuhInstallerPath -ArgumentList "/quiet /norestart" -Wait

# Set Wazuh Agent to run in local mode
Write-Host "Configuring Wazuh Agent for local mode..."
$wazuhConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$wazuhConfig = Get-Content $wazuhConfigPath
$wazuhConfig = $wazuhConfig -replace '<server>.*</server>', '' # Ensure no server is specified
Set-Content -Path $wazuhConfigPath -Value $wazuhConfig

# Start Wazuh Agent Service
Write-Host "Starting Wazuh Agent service in local mode..."
Start-Service -Name WazuhSvc


Write-Host "Performing a quick scan with Windows Defender..."
Start-MpScan -ScanType QuickScan

Write-Host "Basic security checks and configurations are complete."
Write-Host "Please review if there are Windows updates available and install them and Restart the system."
