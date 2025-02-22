# # Import necessary modules
# Import-Module -Name Microsoft.PowerShell.LocalAccounts
# Import-Module -Name NetSecurity
# Import-Module -Name BitsTransfer

# # Create directories
# $ccdcPath = "C:\CCDC"
# $toolsPath = "$ccdcPath\tools-Windows"
# mkdir $ccdcPath -Force
# mkdir "$ccdcPath\DNS" -Force
# mkdir $toolsPath -Force

# # Ask if tools should be downloaded
# $downloadTools = Read-Host "Do you want to download the necessary tools? (yes/no)"
# if ($downloadTools -eq "yes") {
#     # Download necessary tools
#     $tools = @(
#         @{ Name = "Npcap Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/npcap-1.80.exe"; Path = "$toolsPath\npcap-1.80.exe" },
#         @{ Name = "Firefox Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Firefox%20Installer.exe"; Path = "$toolsPath\FirefoxInstaller.exe" }
#     )

#     foreach ($tool in $tools) {
#         Write-Host "Downloading $($tool.Name)..."
#         Start-BitsTransfer -Source $tool.Url -Destination $tool.Path
#     }
# } else {
#     Write-Host "Skipping download of tools."
# }

# # Initialize the global jobs array
# $global:jobs = @()

# function Start-LoggedJob {
#     param (
#         [string]$JobName,
#         [scriptblock]$ScriptBlock
#     )
    
#     $job = Start-Job -Name $JobName -ScriptBlock $ScriptBlock
#     $global:jobs += @($job)  # Ensure the job is added as an array element
#     Write-Host "Started job: $JobName"
# }

# # # Sync system time
# # Start-LoggedJob -JobName "Synchronize System Time" -ScriptBlock {
# #     try {
# #         tzutil /s "Central Standard Time"
# #         w32tm /resync
# #         Write-Host "--------------------------------------------------------------------------------"
# #         Write-Host "System time synchronized to Central Standard Time."
# #         Write-Host "--------------------------------------------------------------------------------"
# #     } catch {
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #         Write-Host "An error occurred while synchronizing system time: $_"
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #     }
# # }

# # # Set strong password policies
# # Start-LoggedJob -JobName "Set Password Policies" -ScriptBlock {
# #     try {
# #         net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /uniquepw:5 /lockoutthreshold:5
# #         Write-Host "--------------------------------------------------------------------------------"
# #         Write-Host "Password policies set successfully."
# #         Write-Host "--------------------------------------------------------------------------------"
# #     } catch {
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #         Write-Host "An error occurred while setting password policies: $_"
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #     }
# # }

# # # Disable unnecessary services
# # $servicesToDisable = @("Spooler", "RemoteRegistry", "Fax")
# # foreach ($service in $servicesToDisable) {
# #     Start-LoggedJob -JobName "Disable Service: $service" -ScriptBlock {
# #         param ($service)
# #         Write-Host "Disabling service: $service"
# #         Stop-Service -Name $service -Force
# #         Set-Service -Name $service -StartupType Disabled
# #     } -ArgumentList $service
# # }

# # # Additional test jobs
# # Start-LoggedJob -JobName "Enable Windows Defender" -ScriptBlock {
# #     try {
# #         Set-MpPreference -DisableRealtimeMonitoring $false
# #         Set-MpPreference -PUAProtection Enabled
# #         Write-Host "--------------------------------------------------------------------------------"
# #         Write-Host "Windows Defender enabled and PUA protection configured."
# #         Write-Host "--------------------------------------------------------------------------------"
# #     } catch {
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #         Write-Host "An error occurred while enabling Windows Defender: $_"
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #     }
# # }

# # Start-LoggedJob -JobName "Configure Windows Firewall" -ScriptBlock {
# #     try {
# #         Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
# #         Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
# #         Write-Host "--------------------------------------------------------------------------------"
# #         Write-Host "Windows Firewall configured."
# #         Write-Host "--------------------------------------------------------------------------------"
# #     } catch {
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #         Write-Host "An error occurred while configuring Windows Firewall: $_"
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #     }
# # }

# # Start-LoggedJob -JobName "Disable SMBv1" -ScriptBlock {
# #     try {
# #         Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
# #         Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
# #         Write-Host "--------------------------------------------------------------------------------"
# #         Write-Host "SMBv1 disabled."
# #         Write-Host "--------------------------------------------------------------------------------"
# #     } catch {
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #         Write-Host "An error occurred while disabling SMBv1: $_"
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #     }
# # }
# # Perform a quick scan with Windows Defender
# Start-LoggedJob -JobName "Quick Scan with Windows Defender" -ScriptBlock { 
#     try {
#         Start-MpScan -ScanType QuickScan
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Quick scan with Windows Defender completed."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
#         Write-Host "An error occurred while performing a quick scan with Windows Defender: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
#     }
# }

# Start-LoggedJob -JobName "Secure and Backup DNS" -ScriptBlock {
#     param ($zone, $ccdcPath)
#     try {
#         # Configure DNS settings
#         #Set-DnsServerSetting -SocketPoolSize 10000 -CacheLockingPercent 100 -Confirm:$false

#         # Export DNS zone file
#         $backupPath = "$ccdcPath\DNS\$zone.dns"
#         Export-DnsServerZone -Name $zone -FileName $backupPath -ComputerName localhost

#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "DNS secured and backed up successfully to $backupPath"
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while securing and backing up DNS: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# } -ArgumentList $zone, $ccdcPath

# # Enable Windows Firewall with basic rules
# Start-LoggedJob -JobName "Configure Windows Firewall" -ScriptBlock {
#     try {
#         # Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
#         # Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        
#         # Export existing Firewall
#         Export-WindowsFirewallRules -FilePath "$ccdcPath\firewall.old"
#         Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
#         # Block by default
#         Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
#         Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
#         # Enable Logging
#         Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "$ccdcPath\pfirewall.log" -LogMaxSizeKilobytes 8192 -LogAllowed True -LogBlocked True
#         Set-NetFirewallSetting -StatefulFtp Disable
#         Set-NetFirewallSetting -StatefulPptp Disable
        
#         # Disable existing rules
#         Get-NetFirewallRule | Set-NetFirewallRule -Enabled False
        
#         # Firewall inbound rules
#         New-NetFirewallRule -DisplayName "NTP in" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 123 -Protocol UDP
#         New-NetFirewallRule -DisplayName "Allow Pings in" -Direction Inbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
#         New-NetFirewallRule -DisplayName "DNS IN (UDP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol UDP
#         New-NetFirewallRule -DisplayName "DNS IN (TCP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol TCP
#         New-NetFirewallRule -DisplayName "LDAP TCP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 389 -Protocol TCP
#         New-NetFirewallRule -DisplayName "LDAP UDP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 389 -Protocol UDP
#         New-NetFirewallRule -DisplayName "LDAP Global Catalog IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 3268 -Protocol TCP
#         New-NetFirewallRule -DisplayName "NETBIOS Resolution IN" -Direction Inbound -Action Allow -Program "System" -Enabled True -Profile Any -LocalPort 138 -Protocol UDP
#         New-NetFirewallRule -DisplayName "Secure LDAP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 636 -Protocol TCP
#         New-NetFirewallRule -DisplayName "Secure LDAP Global Catalog IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 3269 -Protocol TCP
#         New-NetFirewallRule -DisplayName "RPC IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort RPC -Protocol TCP
#         New-NetFirewallRule -DisplayName "RPC-EPMAP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort RPC-EPMap -Protocol TCP
#         New-NetFirewallRule -DisplayName "DHCP UDP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort 67,68 -Protocol UDP
#         New-NetFirewallRule -DisplayName "RPC for DNS IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -LocalPort RPC -Protocol TCP

#         # Outbound rules
#         New-NetFirewallRule -DisplayName "Allow Pings out" -Direction Outbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
#         New-NetFirewallRule -DisplayName "Splunk OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 8000,8089,9997 -Protocol TCP
#         New-NetFirewallRule -DisplayName "Web OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 80,443 -Protocol TCP
#         New-NetFirewallRule -DisplayName "NTP OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 123 -Protocol UDP
#         New-NetFirewallRule -DisplayName "Active Directory TCP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -Protocol TCP
#         New-NetFirewallRule -DisplayName "Active Directory UDP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -Protocol UDP
#         New-NetFirewallRule -DisplayName "DNS TCP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -Protocol TCP
#         New-NetFirewallRule -DisplayName "DNS UDP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -Protocol UDP
#         New-NetFirewallRule -DisplayName "DNS OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 53 -Protocol UDP
#         New-NetFirewallRule -DisplayName "DHCP" -Direction Outbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort 68 -RemotePort 67 -Protocol UDP
        
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Windows Firewall configured with basic rules."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while configuring Windows Firewall: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# # Enable audit policies for key events like login, account management, file system changes, and registry changes
# Start-LoggedJob -JobName "Enable Audit Policies" -ScriptBlock {
#     try {
#         AuditPol.exe /set /subcategory:"Logon" /success:enable /failure:enable
#         AuditPol.exe /set /subcategory:"Account Management" /success:enable /failure:enable
#         AuditPol.exe /set /subcategory:"File System" /success:enable /failure:enable
#         AuditPol.exe /set /subcategory:"Registry" /success:enable /failure:enable
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Audit policies for login, account management, file system changes, and registry changes enabled."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while enabling audit policies: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# # # Disable IPv6 if not needed
# # Start-LoggedJob -JobName "Disable IPv6" -ScriptBlock {
# #     try {
# #         Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
# #         Set-NetIPv6Protocol -State Disabled
# #         Write-Host "--------------------------------------------------------------------------------"
# #         Write-Host "IPv6 disabled."
# #         Write-Host "--------------------------------------------------------------------------------"
# #     } catch {
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #         Write-Host "An error occurred while disabling IPv6: $_"
# #         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #     }
# # }

# # Create alert for Audit WMI subscriptions
# Start-LoggedJob -JobName "Create Alert for Audit WMI Subscriptions" -ScriptBlock {
#     try {
#         $scriptPath = "$toolsPath\WmiAlert.ps1"
#         $taskName = "WmiAlert"
        
#         # Create the script
#         @"
#         $wmiSubscriptions = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
#         $previousSubscriptions = $wmiSubscriptions.PSObject.Properties.Name
        
#         while ($true) {
#             Start-Sleep -Seconds 5
#             $currentSubscriptions = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
#             $newSubscriptions = Compare-Object -ReferenceObject $previousSubscriptions -DifferenceObject $currentSubscriptions.PSObject.Properties.Name | Where-Object { $_.SideIndicator -eq '=>' }
            
#             if ($newSubscriptions) {
#                 [System.Windows.MessageBox]::Show("New WMI subscription detected: $($newSubscriptions.InputObject)")
#                 $previousSubscriptions += $newSubscriptions.InputObject
#             }
#         }
# "@ | Set-Content -Path $scriptPath
#         # Create the scheduled task
#         $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`""
#         $trigger = New-ScheduledTaskTrigger -AtStartup
#         Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -User "SYSTEM" -RunLevel Highest
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Alert for Audit WMI subscriptions created."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while creating alert for Audit WMI subscriptions: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# # Stop non admin users from installing software or running commands
# Start-LoggedJob -JobName "Restrict Non-Admin Users from Installing Software" -ScriptBlock {
#     try {
#         $acl = Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
#         $acl.SetAccessRuleProtection($true, $false)
        
#         # Remove existing access rules
#         $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
        
#         # Add full control for necessary system accounts
#         $adminUser = [System.Security.Principal.NTAccount]"Administrator"
#         $systemUser = [System.Security.Principal.NTAccount]"SYSTEM"
#         $trustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
#         $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule($adminUser, "FullControl", "Allow")
#         $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule($systemUser, "FullControl", "Allow")
#         $trustedInstallerRule = New-Object System.Security.AccessControl.RegistryAccessRule($trustedInstaller, "FullControl", "Allow")
#         $acl.AddAccessRule($adminRule)
#         $acl.AddAccessRule($systemRule)
#         $acl.AddAccessRule($trustedInstallerRule)
        
#         # Apply the modified ACL to the registry key
#         Set-Acl -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -AclObject $acl
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Non-admin users restricted from installing software."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while restricting non-admin users from installing software: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# # Additional security measures
# Start-LoggedJob -JobName "Configure Windows Defender Exploit Guard" -ScriptBlock {
#     try {
#         Set-MpPreference -EnableControlledFolderAccess Enabled
#         Set-MpPreference -EnableExploitProtection Enabled
#         Set-MpPreference -AttackSurfaceReductionRules_Ids @(
#             "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block executable content from email and webmail clients
#             "3B576869-A4EC-4529-8536-B80A7769E899",  # Block executable content from Office files
#             "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",  # Block credential stealing from LSASS
#             "D1E49AAC-8F56-4280-B9BA-993A6D77406C"   # Block executable content from Office files that contain macros
#         )
#         Set-MpPreference -AttackSurfaceReductionRules_Actions @("Enable", "Enable", "Enable", "Enable")
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Windows Defender Exploit Guard configured."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while configuring Windows Defender Exploit Guard: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# # Disable Sign-in for users not Administrator
# Start-LoggedJob -JobName "Disable Sign-in for Non-Admin Users" -ScriptBlock {
#     try {
#         $users = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" }
#         foreach ($user in $users) {
#             Set-LocalUser -Name $user.Name -PasswordNeverExpires $true
#             Set-LocalUser -Name $user.Name -AccountNeverExpires $true
#             Set-LocalUser -Name $user.Name -Enabled $false
#             # Generate a random 64 character password
#             $password = [System.Web.Security.Membership]::GeneratePassword(64, 0)
#             # Set the password to the random password
#             Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $password -AsPlainText -Force)
#             Set-LocalUser -Name $user.Name -UserMayNotChangePassword $true
#             Set-LocalUser -Name $user.Name -PasswordRequired $true
#             Set-LocalUser -Name $user.Name -Description "Disabled for security reasons"
#             Set-LocalUser -Name $user.Name -UserMayNotChangePassword $true

#             Write-Host "--------------------------------------------------------------------------------"
#             Write-Host "Sign-in for user $($user.Name) has been disabled."
#             Write-Host "--------------------------------------------------------------------------------"
#         }
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# # Monitor jobs
# while ($global:jobs.Count -gt 0) {
#     foreach ($job in $global:jobs) {
#         if ($job.State -eq 'Completed') {
#             Write-Host "$(Get-Date -Format 'HH:mm:ss') - $($job.Name) has completed."
#             $job | Receive-Job
#             Remove-Job -Job $job
#             $global:jobs = $global:jobs | Where-Object { $_.Id -ne $job.Id }
#         }
#     }
#     Start-Sleep -Seconds 5
# }

# Write-Host "All jobs have completed."




























# # Import necessary modules
# Import-Module -Name Microsoft.PowerShell.LocalAccounts
# Import-Module -Name NetSecurity
# Import-Module -Name BitsTransfer

# # Create directories
# $ccdcPath = "C:\CCDC"
# $toolsPath = "$ccdcPath\tools-Windows"
# mkdir $ccdcPath -wait

# mkdir "$ccdcPath\DNS" -wait

# mkdir "C:\CCDC\tools-Windows" -wait

# # Download the install script
# $installScriptPath = "$toolsPath\Installs.ps1"
# Write-Host "Downloading install script..."
# Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/Installs.ps1" -OutFile $installScriptPath

# # Download necessary tools
# $tools = @(
#     @{ Name = "Npcap Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/npcap-1.80.exe"; Path = "$toolsPath\npcap-1.80.exe" },
#     @{ Name = "Firefox Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Firefox%20Installer.exe"; Path = "$toolsPath\FirefoxInstaller.exe" },
#     @{ Name = "ClamAV Installer Part 1"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/setup_part.1"; Path = "$toolsPath\setup_part.1" },
#     @{ Name = "ClamAV Installer Part 2"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/setup_part.2"; Path = "$toolsPath\setup_part.2" },
#     @{ Name = "Wireshark Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Wireshark-4.4.3-x64.exe"; Path = "$toolsPath\Wireshark-4.4.3-x64.exe" },
#     @{ Name = "Autoruns"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Autoruns.zip"; Path = "$toolsPath\Autoruns.zip" },
#     @{ Name = "ProcessExplorer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/ProcessExplorer.zip"; Path = "$toolsPath\ProcessExplorer.zip" },
#     @{ Name = "ProcessMonitor"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/ProcessMonitor.zip"; Path = "$toolsPath\ProcessMonitor.zip" },
#     @{ Name = "TCPView"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/TCPView.zip"; Path = "$toolsPath\TCPView.zip" }
# )

# foreach ($tool in $tools) {
#     Write-Host "Downloading $($tool.Name)..."
#     Start-BitsTransfer -Source $tool.Url -Destination $tool.Path
# }
# $destPrefix = "$toolsPath\setup_part"
# # Verify the split
# $part1Bytes = [System.IO.File]::ReadAllBytes("$destPrefix.1")
# $part2Bytes = [System.IO.File]::ReadAllBytes("$destPrefix.2")
# $part1Bytes.Length, $part2Bytes.Length 

# # Combine the parts back into a single file
# $combinedFile = "$toolsPath\combined.msi"
# $combinedBytes = [byte[]]::new($part1Bytes.Length + $part2Bytes.Length)
# [System.Array]::Copy($part1Bytes, 0, $combinedBytes, 0, $part1Bytes.Length)
# [System.Array]::Copy($part2Bytes, 0, $combinedBytes, $part1Bytes.Length, $part2Bytes.Length)
# [System.IO.File]::WriteAllBytes($combinedFile, $combinedBytes)

# # Verify the combined file
# $combinedBytes = [System.IO.File]::ReadAllBytes($combinedFile)
# $combinedBytes.Length, $totalSize

# # Check if PSWindowsUpdate is installed, if not, install it
# if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
#     Write-Host "PSWindowsUpdate module not found. Installing..."
#     Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
# }

# Import-Module -Name PSWindowsUpdate

# # Ask the user if it is the scored 2019 box
# $server = Read-Host "Does this server have AD/DNS? (yes/no)"

# # Ask the user if they want to run the setup
# $runSetup = Read-Host "Do you want to run the setup? (yes/no)"
# if ($runSetup -ne "yes") {
#     Write-Host "Skipping setup..."
#     goto installs
# }

# Write-Host "Synchronizing system time..."
# Start-Job -ScriptBlock { w32tm /resync }

# # Prompt for new administrator password and confirmation
# do {
#     $newAdminPassword = Read-Host -AsSecureString "Enter new password for the local administrator account"
#     $confirmAdminPassword = Read-Host -AsSecureString "Confirm new password for the local administrator account"

#     $newAdminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newAdminPassword))
#     $confirmAdminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmAdminPassword))

#     if ($newAdminPasswordPlain -ne $confirmAdminPasswordPlain) {
#         Write-Host "Passwords do not match. Please try again."
#     }
# } while ($newAdminPasswordPlain -ne $confirmAdminPasswordPlain)

# # Change local administrator password
# $adminAccount = Get-LocalUser -Name "Administrator"
# Set-LocalUser -Name $adminAccount -Password $newAdminPassword

# # Rename administrator account for security
# # $newAdminName = Read-Host "Enter a new name for the administrator account"
# # Rename-LocalUser -Name "Administrator" -NewName $newAdminName
# # Write-Host "Administrator account renamed to $newAdminName."

# # List all user accounts
# Write-Host "Listing all user accounts:"
# Get-LocalUser | Format-Table -Property Name, Enabled, LastLogon

# # Disable guest account
# $guestAccount = Get-LocalUser -Name "Guest"
# if ($guestAccount.Enabled) {
#     Disable-LocalUser -Name "Guest"
#     Write-Host "Guest account has been disabled."
# } else {
#     Write-Host "Guest account is already disabled."
# }

# # Set strong password policies
# Write-Host "Setting strong password policies..."
# Start-Job -ScriptBlock { net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /uniquepw:5 /lockoutthreshold:5 }

# # Disable unnecessary services
# $servicesToDisable = @("Spooler", "RemoteRegistry", "Fax")
# foreach ($service in $servicesToDisable) {
#     Start-Job -ScriptBlock {
#         param ($service)
#         Write-Host "Disabling service: $service"
#         Stop-Service -Name $service -Force
#         Set-Service -Name $service -StartupType Disabled
#     } -ArgumentList $service
# }

# # Enable Windows Defender with real-time protection and PUA protection
# Write-Host "Enabling Windows Defender and configuring protection settings..."
# Start-Job -ScriptBlock {
#     Set-MpPreference -DisableRealtimeMonitoring $false
#     Set-MpPreference -PUAProtection Enabled
# }

# # Enable Windows Firewall with basic rules
# Write-Host "Configuring Windows Firewall..."
# Start-Job -ScriptBlock {
#     # Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
#     # Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    
#     # Export existing Firewall
#     Export-WindowsFirewallRules -FilePath "$ccdcPath\firewall.old"
#     Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
#     # Block by default
#     Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
#     Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
#     # Enable Logging
#     Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "$ccdcPath\pfirewall.log" -LogMaxSizeKilobytes 8192 -LogAllowed True -LogBlocked True
#     Set-NetFirewallSetting -StatefulFtp Disable
#     Set-NetFirewallSetting -StatefulPptp Disable
    
#     # Disable existing rules
#     Get-NetFirewallRule | Set-NetFirewallRule -Enabled False
    
#     # Firewall inbound rules
#     New-NetFirewallRule -DisplayName "NTP in" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 123 -Protocol UDP
#     New-NetFirewallRule -DisplayName "Allow Pings in" -Direction Inbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
#     New-NetFirewallRule -DisplayName "DNS IN (UDP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol UDP
#     New-NetFirewallRule -DisplayName "DNS IN (TCP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol TCP
#     New-NetFirewallRule -DisplayName "LDAP TCP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 389 -Protocol TCP
#     New-NetFirewallRule -DisplayName "LDAP UDP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 389 -Protocol UDP
#     New-NetFirewallRule -DisplayName "LDAP Global Catalog IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 3268 -Protocol TCP
#     New-NetFirewallRule -DisplayName "NETBIOS Resolution IN" -Direction Inbound -Action Allow -Program "System" -Enabled True -Profile Any -LocalPort 138 -Protocol UDP
#     New-NetFirewallRule -DisplayName "Secure LDAP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 636 -Protocol TCP
#     New-NetFirewallRule -DisplayName "Secure LDAP Global Catalog IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 3269 -Protocol TCP
#     New-NetFirewallRule -DisplayName "RPC IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort RPC -Protocol TCP
#     New-NetFirewallRule -DisplayName "RPC-EPMAP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort RPC-EPMap -Protocol TCP
#     New-NetFirewallRule -DisplayName "DHCP UDP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort 67,68 -Protocol UDP
#     New-NetFirewallRule -DisplayName "RPC for DNS IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -LocalPort RPC -Protocol TCP

#     # Outbound rules
#     New-NetFirewallRule -DisplayName "Allow Pings out" -Direction Outbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
#     New-NetFirewallRule -DisplayName "Splunk OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 8000,8089,9997 -Protocol TCP
#     New-NetFirewallRule -DisplayName "Web OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 80,443 -Protocol TCP
#     New-NetFirewallRule -DisplayName "NTP OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 123 -Protocol UDP
#     New-NetFirewallRule -DisplayName "Active Directory TCP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -Protocol TCP
#     New-NetFirewallRule -DisplayName "Active Directory UDP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -Protocol UDP
#     New-NetFirewallRule -DisplayName "DNS TCP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -Protocol TCP
#     New-NetFirewallRule -DisplayName "DNS UDP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -Protocol UDP
#     New-NetFirewallRule -DisplayName "DNS OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 53 -Protocol UDP
#     New-NetFirewallRule -DisplayName "DHCP" -Direction Outbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort 68 -RemotePort 67 -Protocol UDP
# }

# # Disable SMBv1 to mitigate vulnerabilities
# Write-Host "Disabling SMBv1 protocol..."
# Start-Job -ScriptBlock {
#     Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
#     Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
# }

# # Configure Remote Desktop settings (disable if not needed)
# Write-Host "Disabling Remote Desktop Protocol..."
# Start-Job -ScriptBlock {
#     Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
# }

# # Set account lockout policies
# Write-Host "Configuring account lockout policies..."
# Start-Job -ScriptBlock { net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 }

# # Enable audit policies for key events
# Write-Host "Enabling audit policies for login and account management..."
# Start-Job -ScriptBlock {
#     AuditPol.exe /set /subcategory:"Logon" /success:enable /failure:enable
#     AuditPol.exe /set /subcategory:"Account Management" /success:enable /failure:enable
# }

# # Remove unnecessary network shares
# Write-Host "Removing unnecessary network shares..."
# Start-Job -ScriptBlock {
#     Get-SmbShare | Where-Object { $_.Name -ne "ADMIN$" -and $_.Name -ne "C$" } | ForEach-Object {
#         Write-Host "Removing share: $($_.Name)"
#         Remove-SmbShare -Name $_.Name -Force
#     }
# }

# # Enable Windows Firewall (reaffirm if previously configured)
# Write-Host "Reaffirming Windows Firewall enabled..."
# Start-Job -ScriptBlock {
#     Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
# }

# # Disable IPv6 if not needed
# Write-Host "Disabling IPv6..."
# Start-Job -ScriptBlock {
#     Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
#     Set-NetIPv6Protocol -State Disabled
# }

# # Ensure Windows Update is set to automatic
# Write-Host "Setting Windows Update to automatic..."
# Start-Job -ScriptBlock {
#     Set-Service -Name wuauserv -StartupType Automatic
#     Write-Host "Checking for Windows updates..."
#     Install-WindowsUpdate -AcceptAll -Install
# }

# # Secure and backup DNS
# Write-Host "Securing DNS..."
# Get-DNSServerZone
# $zone = Read-Host "Enter the DNS zone used by the scoring engine"
# Start-Job -ScriptBlock {
#     dnscmd.exe /Config /SocketPoolSize 10000
#     dnscmd.exe /Config /CacheLockingPercent 100
#     dnscmd.exe /ZoneExport $zone $toolsPath
# }

# # Additional security measures
# # Write-Host "Enabling Secure Boot..."
# # Start-Job -ScriptBlock { Confirm-SecureBootUEFI }
# Write-Host "Configuring Windows Defender Exploit Guard..."
# Start-Job -ScriptBlock { Set-MpPreference -EnableControlledFolderAccess Enabled }

# # Write-Host "Enabling BitLocker for drive encryption..."
# # Start-Job -ScriptBlock { Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector }

# Write-Host "Configuring Network Level Authentication for Remote Desktop..."
# Start-Job -ScriptBlock { Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1 }

# Write-Host "Disabling LM and NTLMv1 protocols..."
# Start-Job -ScriptBlock { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LmCompatibilityLevel" -Value 5 }

# Write-Host "Enabling Windows Defender Credential Guard..."
# Start-Job -ScriptBlock {
#     Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name "EnableVirtualizationBasedSecurity" -Value 1
#     Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LsaCfgFlags" -Value 1
# }

# Write-Host "Configuring Windows Update to install updates automatically..."
# Start-Job -ScriptBlock { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name "AUOptions" -Value 4 }

# Write-Host "Enabling logging for PowerShell..."
# Start-Job -ScriptBlock {
#     Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name "EnableScriptBlockLogging" -Value 1
#     Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name "EnableTranscripting" -Value 1
# }

# # Ask the user if they want to run the installs
# $runInstalls = Read-Host "Do you want to run the installs? (yes/no)"
# if ($runInstalls -ne "yes") {
#     Write-Host "Skipping installs..."
#     exit
# }
# else {
#     # Set the installer script run on start
#     $scriptPath = "$toolsPath\Installs.ps1"
#     $entryName = "MyStartupScript"
#     Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName -Value "powershell.exe -File `"$scriptPath`""
# }

# Write-Host "Performing a quick scan with Windows Defender..."
# Start-Job -ScriptBlock { Start-MpScan -ScanType QuickScan }

# Write-Host "Basic security checks and configurations are complete."
# Write-Host "Please review if there are Windows updates available."

# # Wait for all jobs to complete
# Get-Job | Wait-Job

# Write-Host "Restarting Computer"
# Restart-Computer

# Import necessary modules
Import-Module -Name Microsoft.PowerShell.LocalAccounts
Import-Module -Name NetSecurity
Import-Module -Name BitsTransfer

# Prompt for new administrator password and confirmation
try {
    do {
        $newAdminPassword = Read-Host -AsSecureString "Enter new password for the local administrator account"
        $confirmAdminPassword = Read-Host -AsSecureString "Confirm new password for the local administrator account"

        $newAdminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newAdminPassword))
        $confirmAdminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmAdminPassword))

        if ($newAdminPasswordPlain -ne $confirmAdminPasswordPlain) {
            Write-Host "Passwords do not match. Please try again."
        }
    } while ($newAdminPasswordPlain -ne $confirmAdminPasswordPlain)

    # Change local administrator password
    $adminAccount = Get-LocalUser -Name "Administrator"
    Set-LocalUser -Name $adminAccount -Password $newAdminPassword
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "Administrator password changed."
    Write-Host "--------------------------------------------------------------------------------"
} catch {
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Write-Host "An error occurred while changing the administrator password: $_"
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
}

# # Set Password for all other accounts to lock them out:
# $allPassword = Read-Host -AsSecureString "Enter new password for all other accounts"

# # Convert the secure string to plain text for use with dsmod
# $allPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($allPassword))

# # Query all users in the domain and change their password
# try {
#     $users = dsquery user -limit 0
#     foreach ($user in $users) {
#         # Get the sAMAccountName for the user
#         $sAMAccountName = dsget user $user -samid

#         # Skip the Administrator account
#         if ($sAMAccountName -ne "Administrator") {
#             dsmod user $user -pwd $allPasswordPlain -mustchpwd yes
#             Write-Host "Password for user $user has been changed and must change password at next logon."
#         } else {
#             Write-Host "Skipping Administrator account."
#         }
#     }
#     Write-Host "--------------------------------------------------------------------------------"
#     Write-Host "Passwords for all users in the domain (except Administrator) have been changed."
#     Write-Host "--------------------------------------------------------------------------------"
# } catch {
#     Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     Write-Host "An error occurred while changing passwords for users in the domain: $_"
#     Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# }



# Create directories
$ccdcPath = "C:\CCDC"
$toolsPath = "$ccdcPath\tools-Windows"
mkdir $ccdcPath 
mkdir "$ccdcPath\DNS" 
mkdir "C:\CCDC\tools-Windows" 

# Download the install script
$installScriptPath = "$toolsPath\Installs.ps1"
Write-Host "Downloading install script..."
Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/Installs.ps1" -OutFile $installScriptPath

# Download necessary tools
$tools = @(
    @{ Name = "Npcap Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/npcap-1.80.exe"; Path = "$toolsPath\npcap-1.80.exe" },
    @{ Name = "Firefox Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Firefox%20Installer.exe"; Path = "$toolsPath\FirefoxInstaller.exe" },
    @{ Name = "ClamAV Installer Part 1"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/setup_part.1"; Path = "$toolsPath\setup_part.1" },
    @{ Name = "ClamAV Installer Part 2"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/setup_part.2"; Path = "$toolsPath\setup_part.2" },
    @{ Name = "Wireshark Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Wireshark-4.4.3-x64.exe"; Path = "$toolsPath\Wireshark-4.4.3-x64.exe" },
    @{ Name = "Autoruns"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Autoruns.zip"; Path = "$toolsPath\Autoruns.zip" },
    @{ Name = "ProcessExplorer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/ProcessExplorer.zip"; Path = "$toolsPath\ProcessExplorer.zip" },
    @{ Name = "ProcessMonitor"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/ProcessMonitor.zip"; Path = "$toolsPath\ProcessMonitor.zip" },
    @{ Name = "TCPView"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/TCPView.zip"; Path = "$toolsPath\TCPView.zip" }
)

foreach ($tool in $tools) {
    Write-Host "Downloading $($tool.Name)..."
    Start-BitsTransfer -Source $tool.Url -Destination $tool.Path
}
$destPrefix = "$toolsPath\setup_part"
# Verify the split
$part1Bytes = [System.IO.File]::ReadAllBytes("$destPrefix.1")
$part2Bytes = [System.IO.File]::ReadAllBytes("$destPrefix.2")
$part1Bytes.Length, $part2Bytes.Length 

# Combine the parts back into a single file
$combinedFile = "$toolsPath\combined.msi"
$combinedBytes = [byte[]]::new($part1Bytes.Length + $part2Bytes.Length)
[System.Array]::Copy($part1Bytes, 0, $combinedBytes, 0, $part1Bytes.Length)
[System.Array]::Copy($part2Bytes, 0, $combinedBytes, $part1Bytes.Length, $part2Bytes.Length)
[System.IO.File]::WriteAllBytes($combinedFile, $combinedBytes)

# Verify the combined file
$combinedBytes = [System.IO.File]::ReadAllBytes($combinedFile)
$combinedBytes.Length, $totalSize

# Check if PSWindowsUpdate is installed, if not, install it
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "PSWindowsUpdate module not found. Installing..."
    Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
}

Import-Module -Name PSWindowsUpdate

# Ask the user if it is the scored 2019 box
$server = Read-Host "Does this server have AD/DNS? (yes/no)"

# Ask the user if they want to run the setup
$runSetup = Read-Host "Do you want to run the setup? (yes/no)"
if ($runSetup -ne "yes") {
    Write-Host "Skipping setup..."
    goto installs
}
# Print out all DNS zones
Get-DNSServerZone
# Ask the user for the DNS zone
$zone = Read-Host "Enter the DNS zone used by the scoring engine"

# Initialize the global jobs array
$global:jobs = @()

function Start-LoggedJob {
    param (
        [string]$JobName,
        [scriptblock]$ScriptBlock
    )
    
    $job = Start-Job -Name $JobName -ScriptBlock $ScriptBlock
    $global:jobs += @($job)  # Ensure the job is added as an array element
    Write-Host "Started job: $JobName"
}



# Sync system time
Start-LoggedJob -JobName "Synchronize System Time" -ScriptBlock {
    try {
        tzutil /s "Central Standard Time"
        w32tm /resync
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "System time synchronized."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while synchronizing system time: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Disable guest account
Start-LoggedJob -JobName "Disable Guest Account" -ScriptBlock {
    try {
        $guestAccount = Get-LocalUser -Name "Guest"
        if ($guestAccount.Enabled) {
            Disable-LocalUser -Name "Guest"
            Write-Host "--------------------------------------------------------------------------------"
            Write-Host "Guest account has been disabled."
            Write-Host "--------------------------------------------------------------------------------"
        } else {
            Write-Host "--------------------------------------------------------------------------------"
            Write-Host "Guest account is already disabled."
            Write-Host "--------------------------------------------------------------------------------"
        }
    } catch {
        Write-Hos   t "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling the guest account: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Set strong password policies
Start-LoggedJob -JobName "Set Password Policies" -ScriptBlock {
    try {
        net accounts /minpwlen:12 /maxpwage:30 /minpwage:1 /uniquepw:5 /lockoutthreshold:5
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Strong password policies set."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while setting password policies: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}


# # Disable unnecessary services
# $servicesToDisable = @("Spooler", "RemoteRegistry", "Fax")
# foreach ($service in $servicesToDisable) {
#     Start-LoggedJob -JobName "Disable Service: $service" -ScriptBlock {
#         param ($service)
#         Write-Host "Disabling service: $service"
#         Stop-Service -Name $service -Force
#         Set-Service -Name $service -StartupType Disabled
#     } -ArgumentList $service
# }

# Enable Windows Defender with real-time protection and PUA protection
Start-LoggedJob -JobName "Enable Windows Defender" -ScriptBlock {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -PUAProtection Enabled
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Defender enabled with real-time protection and PUA protection."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while enabling Windows Defender: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Enable Windows Firewall with basic rules
Start-LoggedJob -JobName "Configure Windows Firewall" -ScriptBlock {
    try {
        # Export existing Firewall rules using netsh
        netsh advfirewall export "$ccdcPath\firewall.old"

        # Enable Windows Firewall profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

        # Block by default
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
        Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True

        # Enable Logging
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "$ccdcPath\pfirewall.log" -LogMaxSizeKilobytes 8192 -LogAllowed True -LogBlocked True

        # Disable existing rules
        Get-NetFirewallRule | Set-NetFirewallRule -Enabled False

        # Firewall inbound rules
        New-NetFirewallRule -DisplayName "NTP in" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 123 -Protocol UDP
        New-NetFirewallRule -DisplayName "Allow Pings in" -Direction Inbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
        New-NetFirewallRule -DisplayName "DNS IN (UDP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol UDP
        New-NetFirewallRule -DisplayName "DNS IN (TCP)" -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort 53 -Protocol TCP
        New-NetFirewallRule -DisplayName "LDAP TCP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 389 -Protocol TCP
        New-NetFirewallRule -DisplayName "LDAP UDP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 389 -Protocol UDP
        New-NetFirewallRule -DisplayName "LDAP Global Catalog IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 3268 -Protocol TCP
        New-NetFirewallRule -DisplayName "NETBIOS Resolution IN" -Direction Inbound -Action Allow -Program "System" -Enabled True -Profile Any -LocalPort 138 -Protocol UDP
        New-NetFirewallRule -DisplayName "Secure LDAP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 636 -Protocol TCP
        New-NetFirewallRule -DisplayName "Secure LDAP Global Catalog IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort 3269 -Protocol TCP
        New-NetFirewallRule -DisplayName "RPC IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -LocalPort RPC -Protocol TCP
        New-NetFirewallRule -DisplayName "RPC-EPMAP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort RPC-EPMap -Protocol TCP
        New-NetFirewallRule -DisplayName "DHCP UDP IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort 67,68 -Protocol UDP
        New-NetFirewallRule -DisplayName "RPC for DNS IN" -Direction Inbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -LocalPort RPC -Protocol TCP

        # Outbound rules
        New-NetFirewallRule -DisplayName "Allow Pings out" -Direction Outbound -Action Allow -Enabled True -Protocol ICMPv4 -IcmpType 8
        New-NetFirewallRule -DisplayName "Splunk OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 8000,8089,9997 -Protocol TCP
        New-NetFirewallRule -DisplayName "Web OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 80,443 -Protocol TCP
        New-NetFirewallRule -DisplayName "NTP OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 123 -Protocol UDP
        New-NetFirewallRule -DisplayName "Active Directory TCP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -Protocol TCP
        New-NetFirewallRule -DisplayName "Active Directory UDP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\lsass.exe" -Enabled True -Profile Any -Protocol UDP
        New-NetFirewallRule -DisplayName "DNS TCP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -Protocol TCP
        New-NetFirewallRule -DisplayName "DNS UDP OUT" -Direction Outbound -Action Allow -Program "C:\Windows\System32\dns.exe" -Enabled True -Profile Any -Protocol UDP
        New-NetFirewallRule -DisplayName "DNS OUT" -Direction Outbound -Action Allow -Enabled True -Profile Any -RemotePort 53 -Protocol UDP
        New-NetFirewallRule -DisplayName "DHCP" -Direction Outbound -Action Allow -Program "C:\Windows\System32\svchost.exe" -Enabled True -Profile Any -LocalPort 68 -RemotePort 67 -Protocol UDP
        
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Firewall configured with basic rules."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while configuring Windows Firewall: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# # Disable SMBv1 to mitigate vulnerabilities
# Start-LoggedJob -JobName "Disable SMBv1" -ScriptBlock {
#     try {
#         Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
#         Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
#         $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
#         Set-ItemProperty -Path $regPath -Name "SMB1" -Value 0
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "SMBv1 protocol disabled."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
#         Write-Host "An error occurred while disabling SMBv1: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
#     }
# }

# Configure Remote Desktop settings (disable if not needed)
Start-LoggedJob -JobName "Disable Remote Desktop" -ScriptBlock {
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Remote Desktop Protocol disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
        Write-Host "An error occurred while disabling Remote Desktop: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
    }
}

# Set account lockout policies
Start-LoggedJob -JobName "Set Account Lockout Policies" -ScriptBlock { 
    try {
        net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Account lockout policies set."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
        Write-Host "An error occurred while setting account lockout policies: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
    }
}

Enable audit policies for key events like login, account management, file system changes, and registry changes
Start-LoggedJob -JobName "Enable Audit Policies" -ScriptBlock {
    try {
        AuditPol.exe /set /subcategory:"Logon" /success:enable /failure:enable
        AuditPol.exe /set /subcategory:"User Account Management" /success:enable /failure:enable
        AuditPol.exe /set /subcategory:"File System" /success:enable /failure:enable
        AuditPol.exe /set /subcategory:"Registry" /success:enable /failure:enable
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Audit policies for login, account management, file system changes, and registry changes enabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while enabling audit policies: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Remove unnecessary network shares
Start-LoggedJob -JobName "Remove Unnecessary Network Shares" -ScriptBlock {
    try {
        Get-SmbShare | Where-Object { $_.Name -ne "ADMIN$" -and $_.Name -ne "C$" -and $_.Name -ne "IPC$" -and $_.Name -ne "NETLOGON" -and $_.Name -ne "SYSVOL" } | ForEach-Object {
            Write-Host "Removing share: $($_.Name)"
            Remove-SmbShare -Name $_.Name -Force
        }
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Unnecessary network shares removed."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while removing unnecessary network shares: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Enable Windows Firewall (reaffirm if previously configured)
Start-LoggedJob -JobName "Reaffirm Windows Firewall" -ScriptBlock {
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Firewall reaffirmed."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while reaffirming Windows Firewall: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# # Disable IPv6 if not needed
# Start-LoggedJob -JobName "Disable IPv6" -ScriptBlock {
#     try {
#         Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
#         Set-NetIPv6Protocol -State Disabled
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "IPv6 disabled."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while disabling IPv6: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# Ensure Windows Update is set to automatic
Start-LoggedJob -JobName "Set Windows Update to Automatic" -ScriptBlock {
    try {
        Set-Service -Name wuauserv -StartupType Automatic
        Write-Host "Checking for Windows updates..."
        Install-WindowsUpdate -AcceptAll -Install
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Update set to automatic and updates installed."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while setting Windows Update to automatic: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Install Windows updates
Start-LoggedJob -JobName "Install Windows Updates" -ScriptBlock {
    try {
        Write-Host "Installing Windows updates..."
        Start-Sleep -Seconds 60

        $maxRetries = 3
        $retryCount = 0
        $success = $false

        while (-not $success -and $retryCount -lt $maxRetries) {
            try {
                Install-WindowsUpdate -AcceptAll -Install
                Write-Host "--------------------------------------------------------------------------------"
                Write-Host "Windows updates installed."
                Write-Host "--------------------------------------------------------------------------------"
                $success = $true
            } catch {
                $retryCount++
                Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                Write-Host "An error occurred while installing Windows updates: $_"
                Write-Host "Retrying... ($retryCount/$maxRetries)"
                Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                Start-Sleep -Seconds 60
            }
        }

        if (-not $success) {
            Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            Write-Host "Failed to install Windows updates after $maxRetries attempts."
            Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        }
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An unexpected error occurred: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Secure and backup DNS to ccdc folder
Start-LoggedJob -JobName "Secure and Backup DNS" -ScriptBlock {
    try {
        dnscmd.exe /Config /SocketPoolSize 10000
        dnscmd.exe /Config /CacheLockingPercent 100
        dnscmd.exe /ZoneExport $zone "$ccdcPath\DNS\$zone.dns"
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "DNS secured and backed up."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while securing and backing up DNS: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Backup AD
Start-LoggedJob -JobName "Backup Active Directory" -ScriptBlock {
    try {
        $timestamp = Get-Date -Format "yyyyMMddHHmmss"
        $backupRoot = "$ccdcPath\AD"
        $backupPath = "$backupRoot\ADBackup_$timestamp"

        if (-Not (Test-Path -Path $backupRoot)) {
            mkdir $backupRoot
        }

        mkdir $backupPath
        ntdsutil.exe "activate instance ntds" "ifm" "create full $backupPath" quit quit
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Active Directory backed up to $backupPath."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while backing up Active Directory: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# # Backup SAM and System Hives
# Start-LoggedJob -JobName "Backup SAM and System Hives" -ScriptBlock {
#     try {
#         $registryPath = "$ccdcPath\Registry"
#         $backupPath = "$registryPath\RegistryBackupSamSystem"

#         # Ensure the backup paths exist
#         if (-not (Test-Path $registryPath)) {
#             mkdir $registryPath
#         }
#         if (-not (Test-Path $backupPath)) {
#             mkdir $backupPath
#         }

#         # Backup the SAM and SYSTEM hives with elevated privileges
#         Start-Process -FilePath "reg.exe" -ArgumentList "save HKLM\SAM $backupPath\SAM.bak" -Verb RunAs -Wait
#         Start-Process -FilePath "reg.exe" -ArgumentList "save HKLM\SYSTEM $backupPath\SYSTEM.bak" -Verb RunAs -Wait

#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "SAM and System hives backed up."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while backing up SAM and System hives: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# # Restrict access to the SAM and System hives to just necessary system accounts
# Start-LoggedJob -JobName "Restrict Access to SAM and System Hives" -ScriptBlock {
#     try {
#         $backupPath = "$ccdcPath\Registry\RegistryBackupSamSystem"
        
#         # Ensure the backup path exists
#         if (-not (Test-Path $backupPath)) {
#             mkdir $backupPath
#         }

#         # Backup the SAM and SYSTEM hives
#         reg save HKLM\SAM "$backupPath\SAM.bak"
#         reg save HKLM\SYSTEM "$backupPath\SYSTEM.bak"

#         # Define necessary system accounts
#         $adminUser = [System.Security.Principal.NTAccount]"Administrator"
#         $systemUser = [System.Security.Principal.NTAccount]"SYSTEM"
#         $trustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"

#         # Function to set ACL for a registry hive
#         function Set-RegistryAcl {
#             param (
#                 [string]$hivePath,
#                 [System.Security.Principal.NTAccount]$adminUser,
#                 [System.Security.Principal.NTAccount]$systemUser,
#                 [System.Security.Principal.NTAccount]$trustedInstaller
#             )

#             $acl = Get-Acl $hivePath
#             $acl.SetAccessRuleProtection($true, $false)

#             # Remove existing access rules
#             $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

#             # Add full control for necessary system accounts
#             $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule($adminUser, "FullControl", "Allow")
#             $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule($systemUser, "FullControl", "Allow")
#             $trustedInstallerRule = New-Object System.Security.AccessControl.RegistryAccessRule($trustedInstaller, "FullControl", "Allow")
#             $acl.AddAccessRule($adminRule)
#             $acl.AddAccessRule($systemRule)
#             $acl.AddAccessRule($trustedInstallerRule)

#             # Apply the modified ACL
#             Set-Acl $hivePath $acl
#         }

#         # Set ACL for SAM hive
#         Set-RegistryAcl -hivePath "HKLM\SAM" -adminUser $adminUser -systemUser $systemUser -trustedInstaller $trustedInstaller

#         # Set ACL for SYSTEM hive
#         Set-RegistryAcl -hivePath "HKLM\SYSTEM" -adminUser $adminUser -systemUser $systemUser -trustedInstaller $trustedInstaller

#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Access to SAM and System hives restricted."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while restricting access to SAM and System hives: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# Create alert for new startup items, create toast notification when new startup item is created, check every 5 seconds, this should be run as a scheduled task
Start-LoggedJob -JobName "Create Alert for New Startup Items" -ScriptBlock {
    try {
        $scriptPath = "$toolsPath\StartupAlert.ps1"
        $taskName = "StartupItemAlert"
        
        # Create the script
        @"
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null

        $startupItems = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
        $previousItems = $startupItems.PSObject.Properties.Name
        
        while ($true) {
            Start-Sleep -Seconds 5
            $currentItems = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
            $newItems = Compare-Object -ReferenceObject $previousItems -DifferenceObject $currentItems.PSObject.Properties.Name | Where-Object { $_.SideIndicator -eq '=>' }
            
            if ($newItems) {
                $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(1)
                $ToastXml = [xml] $Template.GetXml()
                $ToastXml.GetElementsByTagName("text").Item(0).InnerText = "New startup item detected: $($newItems.InputObject)"
                $Toast = [Windows.UI.Notifications.ToastNotification]::new($ToastXml)
                $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Startup Monitor")
                $Notifier.Show($Toast)
                $previousItems += $newItems.InputObject
            }
        }
"@ | Set-Content -Path $scriptPath

        # Create the scheduled task
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -User "SYSTEM" -RunLevel Highest
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Alert for new startup items created."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while creating alert for new startup items: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Lockdown the CCDC folder
Start-LoggedJob -JobName "Lockdown CCDC Folder" -ScriptBlock {
    try {
        $ccdcPath = "C:\CCDC"
        $acl = Get-Acl $ccdcPath
        $acl.SetAccessRuleProtection($true, $false)
        
        # Remove existing access rules
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
        
        # Add full control for necessary system accounts
        $adminUser = [System.Security.Principal.NTAccount]"Administrator"
        $systemUser = [System.Security.Principal.NTAccount]"SYSTEM"
        $trustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminUser, "FullControl", "Allow")
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemUser, "FullControl", "Allow")
        $trustedInstallerRule = New-Object System.Security.AccessControl.FileSystemAccessRule($trustedInstaller, "FullControl", "Allow")
        $acl.AddAccessRule($adminRule)
        $acl.AddAccessRule($systemRule)
        $acl.AddAccessRule($trustedInstallerRule)
        
        # Apply the modified ACL to the CCDC folder
        Set-Acl -Path $ccdcPath -AclObject $acl
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "CCDC folder lockdown complete."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while locking down the CCDC folder: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# # Restrict access to running any commands to Administrator
# Start-LoggedJob -JobName "Restrict Access to Commands" -ScriptBlock {
#     try {
#         $acl = Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
#         $acl.SetAccessRuleProtection($true, $false)
        
#         # Remove existing access rules
#         $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
        
#         # Add full control for necessary system accounts
#         $adminUser = [System.Security.Principal.NTAccount]"Administrator"
#         $systemUser = [System.Security.Principal.NTAccount]"SYSTEM"
#         $trustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
#         $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule($adminUser, "FullControl", "Allow")
#         $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule($systemUser, "FullControl", "Allow")
#         $trustedInstallerRule = New-Object System.Security.AccessControl.RegistryAccessRule($trustedInstaller, "FullControl", "Allow")
#         $acl.AddAccessRule($adminRule)
#         $acl.AddAccessRule($systemRule)
#         $acl.AddAccessRule($trustedInstallerRule)
        
#         # Apply the modified ACL to the registry key
#         Set-Acl -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -AclObject $acl
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Access to running commands restricted to Administrator."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while restricting access to running commands: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# Disable all ports except the ones needed for AD/DNS
try {
    # Block all inbound traffic
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    
    # Allow inbound traffic for necessary services
    $rules = @(
        @{Name="NTP in"; Port=123; Protocol="UDP"},
        @{Name="Allow Pings in"; Protocol="ICMPv4"},
        @{Name="DNS IN (UDP)"; Port=53; Protocol="UDP"},
        @{Name="DNS IN (TCP)"; Port=53; Protocol="TCP"},
        @{Name="LDAP TCP IN"; Port="389,636,3268,3269,135,1024-65535,49152-65535,88,464,53,123,445,135,137-139,389-636,3268-3269,135-135,1024-65535,49152-65535,88-88,464-464,53-53,123-123,445-445"; Protocol="TCP"},
        @{Name="LDAP UDP IN"; Port="389,636,3268,3269,135,1024-65535,49152-65535,88,464,53,123,445,135,137-139,389-636,3268-3269,135-135,1024-65535,49152-65535,88-88,464-464,53-53,123-123,445-445"; Protocol="UDP"},
        @{Name="LDAP Global Catalog IN"; Port=3268; Protocol="TCP"},
        @{Name="NETBIOS Resolution IN"; Port=137; Protocol="UDP"},
        @{Name="Secure LDAP IN"; Port=636; Protocol="TCP"},
        @{Name="Secure LDAP Global Catalog IN"; Port=3269; Protocol="TCP"},
        @{Name="RPC IN"; Port=135; Protocol="TCP"},
        @{Name="RPC-EPMAP IN"; Port=135; Protocol="TCP"},
        @{Name="DHCP UDP IN"; Port=67; Protocol="UDP"}
    )

    foreach ($rule in $rules) {
        if ($rule.Port -and $rule.Protocol) {
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow -Enabled True -Profile Any -LocalPort $rule.Port -Protocol $rule.Protocol | Out-Null
            Write-Host "Allowed: $($rule.Name) on port $($rule.Port)"
        } elseif ($rule.Protocol) {
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol $rule.Protocol | Out-Null
            Write-Host "Allowed: $($rule.Name) with protocol $($rule.Protocol)"
        } else {
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow -Enabled True -Profile Any | Out-Null
            Write-Host "Allowed: $($rule.Name)"
        }
    }

    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "All ports except AD/DNS disabled."
    Write-Host "--------------------------------------------------------------------------------"
} catch {
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Write-Host "An error occurred while disabling all ports except AD/DNS: $_"
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
}

# Create alert for Audit WMI subscriptions
Start-LoggedJob -JobName "Create Alert for Audit WMI Subscriptions" -ScriptBlock {
    try {
        $scriptPath = "$toolsPath\WmiAlert.ps1"
        $taskName = "WmiAlert"
        
        # Create the script
        @"
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null

        $wmiSubscriptions = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
        $previousSubscriptions = $wmiSubscriptions.PSObject.Properties.Name
        
        while ($true) {
            Start-Sleep -Seconds 5
            $currentSubscriptions = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
            $newSubscriptions = Compare-Object -ReferenceObject $previousSubscriptions -DifferenceObject $currentSubscriptions.PSObject.Properties.Name | Where-Object { $_.SideIndicator -eq '=>' }
            
            if ($newSubscriptions) {
                $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(1)
                $ToastXml = [xml] $Template.GetXml()
                $ToastXml.GetElementsByTagName("text").Item(0).InnerText = "New WMI subscription detected: $($newSubscriptions.InputObject)"
                $Toast = [Windows.UI.Notifications.ToastNotification]::new($ToastXml)
                $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("WMI Monitor")
                $Notifier.Show($Toast)
                $previousSubscriptions += $newSubscriptions.InputObject
            }
        }
"@ | Set-Content -Path $scriptPath

        # Create the scheduled task
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -User "SYSTEM" -RunLevel Highest
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Alert for Audit WMI subscriptions created."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while creating alert for Audit WMI subscriptions: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Remove .bat or .lnk files in startup folder using scheduled task to fight persistence
Start-LoggedJob -JobName "Remove .bat or .lnk Files in Startup Folder" -ScriptBlock {
    try {
        $scriptPath = "$toolsPath\RemoveStartupFiles.ps1"
        $taskName = "RemoveStartupFiles"
        
        # Create the script
        @"
        $startupFolder = [System.Environment]::GetFolderPath('Startup')
        $filesToRemove = Get-ChildItem -Path $startupFolder -Filter "*.bat", "*.lnk"
        
        foreach ($file in $filesToRemove) {
            Remove-Item -Path $file.FullName -Force
            [System.Windows.MessageBox]::Show("Removed startup file: $($file.Name)")
        }
"@ | Set-Content -Path $scriptPath
        # Create the scheduled task
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -User "SYSTEM" -RunLevel Highest
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Scheduled task to remove .bat or .lnk files in startup folder created."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while creating scheduled task to remove .bat or .lnk files in startup folder: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Stop non admin users from installing software or running commands
Start-LoggedJob -JobName "Restrict Non-Admin Users from Installing Software" -ScriptBlock {
    try {
        $acl = Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        $acl.SetAccessRuleProtection($true, $false)
        
        # Clear existing access rules
        $acl.SetAccessRuleProtection($true, $true)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
        
        # Add full control for necessary system accounts
        $adminUser = [System.Security.Principal.NTAccount]"Administrator"
        $systemUser = [System.Security.Principal.NTAccount]"SYSTEM"
        $trustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
        $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule($adminUser, "FullControl", "Allow")
        $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule($systemUser, "FullControl", "Allow")
        $trustedInstallerRule = New-Object System.Security.AccessControl.RegistryAccessRule($trustedInstaller, "FullControl", "Allow")
        $acl.AddAccessRule($adminRule)
        $acl.AddAccessRule($systemRule)
        $acl.AddAccessRule($trustedInstallerRule)
        
        # Apply the modified ACL to the registry key
        Set-Acl -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -AclObject $acl
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Non-admin users restricted from installing software."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while restricting non-admin users from installing software: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Block credential dumping
Start-LoggedJob -JobName "Block Credential Dumping" -ScriptBlock {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $regPath -Name "NoLmHash" -Value 1
        Set-ItemProperty -Path $regPath -Name "LimitBlankPasswordUse" -Value 1
        Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 1
        Set-ItemProperty -Path $regPath -Name "RestrictAnonymousSAM" -Value 1
        Set-ItemProperty -Path $regPath -Name "EveryoneIncludesAnonymous" -Value 0
        Set-ItemProperty -Path $regPath -Name "NoDefaultAdminShares" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoLMAuthentication" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionShares" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionUsername" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionPassword" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoSaveSettings" -Value 1
        
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Set-ItemProperty -Path $regPath -Name "AutoShareWks" -Value 0
        Set-ItemProperty -Path $regPath -Name "AutoShareServer" -Value 0
        Set-ItemProperty -Path $regPath -Name "RestrictNullSessAccess" -Value 1
        Set-ItemProperty -Path $regPath -Name "NullSessionPipes" -Value ""
        Set-ItemProperty -Path $regPath -Name "NullSessionShares" -Value ""
        Set-ItemProperty -Path $regPath -Name "Samba" -Value 0

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        Set-ItemProperty -Path $regPath -Name "EnableSecuritySignature" -Value 1
        Set-ItemProperty -Path $regPath -Name "RequireSecuritySignature" -Value 1
        Set-ItemProperty -Path $regPath -Name "EnablePlainTextPassword" -Value 0
        
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Credential dumping blocked."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
        Write-Host "An error occurred while blocking credential dumping: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
    }
}

# block unnecessary winrm traffic
Start-LoggedJob -JobName "Block Unnecessary WinRM Traffic" -ScriptBlock {
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"
        
        # Ensure the registry path exists
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $regPath -Name "AllowWinRM" -Value 0
        Set-ItemProperty -Path $regPath -Name "AllowWinRMHTTP" -Value 0
        Set-ItemProperty -Path $regPath -Name "AllowWinRMHTTPS" -Value 0
        
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $regPath -Name "EnableLUA" -Value 0
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Unnecessary WinRM traffic blocked."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while blocking unnecessary WinRM traffic: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# disable remote sign in
Start-LoggedJob -JobName "Disable Remote Sign-in" -ScriptBlock {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $regPath -Name "EnableLUA" -Value 0
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Remote sign-in disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling remote sign-in: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Enable LSA Protection, restrict debug privileges, disable WDigest
Start-LoggedJob -JobName "Enable LSA Protection" -ScriptBlock {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $regPath -Name "LsaCfgFlags" -Value 1
        Set-ItemProperty -Path $regPath -Name "RunAsPPL" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "LSA Protection enabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while enabling LSA Protection: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}
Start-LoggedJob -JobName "Restrict Debug Privileges" -ScriptBlock {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 1
        Set-ItemProperty -Path $regPath -Name "RestrictAnonymousSAM" -Value 1
        Set-ItemProperty -Path $regPath -Name "EveryoneIncludesAnonymous" -Value 0
        Set-ItemProperty -Path $regPath -Name "NoDefaultAdminShares" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoLMAuthentication" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionShares" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionUsername" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoNullSessionPassword" -Value 1
        Set-ItemProperty -Path $regPath -Name "NoSaveSettings" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Debug privileges restricted."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while restricting debug privileges: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}
Start-LoggedJob -JobName "Disable WDigest" -ScriptBlock {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        Set-ItemProperty -Path $regPath -Name "UseLogonCredential" -Value 0
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "WDigest disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling WDigest: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# disable powershell remoting
Start-LoggedJob -JobName "Disable PowerShell Remoting" -ScriptBlock {
    try {
        # Disable PSRemoting
        Disable-PSRemoting -Force

        # Stop and disable the WinRM service
        Stop-Service -Name WinRM -Force
        Set-Service -Name WinRM -StartupType Disabled

        # Delete the listener that accepts requests on any IP address
        winrm delete winrm/config/Listener?Address=*+Transport=HTTP
        winrm delete winrm/config/Listener?Address=*+Transport=HTTPS

        # Disable the firewall exceptions for WS-Management communications
        Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -Enabled False
        Set-NetFirewallRule -Name "WINRM-HTTPS-In-TCP" -Enabled False

        # Restore the value of the LocalAccountTokenFilterPolicy to 0
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $regPath -Name "LocalAccountTokenFilterPolicy" -Value 0

        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "PowerShell remoting disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling PowerShell remoting: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Additional security measures
Start-LoggedJob -JobName "Configure Windows Defender Exploit Guard" -ScriptBlock {
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled
        
        # Configure system-level mitigations
        Set-ProcessMitigation -System -Enable DEP, SEHOP, ForceRelocateImages, BottomUp, HighEntropy
        
        # Configure attack surface reduction rules
        Set-MpPreference -AttackSurfaceReductionRules_Ids @(
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block executable content from email and webmail clients
            "3B576869-A4EC-4529-8536-B80A7769E899",  # Block executable content from Office files
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",  # Block credential stealing from LSASS
            "D1E49AAC-8F56-4280-B9BA-993A6D77406C"   # Block executable content from Office files that contain macros
        )
        Set-MpPreference -AttackSurfaceReductionRules_Actions @("Enable", "Enable", "Enable", "Enable")
        
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Defender Exploit Guard configured."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while configuring Windows Defender Exploit Guard: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Configure Network Level Authentication for Remote Desktop" -ScriptBlock { 
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1 
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "AllowRemoteRPC" -Value 0
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Network Level Authentication for Remote Desktop configured."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while configuring Network Level Authentication for Remote Desktop: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Disable LM and NTLMv1 Protocols" -ScriptBlock {
    try {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LmCompatibilityLevel" -Value 5 
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name "SMB1" -Value 0
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name "EnableSecuritySignature" -Value 1
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name "RequireSecuritySignature" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "LM and NTLMv1 protocols disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling LM and NTLMv1 protocols: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Enable Windows Defender Credential Guard" -ScriptBlock {
    try {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name "EnableVirtualizationBasedSecurity" -Value 1
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LsaCfgFlags" -Value 1
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "RunAsPPL" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Defender Credential Guard enabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while enabling Windows Defender Credential Guard: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Configure Windows Update to Install Updates Automatically" -ScriptBlock { 
    try {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name "AUOptions" -Value 4 
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Windows Update configured to install updates automatically."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while configuring Windows Update: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Start-LoggedJob -JobName "Enable Logging for PowerShell" -ScriptBlock {
#     try {
#         Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name "EnableScriptBlockLogging" -Value 1
#         Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name "EnableTranscripting" -Value 1
#         Write-Host "--------------------------------------------------------------------------------"
#         Write-Host "Logging for PowerShell enabled."
#         Write-Host "--------------------------------------------------------------------------------"
#     } catch {
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#         Write-Host "An error occurred while enabling logging for PowerShell: $_"
#         Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#     }
# }

# Disable PSExec
Start-LoggedJob -JobName "Disable PSExec" -ScriptBlock {
    try {
        $psexecPath = "C:\Windows\System32\psexec.exe"
        if (Test-Path $psexecPath) {
            Remove-Item $psexecPath -Force
            Write-Host "--------------------------------------------------------------------------------"
            Write-Host "PSExec has been disabled."
            Write-Host "--------------------------------------------------------------------------------"
        } else {
            Write-Host "---------------------------------------------------------------------------------"
            Write-Host "PSExec is not present on the system."
            Write-Host "---------------------------------------------------------------------------------"
        }
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling PSExec: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Disable Sign-in for users not in the Administrators group
try {
    $users = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" -and $_.PrincipalSource -eq 'Local' }
    foreach ($user in $users) {
        $userGroups = (Get-LocalGroupMember -Group "Administrators").Name
        if ($user.Name -notin $userGroups) {
            Disable-LocalUser -Name $user.Name
            Write-Host "--------------------------------------------------------------------------------"
            Write-Host "Sign-in for user $($user.Name) has been disabled."
            Write-Host "--------------------------------------------------------------------------------"
        }
    }
} catch {
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Write-Host "An error occurred: $_"
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
}

# Disable RDP
Start-LoggedJob -JobName "Disable RDP" -ScriptBlock {
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "RDP has been disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling RDP: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}




# Perform a quick scan with Windows Defender
Start-LoggedJob -JobName "Quick Scan with Windows Defender" -ScriptBlock { 
    try {
        Start-MpScan -ScanType QuickScan
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Quick scan with Windows Defender completed."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
        Write-Host "An error occurred while performing a quick scan with Windows Defender: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" 
    }
}

Start-LoggedJob -JobName "Remove RDP Users" -ScriptBlock {
    try {
        $rdpGroup = "Remote Desktop Users"
        $users = Get-LocalGroupMember -Group $rdpGroup
        foreach ($user in $users) {
            Remove-LocalGroupMember -Group $rdpGroup -Member $user
            Write-Host "--------------------------------------------------------------------------------"
            Write-Host "Removed $($user.Name) from $rdpGroup."
            Write-Host "--------------------------------------------------------------------------------"
        }
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while removing RDP users: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Disable RDP" -ScriptBlock {
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "RDP has been disabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while disabling RDP: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Enable UAC" -ScriptBlock {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $regPath -Name "ConsentPromptBehaviorAdmin" -Value 1
        Set-ItemProperty -Path $regPath -Name "EnableLUA" -Value 1
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "UAC enabled."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while enabling UAC: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Harden IIS" -ScriptBlock {
    try {
        $iisCmds = @(
            "C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /requestLimits.maxQueryString:2048",
            "C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /allowHighBitCharacters:false",
            "C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /allowDoubleEscaping:false",
            "C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='TRACE',allowed='false']",
            "C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /fileExtensions.allowunlisted:false",
            "C:\windows\system32\inetsrv\appcmd.exe set config /section:handlers /accessPolicy:Read",
            "C:\windows\system32\inetsrv\appcmd.exe set config -section:system.webServer/security/isapiCgiRestriction /notListedIsapisAllowed:false",
            "C:\windows\system32\inetsrv\appcmd.exe set config -section:system.webServer/security/isapiCgiRestriction /notListedCgisAllowed:false"
        )
        foreach ($cmd in $iisCmds) {
            Invoke-Expression $cmd
        }
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "IIS hardened."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while hardening IIS: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Patch Mimikatz" -ScriptBlock {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        if (Test-Path $regPath) {
            Set-ItemProperty -Path $regPath -Name "UseLogonCredential" -Value 0
        }
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Mimikatz patched."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while patching Mimikatz: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Patch DCSync Vulnerability" -ScriptBlock {
    try {
        Import-Module ActiveDirectory
        $permissions = Get-ACL "AD:\DC=domain,DC=com" | Select-Object -ExpandProperty Access
        $criticalPermissions = $permissions | Where-Object { $_.ObjectType -eq "19195a5b-6da0-11d0-afd3-00c04fd930c9" -or $_.ObjectType -eq "4c164200-20c0-11d0-a768-00aa006e0529" }
        foreach ($permission in $criticalPermissions) {
            if ($permission.ActiveDirectoryRights -match "Replicating Directory Changes") {
                Write-Host "Removing Replicating Directory Changes permission from $($permission.IdentityReference)"
                $permissions.RemoveAccessRule($permission)
            }
        }
        Set-ACL -Path "AD:\DC=domain,DC=com" -AclObject $permissions
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "DCSync vulnerability patched."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while patching DCSync vulnerability: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Upgrade SMB" -ScriptBlock {
    try {
        $smbv1Enabled = (Get-SmbServerConfiguration).EnableSMB1Protocol
        $smbv2Enabled = (Get-SmbServerConfiguration).EnableSMB2Protocol
        $restart = $false

        if ($smbv1Enabled -eq $true) {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
            $restart = $true
        }

        if ($smbv2Enabled -eq $false) {
            Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
            $restart = $true
        }

        if ($restart -eq $true) {
            Write-Host "Please consider restarting the machine for changes to take effect."
        }
        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "SMB upgraded."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while upgrading SMB: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

Start-LoggedJob -JobName "Configure Secure GPO" -ScriptBlock {
    try {
        Import-Module GroupPolicy

        $gpoName = "SecureGPO"
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            $gpo = New-GPO -Name $gpoName
        }

        
                # Define configurations
                $configurations = @{
                    "Prevent Windows from Storing LAN Manager Hash" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "NoLMHash"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
                    "Disable Forced System Restarts" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
                        "ValueName" = "NoAutoRebootWithLoggedOnUsers"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
                    "Disable Guest Account" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                        "ValueName" = "AllowGuest"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
                    "Disable Anonymous SID Enumeration" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "RestrictAnonymousSAM"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
                    "Enable Event Logs" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\Eventlog\Application"
                        "ValueName" = "AutoBackupLogFiles"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
                    "Disable Anonymous Account in Everyone Group" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "EveryoneIncludesAnonymous"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
                    "Enable User Account Control" = @{
                        "Key" = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                        "ValueName" = "EnableLUA"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
                    "Disable WDigest UseLogonCredential" = @{
                        "Key" = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest"
                        "ValueName" = "UseLogonCredential"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
                    "Disable WDigest Negotiation" = @{
                        "Key" = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest"
                        "ValueName" = "Negotiate"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
                    "Enable LSASS protection" = @{
                        "Key" = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA"
                        "ValueName" = "RunAsPPL"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
                    "Disable Restricted Admin" = @{
                        "Key" = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA"
                        "ValueName" = "DisableRestrictedAdmin"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
        # # Configure Windows Defender Antivirus settings via Group Policy to enable real-time monitoring
                    "Configure DisableAutoExclusions" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions"
                        "ValueName" = "DisableAutoExclusions"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
        
                    "Configure MpCloudBlockLevel" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine"
                        "ValueName" = "MpCloudBlockLevel"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableDatagramProcessing" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\NIS"
                        "ValueName" = "DisableDatagramProcessing"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableProtocolRecognition" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\NIS"
                        "ValueName" = "DisableProtocolRecognition"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableSignatureRetirement" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS"
                        "ValueName" = "DisableSignatureRetirement"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure LocalSettingOverridePurgeItemsAfterDelay" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Quarantine"
                        "ValueName" = "LocalSettingOverridePurgeItemsAfterDelay"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableRealtimeMonitoring" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "DisableRealtimeMonitoring"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableBehaviorMonitoring" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "DisableBehaviorMonitoring"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableIOAVProtection" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "DisableIOAVProtection"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableOnAccessProtection" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "DisableOnAccessProtection"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableRawWriteNotification" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "DisableRawWriteNotification"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableScanOnRealtimeEnable" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "DisableScanOnRealtimeEnable"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableScriptScanning" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "DisableScriptScanning"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure LocalSettingOverrideDisableBehaviorMonitoring" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "LocalSettingOverrideDisableBehaviorMonitoring"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure LocalSettingOverrideDisableIOAVProtection" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "LocalSettingOverrideDisableIOAVProtection"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure LocalSettingOverrideDisableOnAccessProtection" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "LocalSettingOverrideDisableOnAccessProtection"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure LocalSettingOverrideDisableRealtimeMonitoring" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "LocalSettingOverrideDisableRealtimeMonitoring"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure LocalSettingOverrideRealtimeScanDirection" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "LocalSettingOverrideRealtimeScanDirection"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure RealtimeScanDirection" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                        "ValueName" = "RealtimeScanDirection"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableHeuristics" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Scan"
                        "ValueName" = "DisableHeuristics"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisablePackedExeScanning" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Scan"
                        "ValueName" = "DisablePackedExeScanning"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableRemovableDriveScanning" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Scan"
                        "ValueName" = "DisableRemovableDriveScanning"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure ScanParameters" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Scan"
                        "ValueName" = "ScanParameters"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
         
                    "Configure QuickScanInterval" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Scan"
                        "ValueName" = "QuickScanInterval"
                        "Value" = 2
                        "Type" = "DWORD"
                    }
         
                    "Configure MeteredConnectionUpdates" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                        "ValueName" = "MeteredConnectionUpdates"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableScanOnUpdate" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                        "ValueName" = "DisableScanOnUpdate"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableScheduledSignatureUpdateOnBattery" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                        "ValueName" = "DisableScheduledSignatureUpdateOnBattery"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableUpdateOnStartupWithoutEngine" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                        "ValueName" = "DisableUpdateOnStartupWithoutEngine"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure ForceUpdateFromMU" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                        "ValueName" = "ForceUpdateFromMU"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
         
                    "Configure RealtimeSignatureDelivery" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                        "ValueName" = "RealtimeSignatureDelivery"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
         
                    "Configure SignatureDisableNotification" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                        "ValueName" = "SignatureDisableNotification"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure UpdateOnStartUp" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                        "ValueName" = "UpdateOnStartUp"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
         
                    "Configure DisableBlockAtFirstSeen" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet"
                        "ValueName" = "DisableBlockAtFirstSeen"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure SpynetReporting" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet"
                        "ValueName" = "SpynetReporting"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
         
                    "Configure LocalSettingOverrideSpynetReporting" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet"
                        "ValueName" = "LocalSettingOverrideSpynetReporting"
                        "Value" = 0
                        "Type" = "DWORD"
                    }
         
                    "Configure EnableControlledFolderAccess" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
                        "ValueName" = "EnableControlledFolderAccess"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
        
                    "Configure AllowNetworkProtectionOnWinServer" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
                        "ValueName" = "AllowNetworkProtectionOnWinServer"
                        "Value" = 1
                        "Type" = "DWORD"
                    }
         
                    "Configure EnableNetworkProtection" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
                        "ValueName" = "EnableNetworkProtection"
                        "Value" = 2
                        "Type" = "DWORD"
                    }
                #other best practice keys
                    "Configure SecurityLevel" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
                        "ValueName" = "SecurityLevel"
                        "Type" = "DWORD"
                        "Value" = 0
                    }
                    "Configure SetCommand" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
                        "ValueName" = "SetCommand"
                        "Type" = "DWORD"
                        "Value" = 0
                    }
                    "Configure AllocateCDRoms" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                        "ValueName" = "AllocateCDRoms"
                        "Type" = "String"
                        "Value" = "1"
                    }
                    "Configure AllocateFloppies" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                        "ValueName" = "AllocateFloppies"
                        "Type" = "String"
                        "Value" = "1"
                    }
                    "Configure CachedLogonsCount" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                        "ValueName" = "CachedLogonsCount"
                        "Type" = "String"
                        "Value" = "0"
                    }
                    "Configure ForceUnlockLogon" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                        "ValueName" = "ForceUnlockLogon"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure ConsentPromptBehaviorAdmin" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                        "ValueName" = "ConsentPromptBehaviorAdmin"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure ConsentPromptBehaviorUser" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                        "ValueName" = "ConsentPromptBehaviorUser"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure DisableCAD" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                        "ValueName" = "DisableCAD"
                        "Type" = "DWORD"
                        "Value" = 0
                    }
                    "Configure EnableLUA" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                        "ValueName" = "EnableLUA"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure FilterAdministratorToken" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                        "ValueName" = "FilterAdministratorToken"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure NoConnectedUser" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                        "ValueName" = "NoConnectedUser"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure PromptOnSecureDesktop" = @{
                        "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                        "ValueName" = "PromptOnSecureDesktop"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure ForceKeyProtection" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Cryptography"
                        "ValueName" = "ForceKeyProtection"
                        "Type" = "DWORD"
                        "Value" = 2
                    }
                    "Configure AuthenticodeEnabled" = @{
                        "Key" = "HKLM\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
                        "ValueName" = "AuthenticodeEnabled"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure AuditBaseObjects" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "AuditBaseObjects"
                        "Type" = "DWORD"
                        "Value" = 0
                    }
                    "Configure DisableDomainCreds" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "DisableDomainCreds"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure EveryoneIncludesAnonymous" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "EveryoneIncludesAnonymous"
                        "Type" = "DWORD"
                        "Value" = 0
                    }
                    "Configure Enabled" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
                        "ValueName" = "Enabled"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure FullPrivilegeAuditing" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "FullPrivilegeAuditing"
                        "Type" = "Binary"
                        "Value" = 0
                    }
                    "Configure LimitBlankPasswordUse" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "LimitBlankPasswordUse"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure NTLMMinClientSec" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0"
                        "ValueName" = "NTLMMinClientSec"
                        "Type" = "DWORD"
                        "Value" = 537395200
                    }
                    "Configure NTLMMinServerSec" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0"
                        "ValueName" = "NTLMMinServerSec"
                        "Type" = "DWORD"
                        "Value" = 537395200
                    }
                    "Configure NoLMHash" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "NoLMHash"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure RestrictAnonymous" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "RestrictAnonymous"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure RestrictAnonymousSAM" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "RestrictAnonymousSAM"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure RestrictRemoteSAM" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "RestrictRemoteSAM"
                        "Type" = "String"
                        "Value" = "O:BAG:BAD:(A;;RC;;;BA)"
                    }
                    "Configure SCENoApplyLegacyAuditPolicy" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "SCENoApplyLegacyAuditPolicy"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure SubmitControl" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                        "ValueName" = "SubmitControl"
                        "Type" = "DWORD"
                        "Value" = 0
                    }
                    "Configure AddPrinterDrivers" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
                        "ValueName" = "AddPrinterDrivers"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure Winreg Exact Paths" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
                        "ValueName" = "Machine"
                        "Type" = "MultiString"
                        "Value" =  ""
                    }
                    "Configure Winreg Allowed Paths" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
                        "ValueName" = "Machine"
                        "Type" = "MultiString"
                        "Value" = ""
                    }
                    "Configure ProtectionMode" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Control\Session Manager"
                        "ValueName" = "ProtectionMode"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure EnableSecuritySignature" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters"
                        "ValueName" = "EnableSecuritySignature"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure RequireSecuritySignature" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters"
                        "ValueName" = "RequireSecuritySignature"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure RestrictNullSessAccess" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters"
                        "ValueName" = "RestrictNullSessAccess"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure EnablePlainTextPassword" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
                        "ValueName" = "EnablePlainTextPassword"
                        "Type" = "DWORD"
                        "Value" = 0
                    }
                    "Configure EnableSecuritySignature Workstation" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
                        "ValueName" = "EnableSecuritySignature"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure RequireSecuritySignature Workstation" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
                        "ValueName" = "RequireSecuritySignature"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure LDAPClientIntegrity" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\LDAP"
                        "ValueName" = "LDAPClientIntegrity"
                        "Type" = "DWORD"
                        "Value" = 2
                    }
                    "Configure DisablePasswordChange" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                        "ValueName" = "DisablePasswordChange"
                        "Type" = "DWORD"
                        "Value" = 0
                    }
                    "Configure RefusePasswordChange" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                        "ValueName" = "RefusePasswordChange"
                        "Type" = "DWORD"
                        "Value" = 0
                    }
                    "Configure RequireSignOrSeal" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                        "ValueName" = "RequireSignOrSeal"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure RequireStrongKey" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                        "ValueName" = "RequireStrongKey"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure SealSecureChannel" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                        "ValueName" = "SealSecureChannel"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure SignSecureChannel" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                        "ValueName" = "SignSecureChannel"
                        "Type" = "DWORD"
                        "Value" = 1
                    }
                    "Configure LdapEnforceChannelBinding" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\NTDS\Parameters"
                        "ValueName" = "LdapEnforceChannelBinding"
                        "Type" = "DWORD"
                        "Value" = 2
                    }
                    "Configure LDAPServerIntegrity" = @{
                        "Key" = "HKLM\System\CurrentControlSet\Services\NTDS\Parameters"
                        "ValueName" = "LDAPServerIntegrity"
                        "Type" = "DWORD"
                        "Value" = 2
                    }
        
                }

                $successfulConfigurations = 0
                $failedConfigurations = @()

                # Loop through configurations
                foreach ($configName in $configurations.Keys) {
                    $config = $configurations[$configName]
                    $keyPath = $config["Key"]

                    # Set GPO registry value
                    try {
                        Set-GPRegistryValue -Name $GPOName -Key $config["Key"] -ValueName $config["ValueName"] -Value $config["Value"] -Type $config["Type"]
                        $successfulConfigurations++
                    } catch {
                        $failedConfigurations += $configName
                    }
                }

                Write-Host "$successfulConfigurations configurations successfully applied." -ForegroundColor Green

                if ($failedConfigurations.Count -gt 0) {
                    Write-Host "`nConfigurations that couldn't be applied:" -ForegroundColor Red
                    $failedConfigurations
                } else {
                    Write-Host "All configurations applied successfully." -ForegroundColor Green
                }

                Write-Host "Applying gpupdate across all machines on the domain" -ForegroundColor Magenta
                Global-Gpupdate
            } catch {
                Write-Host $_.Exception.Message -ForegroundColor Yellow
                Write-Host "Error Occurred..."
            }
        }

        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Secure GPO configured."
        Write-Host "--------------------------------------------------------------------------------"
    catch {
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Write-Host "An error occurred while configuring Secure GPO: $_"
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
}
Start-LoggedJob -JobName "Create Good GPO" -ScriptBlock {
    try {
        Import-Module GroupPolicy

        $gpoName = "GoodGPO"
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            $gpo = New-GPO -Name $gpoName
        }

        # Configure GPO settings
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Type DWord -Value 0
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -Type DWord -Value 4
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallDay" -Type DWord -Value 0
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallTime" -Type DWord -Value 3

        # Link GPO to domain
        $domain = (Get-ADDomain).DistinguishedName
        New-GPLink -Name $gpoName -Target $domain

        Write-Host "--------------------------------------------------------------------------------"
        Write-Host "Good GPO created."
        Write-Host "--------------------------------------------------------------------------------"
    } catch {
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        Write-Host "An error occurred while creating Good GPO: $_"
        Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    }
}

# Monitor jobs
while ($jobs.Count -gt 0) {
    foreach ($job in $jobs) {
        if ($job.State -eq 'Completed') {
            $job | Receive-Job
            $jobs = $jobs | Where-Object { $_.Id -ne $job.Id }
        }
    }
    Start-Sleep -Seconds 5
}
# Ask the user if they want to run the installs
$runInstalls = Read-Host "Do you want to run the installs? (yes/no)"
if ($runInstalls -ne "yes") {
    Write-Host "Skipping installs..."
    exit
}
else {
    # Set the installer script run on start
    $scriptPath = "$toolsPath\Installs.ps1"
    $entryName = "MyStartupScript"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName -Value "powershell.exe -File `"$scriptPath`""
}

# # Monitor jobs
# while ($global:jobs.Count -gt 0) {
#     foreach ($job in $global:jobs) {
#         if ($job.State -eq 'Completed') {
#             Write-Host "$(Get-Date -Format 'HH:mm:ss') - $($job.Name) has completed."
#             $job | Receive-Job
#             Remove-Job -Job $job
#             $global:jobs = $global:jobs | Where-Object { $_.Id -ne $job.Id }
#         }
#     }
#     Start-Sleep -Seconds 5
# }



Write-Host "All jobs have completed or maximum wait time exceeded."
# Wait for all jobs to complete
Get-Job | Wait-Job
Write-Host "All jobs have completed."
# Restart the computer
Write-Host "--------------------------------------------------------------------------------"
Write-Host "Restarting Computer"
Write-Host "--------------------------------------------------------------------------------"
Restart-Computer
