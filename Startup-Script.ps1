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

# Download the update script
$installScriptPath = "$toolsPath\Win-Update.ps1"
Write-Host "Downloading install script..."
Invoke-WebRequest "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Windows/Win-Update.ps1" -OutFile $installScriptPath

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

# Get what Windows is running
$productName = (Get-ComputerInfo).WindowsProductName
if ($productName -eq "Windows Server 2019 Standard") {
    if ((Get-WindowsFeature -Name AD-Domain-Services).installed) {
        # Download hardening script
        $ScriptPath = "$toolsPath\ad-hardening.ps1"
        Write-Host "Downloading hardening script..."
        Invoke-WebRequest "https://github.com/Baglesrfine/CCDL-Windows/raw/refs/heads/main/ad-hardening.ps1" -OutFile $ScriptPath
        & "$toolsPath\ad-hardening.ps1"
    } else {
        # Download hardening script
        $ScriptPath = "$toolsPath\server2019-hardening.ps1"
        Write-Host "Downloading hardening script..."
        Invoke-WebRequest "https://github.com/Baglesrfine/CCDL-Windows/raw/refs/heads/main/server2019-hardening.ps1" -OutFile $ScriptPath
        & "$toolsPath\server2019-hardening.ps1"
    }
}
else {
    $ScriptPath = "$toolsPath\consumner-windows-hardening.ps1"
    Write-Host "Downloading hardening script..."
    Invoke-WebRequest "https://github.com/Baglesrfine/CCDL-Windows/raw/refs/heads/main/consumner-windows-hardening.ps1" -OutFile $ScriptPath
    & "$toolsPath\consumner-windows-hardening.ps1"
}

# Set the installer script run on start
$scriptPath = "$toolsPath\Installs.ps1"
$entryName = "MyStartupScript"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName -Value "powershell.exe -File `"$scriptPath`""

Write-Host "All jobs have completed or maximum wait time exceeded."
# Wait for all jobs to complete
Get-Job | Wait-Job
Write-Host "All jobs have completed."
# Restart the computer
Write-Host "--------------------------------------------------------------------------------"
Write-Host "Restarting Computer"
Write-Host "--------------------------------------------------------------------------------"
Restart-Computer