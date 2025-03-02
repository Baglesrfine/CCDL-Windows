$ccdcPath = "C:\CCDC"
$toolsPath = "$ccdcPath\tools-Windows"
mkdir "$toolsPath\GPOs"

# Download Group Policy
$tools = @(
    @{ Name = "Windows Defender GPOs"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Defender-gpos.zip"; Path = "$toolsPath\Defender-gpos.zip" },
    @{ Name = "Firefox GPOs"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Firefox-gpos.zip"; Path = "$toolsPath\Firefox-gpos.zip" },
    @{ Name = "Edge GPOs"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/MS-Edge-gpos.zip"; Path = "$toolsPath\MS-Edge-gpos.zip" },
    @{ Name = "Windows 10 GPOs"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Windows-10-gpos.zip"; Path = "$toolsPath\Windows-10-gpos.zip" },
    @{ Name = "Windows 2019 GPOs"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/Windows-2019-gpos.zip"; Path = "$toolsPath\Windows-2019-gpos.zip" }
)

foreach ($tool in $tools) {
    Write-Host "Downloading $($tool.Name)..."
    Start-BitsTransfer -Source $tool.Url -Destination $tool.Path
}

# Unzip the GPOs
foreach ($tool in $tools) {
    if ($tool.Path -like "*.zip") {
        $destinationPath = [System.IO.Path]::GetDirectoryName($tool.Path)
        Write-Host "Extracting $($tool.Name) to $destinationPath..."
        Expand-Archive -Path $tool.Path -DestinationPath $destinationPath -Force
    }
}

# Define the path to the specific GPO folder
#$gpoFolder = "$env:TEMP\DoD_GPOs\DoD WinSvr 2019 MS and DC v3r2\GPOs"
#$wmiFilterFolder = "$env:TEMP\DoD_GPOs\DoD WinSvr 2019 MS and DC v3r2\WMI Filter"
$gpoFolders = @(
    @{ Name = 'Defender' Path = "$toolsPath\Defender-gpos"},
    @{ Name = 'Firefox' Path = "$toolsPath\Firefox-gpos"},
    @{ Name = 'Edge' Path = "$toolsPath\MS-Edge-gpos"},
    @{ Name = 'Windows 10' Path = "$toolsPath\Windows-10-gpos"},
    @{ Name = 'Windows 2019' Path = "$toolsPath\Windows-2019-gpos"}
)

# Import the GPOs
Write-Host "Importing DoD GPOs..."
foreach (gpoFolder in gpoFolders) {
    $gpoSubFolders = Get-ChildItem -Path $gpoFolder.Path -Directory
    foreach ($gpoSubFolder in $gpoSubFolders) {
        $gpoName = $gpoSubFolder.Name
        Write-Host "Importing GPO: $gpoName"
        Import-GPO -BackupGpoName $gpoName -Path $gpoSubFolder.FullName
    }
}

# Apply WMI filters if they exist
# if (Test-Path $wmiFilterFolder) {
#     Write-Host "Applying WMI Filters..."
#     $wmiFilterFiles = Get-ChildItem -Path $wmiFilterFolder -Filter "*.xml"
#     foreach ($wmiFilterFile in $wmiFilterFiles) {
#         Write-Host "Importing WMI Filter: $($wmiFilterFile.Name)"
#         Import-WmiFilter -Path $wmiFilterFile.FullName
#     }
# }

# Apply the GPOs
Write-Host "Applying DoD GPOs..."
gpupdate /force

Write-Host "DoD GPOs have been downloaded, imported, and applied successfully."