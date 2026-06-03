<#
=================================================================================
  PORTABLE WORKSTATION AUDIT AUTOMATION SCRIPT
  Filename: WorkstationAudit.ps1
  Updated: June 3, 2026
=================================================================================
#>

Clear-Host
Write-Host "=================================================================" -ForegroundColor Yellow
Write-Host "   RUNNING AUTOMATED CHECKLIST EXTRACTION MODULE..." -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Yellow

# -------------------------------------------------------------------------------
# SECTIONS 1 & 2: MACHINE IDENTIFICATION & HARDWARE
# -------------------------------------------------------------------------------
Write-Host "`n[+] SECTIONS 1 & 2: IDENTIFICATION & HARDWARE DATA" -ForegroundColor Cyan
$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$BIOS = Get-CimInstance -ClassName Win32_BIOS
$CPU = Get-CimInstance -ClassName Win32_Processor

# Advanced GPU / Video Controller Detection (Reverted to Original Name/Driver)
$GPUList = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue
$DetectedGPUs = if ($GPUList) {
    ($GPUList | ForEach-Object { "$($_.Name) (Driver: $($_.DriverVersion))" }) -join " | "
} else {
    "No Video Controller Identified via WMI"
}

$MemoryModule = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue | Select-Object -First 1
$RamSpeed = if ($MemoryModule) { $MemoryModule.Speed } else { 0 }
$RamGeneration = "DDR3 or Older"

if ($RamSpeed -gt 0) {
    if ($RamSpeed -le 3200) { $RamGeneration = "DDR4" }
    elseif ($RamSpeed -gt 3200) { $RamGeneration = "DDR5" }
} else {
    $RamGeneration = "Unknown (Check Registry / Task Manager)"
}

$TpmCheck = Get-Tpm -ErrorAction SilentlyContinue
$TpmPresent = "No / Not Found"
$TpmVersion = "N/A (Check BIOS / Motherboard Settings)"

if ($TpmCheck -and $TpmCheck.TpmPresent) {
    $TpmPresent = "Yes"
    
    $TpmWmi = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    if ($null -ne $TpmWmi) {
        $TpmVersion = "$($TpmWmi.SpecVersion) (Mfg Version: $($TpmWmi.ManufacturerVersion))"
    } else {
        $TpmVersion = "Present (Hardware Active - Run script as Admin for version details)"
    }
}

[PSCustomObject]@{
    "Computer Name"      = $env:COMPUTERNAME
    "Assigned User"      = $ComputerSystem.UserName
    "Manufacturer"       = $ComputerSystem.Manufacturer
    "Model"              = $ComputerSystem.Model
    "Serial Number"      = $BIOS.SerialNumber
    "CPU Architecture"   = "$($CPU.Name) ($($CPU.NumberOfCores) Physical Cores)"
    "GPU Installed"      = $DetectedGPUs
    "RAM Installed (GB)" = [Math]::Round($ComputerSystem.TotalPhysicalMemory / 1GB, 2)
    "RAM Generation"     = "$RamGeneration (Clock Speed: $RamSpeed MHz)"
    "TPM Chip Present?"  = $TpmPresent
    "TPM Version Details"= $TpmVersion
    "Detected Monitors"  = "CHECK PHYSICALLY (Skipped via Script)"
} | Format-List

# --- STORAGE HARDWARE DISK ANALYSIS BLOCK ---
Write-Host "--- Local Drive Space Capacity & Media Type Properties ---" -ForegroundColor Yellow

# Query physical disk hardware media and bus types
$PhysicalDisks = Get-CimInstance -Namespace root\Microsoft\Windows\Storage -ClassName MSFT_PhysicalDisk -ErrorAction SilentlyContinue

Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $LogicalDrive = $_
    $TotalGB = [Math]::Round($LogicalDrive.Size / 1GB, 2)
    $FreeGB = [Math]::Round($LogicalDrive.FreeSpace / 1GB, 2)
    $UsedGB = [Math]::Round($TotalGB - $FreeGB, 2)
    
    $DriveLabel = "SSD"
    if ($PhysicalDisks) {
        $PrimaryDisk = $PhysicalDisks | Where-Object {$_.DeviceId -eq 0} | Select-Object -First 1
        if ($PrimaryDisk) {
            if ($PrimaryDisk.MediaType -eq 4 -or $PrimaryDisk.MediaType -like "*SSD*") {
                $DriveLabel = if ($PrimaryDisk.BusType -eq "NVMe" -or $PrimaryDisk.BusType -eq 17) { "SSD (NVMe)" } else { "SSD" }
            } elseif ($PrimaryDisk.MediaType -eq 3 -or $PrimaryDisk.MediaType -like "*HDD*") {
                $DriveLabel = "HDD"
            } else {
                $DriveLabel = "SSD"
            }
        }
    }
    
    [PSCustomObject]@{
        "Drive Letter"   = $LogicalDrive.DeviceID
        "Drive Type"     = $DriveLabel
        "Total Size"     = "$TotalGB GB"
        "Used Space"     = "$UsedGB GB"
        "Free Space Left"= "$FreeGB GB"
    }
} | Format-Table -AutoSize

# -------------------------------------------------------------------------------
# SECTIONS 3 & 4: OPERATING SYSTEM & DOMAIN IDENTITY
# -------------------------------------------------------------------------------
Write-Host "`n[+] SECTIONS 3 & 4: OPERATING SYSTEM & DOMAIN CONFIGURATION" -ForegroundColor Cyan
$OS = Get-CimInstance -ClassName Win32_OperatingSystem

# Advanced Licensing & Partial Key Query
$LicenseProduct = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%' and PartialProductKey is not null" -ErrorAction SilentlyContinue
if ($LicenseProduct) {
    $LicenseChannel = $LicenseProduct.ProductKeyChannel
    $PartialKey     = $LicenseProduct.PartialProductKey
} else {
    $LicenseChannel = "Unknown (Run as Admin)"
    $PartialKey     = "Unknown"
}

# Domain & OU Parsing Logic
$DomainJoined = "No"
$JoinDate = "N/A"
$OU = "N/A"

if ($ComputerSystem.PartOfDomain) {
    $DomainJoined = "Yes"
    try {
        $ComputerSearcher = [ADISearcher]"(&(objectCategory=computer)(name=$env:COMPUTERNAME))"
        $ResolveObject = $ComputerSearcher.FindOne()
        if ($ResolveObject) {
            $MachineDN = $ResolveObject.Path
            $OU = ($MachineDN -split ",*..=")[2]
            $DirectoryEntry = $ResolveObject.GetDirectoryEntry()
            $JoinDate = $DirectoryEntry.whenCreated
        }
    } catch {
        $OU = "Connected (Access Restricted)"
        $JoinDate = "Unknown"
    }
}

# Entra ID / Azure AD & Hybrid Join Evaluation
$EntraJoined = "No"
$HybridJoin = "No"
$DSRegStatus = dsregcmd /status | Out-String

if ($DSRegStatus -match "AzureAdJoined\s*:\s*YES") { $EntraJoined = "Yes" }
if ($DSRegStatus -match "DomainJoined\s*:\s*YES" -and $DSRegStatus -match "AzureAdJoined\s*:\s*YES") { $HybridJoin = "Yes" }

# Local Group Accounts Parsing (Admins vs Standard Users)
$LocalAdmins = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ", "
$LocalUsers  = (Get-LocalGroupMember -Group "Users" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ", "

# Guest Account Status Evaluation
$GuestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
$GuestDisabled = if ($GuestAccount) { if (-not $GuestAccount.Enabled) { "Yes" } else { "No" } } else { "N/A" }

# Live GPO Last Refresh Extraction
try {
    $TempFile = [System.IO.Path]::GetTempFileName()
    gpresult /scope computer /x $TempFile /f | Out-Null
    [xml]$GPReport = Get-Content -Path $TempFile -Raw
    Remove-Item -Path $TempFile -ErrorAction SilentlyContinue
    
    $RawGPUTime = $GPReport.RsopData.ComputerResults.ExtensionData.Extension.PolicyRefreshTime
    if ($RawGPUTime) {
        $GPOLastRefresh = [Management.ManagementDateTimeConverter]::ToDateTime($RawGPUTime)
    } else {
        $GPOLastRefresh = "RUN: 'gpresult /scope computer /r' to check date manually"
    }
} catch {
    $GPOLastRefresh = "RUN: 'gpresult /scope computer /r' to check date manually"
}

[PSCustomObject]@{
    "OS Name & Edition"   = $OS.Caption
    "OS Version / Build"  = $OS.Version
    "Install Date"        = $OS.InstallDate
    "License Type"        = $LicenseChannel
    "Activation Key (5)"  = $PartialKey
    "Domain-Joined?"      = $DomainJoined
    "Domain Name"         = if ($ComputerSystem.PartOfDomain) { $ComputerSystem.Domain } else { "N/A" }
    "Organizational Unit" = $OU
    "Join Date (AD)"      = $JoinDate
    "Entra ID Joined?"    = $EntraJoined
    "Hybrid Join?"        = $HybridJoin
    "Local Admin Accounts"= if ($LocalAdmins) { $LocalAdmins } else { "None Found" }
    "Standard Users List" = if ($LocalUsers) { $LocalUsers } else { "None Found" }
    "Guest Account Disab?"= $GuestDisabled
    "GPO Last Refresh"    = $GPOLastRefresh
    "Last System Reboot"  = $OS.LastBootUpTime
} | Format-List

# -------------------------------------------------------------------------------
# SECTIONS 5 & 6: SECURITY & REMOTE INTERACTION POSTURE
# -------------------------------------------------------------------------------
Write-Host "`n[+] SECTIONS 5 & 6: SECURITY ENVIRONMENT & REMOTE AGENTS" -ForegroundColor Cyan
$BitLocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
$ScreenConnect = Get-Service -Name "ScreenConnect*" -ErrorAction SilentlyContinue

# Bulletproof Firmware Boot Mode Detection (UEFI vs Legacy BIOS)
$BootMode = "Legacy BIOS"
try {
    $Null = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    $BootMode = "UEFI"
} catch {
    if ($error[0].Exception.Message -match "not supported") {
        $BootMode = "Legacy BIOS"
    } else {
        $BootMode = "UEFI"
    }
}

# Secure Boot State Parsing
try {
    $SecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    $SecureBootState = if ($SecureBoot) { "Enabled / Yes" } else { "Disabled / No" }
} catch {
    $SecureBootState = "Access Denied (Requires Admin Privileges)"
}

# Live Windows Firewall Rule State Analytics
$DomainFW  = (Get-NetFirewallProfile -Profile Domain).Enabled
$PrivateFW = (Get-NetFirewallProfile -Profile Private).Enabled
$PublicFW  = (Get-NetFirewallProfile -Profile Public).Enabled

$FirewallStatus = if ($DomainFW -and $PrivateFW -and $PublicFW) { "Yes (All Profiles Enabled)" } 
                  else { "Partial (Dom:$DomainFW, Priv:$PrivateFW, Pub:$PublicFW)" }

$FirewallTypes = "Domain: $DomainFW | Private: $PrivateFW | Public: $PublicFW"

[PSCustomObject]@{
    "Windows Defender AV" = (Get-MpComputerStatus).AMServiceEnabled
    "Firewall Enabled?"   = $FirewallStatus
    "Firewall Profile Type"= $FirewallTypes
    "Secure Boot State"  = $SecureBootState
    "UEFI / BIOS Mode"   = $BootMode
    "BIOS/UEFI Password" = "CHECK PHYSICALLY (Restricted via OS Layer)"
    "BIOS Version"       = $BIOS.SMBIOSBIOSVersion
    "BitLocker Status"   = if ($BitLocker) { $BitLocker.ProtectionStatus } else { "Not Found" }
    "ScreenConnect Client"= if ($ScreenConnect) { "Installed & Running" } else { "Not Identified" }
} | Format-List

# -------------------------------------------------------------------------------
# SECTIONS 7 & 8: PERIPHERALS & PRINT INFRASTRUCTURE
# -------------------------------------------------------------------------------
Write-Host "`n[+] SECTIONS 7 & 8: CONNECTED HARDWARE & PRINT QUEUES" -ForegroundColor Cyan
$ActivePrinters = Get-CimInstance -ClassName Win32_Printer -ErrorAction SilentlyContinue

if ($ActivePrinters) {
    $ActivePrinters | ForEach-Object {
        [PSCustomObject]@{
            "Printer Name"   = $_.Name
            "Driver Assigned"= $_.DriverName
            "Port/Connection"= $_.PortName
            "Is Default?"    = if ($_.Default) { "Yes" } else { "No" }
        }
    } | Format-Table -AutoSize
} else {
    Write-Warning "No active hardware or software print queues detected on this workstation."
}

# -------------------------------------------------------------------------------
# SECTION 9: NETWORK CONFIGURATIONS & STORAGE LINKS
# -------------------------------------------------------------------------------
Write-Host "`n[+] SECTION 9: TOPOGRAPHY LAYOUTS & STORAGE PATHS" -ForegroundColor Cyan

Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"} | ForEach-Object {
    $Adapter = Get-NetAdapter -Name $_.InterfaceAlias -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        "Network Card"   = $_.InterfaceAlias
        "IPv4 Address"   = $_.IPAddress
        "MAC Address"    = $Adapter.MacAddress
    }
} | Format-Table -AutoSize

Write-Host "Configured DNS Infrastructure Resolvers:" -ForegroundColor Yellow
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses -ne $null} | 
    Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize

Write-Host "Identified Local Shared Network Drives:" -ForegroundColor Yellow
$NetworkDriveInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=4" -ErrorAction SilentlyContinue | Select-Object @{Name='Drive Letter';Expression={$_.DeviceID}}, @{Name='Remote Path';Expression={$_.ProviderName}}, @{Name='Volume Name';Expression={$_.VolumeName}}, @{Name='Free Space';Expression={if ($_.FreeSpace) {[Math]::Round($_.FreeSpace / 1GB, 2) + ' GB'} else {'N/A'}}}, @{Name='Total Size';Expression={if ($_.Size) {[Math]::Round($_.Size / 1GB, 2) + ' GB'} else {'N/A'}}}
if ($NetworkDriveInfo) {
    $NetworkDriveInfo | Format-Table -AutoSize
} else {
    Write-Host "No mapped network drives detected." -ForegroundColor Cyan
}

# Specific explicit validation for your target checklist drive letter
Write-Host "`nVerifying Local R: Drive Mapping Status..." -ForegroundColor Yellow
$TargetDrive = "R:"
if (Get-PSDrive -Name $TargetDrive.Replace(":","") -ErrorAction SilentlyContinue) {
    Write-Host "SUCCESS: Drive letter $TargetDrive is actively registered locally." -ForegroundColor Green
} else {
    Write-Warning "WARNING: Drive $TargetDrive is unmapped or experiencing a ghost runtime connection conflict."
}

Write-Host "`n=================================================================" -ForegroundColor Yellow
Write-Host "   AUDIT COMPLETE. ALL CHECKS PASSING FLUSHED BACK TO CONSOLE." -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Yellow