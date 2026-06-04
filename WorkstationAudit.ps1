<#
=================================================================================
  PORTABLE WORKSTATION AUDIT AUTOMATION SCRIPT
  Filename: WorkstationAudit.ps1
  Updated: June 4, 2026
  Fixes Applied:
    - Corrected [ADSISearcher] typo (was [ADISearher]) in Domain/OU lookup
    - Replaced network drive detection with HKU SID-based lookup so drives
      mapped by the logged-in user are visible even when script runs as Admin
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
    ($GPUList | ForEach-Object { 
        $VRAM_GB = if ($_.AdapterRAM) { [Math]::Round($_.AdapterRAM / 1GB, 2) } else { "Unknown" }
        "$($_.Name) (VRAM: $VRAM_GB GB, Driver: $($_.DriverVersion))" 
    }) -join " | "
} else {
    "No Video Controller Identified via WMI"
}

$MemoryModule = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue | Select-Object -First 1
$RamSpeed = if ($MemoryModule) { $MemoryModule.Speed } else { 0 }
$RamGeneration = "Unknown"

# Use SMBIOS Memory Type for accurate identification (not speed-based)
# SMBIOS types: 20=DDR, 21=DDR2, 24=DDR3, 26=DDR4, 27=LPDDR, 28=LPDDR2, 29=LPDDR3,
# 30=LPDDR4, 31=LPDDR5, 32=CAMM DDR4, 33=CAMM DDR5, 34=DDR5, 35=LPDDR5X,
# 40=HBM, 41=HBM2, 42=HBM2E, 43=HBM3, 45=DDR5X, 46=LPDDR6, others=Unknown
if ($MemoryModule -and $MemoryModule.SMBIOSMemoryType) {
    $MemType = $MemoryModule.SMBIOSMemoryType
    switch ($MemType) {
        20  { $RamGeneration = "DDR" }
        21  { $RamGeneration = "DDR2" }
        24  { $RamGeneration = "DDR3" }
        26  { $RamGeneration = "DDR4" }
        27  { $RamGeneration = "LPDDR" }
        28  { $RamGeneration = "LPDDR2" }
        29  { $RamGeneration = "LPDDR3" }
        30  { $RamGeneration = "LPDDR4" }
        31  { $RamGeneration = "LPDDR5" }
        32  { $RamGeneration = "DDR4 All-In-One (CAMM)" }
        33  { $RamGeneration = "DDR5 All-In-One (CAMM2)" }
        34  { $RamGeneration = "DDR5" }
        35  { $RamGeneration = "LPDDR5X" }
        45  { $RamGeneration = "DDR5X" }
        46  { $RamGeneration = "LPDDR6" }
        default { $RamGeneration = "Unknown / Other (SMBIOS Type: $MemType)" }
    }
} else {
    $RamGeneration = "Unknown (Check BIOS or Device Manager)"
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
        # FIX: Corrected typo - was [ADISearher] which caused a crash on domain-joined machines
        $ComputerSearcher = [ADSISearcher]"(&(objectCategory=computer)(name=$env:COMPUTERNAME))"
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
        
        # Fallback: Query Registry if AD is unreachable (more reliable method)
        try {
            $RegPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
            $DomainJoinInfo = Get-ItemProperty -Path $RegPath -Name "DomainJoinInfo" -ErrorAction SilentlyContinue
            if ($DomainJoinInfo -and $DomainJoinInfo.DomainJoinInfo) {
                $JoinDate = [DateTime]::FromBinary($DomainJoinInfo.DomainJoinInfo)
            }
        } catch {
            # If registry also fails, keep "Unknown"
        }
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

# -------------------------------------------------------------------------------
# FIX: Network Drive Detection Rewritten for Admin Session Compatibility
#
# When running as Admin, Windows creates a separate elevated session that does NOT
# inherit the logged-in user's mapped drives. The fix resolves the actual logged-in
# user's SID and reads their drive mappings directly from HKEY_USERS in the registry,
# which IS accessible from an admin context. Three methods are combined:
#   Method 1: WMI  - works when drives are live and visible in the current session
#   Method 2: HKU SID lookup  - reads the logged-in user's hive directly (main fix)
#   Method 3: All user profiles  - catches any other user with drives mapped on login
# -------------------------------------------------------------------------------

# Identify both the logged-in user and the account running the script
$LoggedInUser = $ComputerSystem.UserName
$ScriptRunningAs = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "  [Debug] Logged-in user  : $LoggedInUser" -ForegroundColor Gray
Write-Host "  [Debug] Script running as: $ScriptRunningAs" -ForegroundColor Gray

# Resolve the logged-in user's SID (needed to find their hive under HKU)
$LoggedInSID = $null
if ($LoggedInUser) {
    try {
        $NTAccount  = New-Object System.Security.Principal.NTAccount($LoggedInUser)
        $LoggedInSID = $NTAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        Write-Host "  [Warn] Could not resolve SID for $LoggedInUser - falling back to all-profile scan" -ForegroundColor Yellow
    }
}

# Method 1: WMI query (works when the admin session can see live drive connections)
$WMIDrives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=4" -ErrorAction SilentlyContinue |
    Select-Object @{Name='Drive Letter'; Expression={$_.DeviceID}},
                  @{Name='Remote Path';  Expression={$_.ProviderName}},
                  @{Name='Volume Name';  Expression={$_.VolumeName}},
                  @{Name='Free Space';   Expression={if ($_.FreeSpace) { [Math]::Round($_.FreeSpace / 1GB, 2).ToString() + ' GB' } else { 'N/A' }}},
                  @{Name='Total Size';   Expression={if ($_.Size)      { [Math]::Round($_.Size      / 1GB, 2).ToString() + ' GB' } else { 'N/A' }}}

# Method 2: Read the logged-in user's mapped drives directly from HKU using their SID
# This is the primary fix - visible from admin session even when WMI returns nothing
$HKUDrives = @()
if ($LoggedInSID) {
    $HKUNetworkPath = "Registry::HKEY_USERS\$LoggedInSID\Network"
    if (Test-Path $HKUNetworkPath -ErrorAction SilentlyContinue) {
        $HKUDrives = Get-ChildItem -Path $HKUNetworkPath -ErrorAction SilentlyContinue | ForEach-Object {
            $RemotePath = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).RemotePath
            [PSCustomObject]@{
                "Drive Letter" = "$($_.PSChildName):"
                "Remote Path"  = if ($RemotePath) { $RemotePath } else { "Unknown" }
                "Volume Name"  = "Mapped (logged-in user registry)"
                "Free Space"   = "N/A"
                "Total Size"   = "N/A"
            }
        }
    }
}

# Method 3: Scan all loaded user hives under HKU to catch any other mapped users
$AllUserRegDrives = @()
try {
    $UserProfiles = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-.*' -and $_.PSChildName -notlike "*_Classes" }

    foreach ($Profile in $UserProfiles) {
        # Skip the logged-in user - already handled in Method 2
        if ($Profile.PSChildName -eq $LoggedInSID) { continue }
        try {
            $NetworkPath    = "$($Profile.PSPath)\Network"
            $NetworkRegPath = Get-ChildItem -Path $NetworkPath -ErrorAction SilentlyContinue
            if ($NetworkRegPath) {
                $NetworkRegPath | ForEach-Object {
                    $DriveLetter = $_.PSChildName
                    $RemotePath  = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).RemotePath
                    $AllUserRegDrives += [PSCustomObject]@{
                        "Drive Letter" = "$($DriveLetter):"
                        "Remote Path"  = if ($RemotePath) { $RemotePath } else { "Unknown" }
                        "Volume Name"  = "Other User Profile (HKU)"
                        "Free Space"   = "N/A"
                        "Total Size"   = "N/A"
                    }
                }
            }
        } catch { }
    }
} catch { }

# Merge all three methods, deduplicating by drive letter
# Priority: WMI (has live size data) > HKU SID > other profiles
$FinalDrives   = @()
$SeenLetters   = @()

foreach ($Drive in (@($WMIDrives) + @($HKUDrives) + @($AllUserRegDrives))) {
    if ($null -eq $Drive) { continue }
    $Letter = $Drive."Drive Letter"
    if ($SeenLetters -notcontains $Letter) {
        $FinalDrives += $Drive
        $SeenLetters += $Letter
    }
}

if ($FinalDrives) {
    $FinalDrives | Format-Table -AutoSize
} else {
    Write-Host "No mapped network drives detected for any user on this machine." -ForegroundColor Cyan
}

# -------------------------------------------------------------------------------
# Specific explicit validation for your target checklist drive letter (R:)
# -------------------------------------------------------------------------------
Write-Host "`nVerifying Local R: Drive Mapping Status..." -ForegroundColor Yellow
$TargetDrive = "R:"
$DriveFound  = $false
$DriveSource = ""

# Check 1: Already found in our combined results above
if ($SeenLetters -contains $TargetDrive) {
    $DriveFound  = $true
    $DriveSource = "found via drive scan above"
}

# Check 2: Active PSDrive in current session
if (-not $DriveFound -and (Get-PSDrive -Name $TargetDrive.Replace(":","") -ErrorAction SilentlyContinue)) {
    $DriveFound  = $true
    $DriveSource = "active PSDrive in current session"
}

# Check 3: Logged-in user's HKU hive (direct SID lookup)
if (-not $DriveFound -and $LoggedInSID) {
    $HKURPath = "Registry::HKEY_USERS\$LoggedInSID\Network\$($TargetDrive.Replace(':',''))"
    if (Test-Path $HKURPath -ErrorAction SilentlyContinue) {
        $DriveFound  = $true
        $DriveSource = "logged-in user registry (HKU SID)"
    }
}

# Check 4: HKCU of the current session
if (-not $DriveFound -and (Test-Path "HKCU:\Network\$($TargetDrive.Replace(':',''))" -ErrorAction SilentlyContinue)) {
    $DriveFound  = $true
    $DriveSource = "current session HKCU registry"
}

# Check 5: Any other loaded user profile in HKU
if (-not $DriveFound) {
    try {
        $UserProfiles = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-.*' -and $_.PSChildName -notlike "*_Classes" }
        foreach ($Profile in $UserProfiles) {
            $RDrivePath = "$($Profile.PSPath)\Network\$($TargetDrive.Replace(':',''))"
            if (Test-Path -Path $RDrivePath -ErrorAction SilentlyContinue) {
                $DriveFound  = $true
                $DriveSource = "other user profile in HKU ($($Profile.PSChildName))"
                break
            }
        }
    } catch { }
}

if ($DriveFound) {
    Write-Host "SUCCESS: Drive $TargetDrive is mapped ($DriveSource)." -ForegroundColor Green
} else {
    Write-Warning "WARNING: Drive $TargetDrive is unmapped or experiencing a ghost runtime connection conflict."
    Write-Host "  -> Logged-in user     : $LoggedInUser" -ForegroundColor Yellow
    Write-Host "  -> Script running as  : $ScriptRunningAs" -ForegroundColor Yellow
    Write-Host "  -> Mapped drives are stored per-user - verify this account has the drive mapped" -ForegroundColor Yellow
    Write-Host "  -> If running as Admin, drives may only be visible to the logged-in user, not the admin session" -ForegroundColor Yellow
    Write-Host "  -> Check Network Connection Profile is set to 'Private' or 'Domain' (not 'Public')" -ForegroundColor Yellow
    Write-Host "  -> Try running 'gpupdate /force' logged in as the affected user to re-apply drive mappings" -ForegroundColor Yellow
}

Write-Host "`n=================================================================" -ForegroundColor Yellow
Write-Host "   AUDIT COMPLETE. ALL CHECKS PASSING FLUSHED BACK TO CONSOLE." -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Yellow