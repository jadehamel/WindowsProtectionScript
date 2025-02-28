# Enable God Mode
$godModePath = "$env:UserProfile\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
if (!(Test-Path $godModePath)) {
  New-Item -ItemType Directory -Path $godModePath | Out-Null
}

# Show hidden files, extensions, and protected system files
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowSuperHidden -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Value 0

# Disable restrictions on Control Panel and Folder Options
$explorerPoliciesPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (-not (Test-Path $explorerPoliciesPath)) {
  New-Item -Path $explorerPoliciesPath -Force | Out-Null
}
Set-ItemProperty -Path $explorerPoliciesPath -Name NoControlPanel -Value 0
Set-ItemProperty -Path $explorerPoliciesPath -Name NoFolderOptions -Value 0
Set-ItemProperty -Path $explorerPoliciesPath -Name NoRun -Value 0

# Enable visibility of all network folders in Explorer
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name NavPaneShowAllFolders -Value 1

# Re-enable Task Manager and Registry Editor if they are blocked
$systemPoliciesPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $systemPoliciesPath)) {
  New-Item -Path $systemPoliciesPath -Force | Out-Null
}
Set-ItemProperty -Path $systemPoliciesPath -Name DisableTaskMgr -Value 0
Set-ItemProperty -Path $systemPoliciesPath -Name DisableRegistryTools -Value 0

# Make the Recycle Bin visible on the desktop
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 0

# Unhide files on C: while avoiding errors
$items = Get-ChildItem -Path C:\ -Hidden -Recurse -ErrorAction SilentlyContinue
foreach ($item in $items) {
  try {
    $item.Attributes = $item.Attributes -band -bnot [System.IO.FileAttributes]::Hidden
  } catch {
    Write-Host "Cannot modify: $($item.FullName)" -ForegroundColor Yellow
  }
}

# Set Wi-Fi adapter settings to enhance security and privacy
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}

# Check if an active Wi-Fi adapter is present
if ($adapter) {
  $adapterName = $adapter.Name

  # Apply recommended settings
  netsh wlan set autoconfig enabled=no interface="$adapterName"
  netsh wlan set blocklist add=*
  netsh wlan set hostednetwork mode=disallow
  
  # Set specific properties
  $settings = @{
    "802.11a/b/g Wireless Mode" = "Disable"
    "802.11n/ac Wireless Mode" = "Enable"
    "ARP Offload for WoWLAN" = "Disable"
    "Channel Width for 2.4GHz" = "20MHz"
    "Channel Width for 5GHz" = "40MHz"
    "Fat Channel Intolerant" = "Enable"
    "Global BG Scan Blocking" = "Enable"
    "GTK Rekeying for WoWLAN" = "Disable"
    "MIMO Power Save Mode" = "No SMPS"
    "Mixed Mode Protection" = "CTS-to-Self"
    "NS Offload for WoWLAN" = "Disable"
    "Packet Coalescing" = "Disable"
    "Preferred Band" = "5GHz"
    "Roaming Aggressiveness" = "Lowest"
    "Sleep on WoWLAN Disconnect" = "Disable"
    "Throughput Booster" = "Disable"
    "Transmit Power" = "Medium"
    "U-APSD Support" = "Disable"
    "Wake on Magic Packet" = "Disable"
    "Wake on Pattern Match" = "Disable"
  }

  foreach ($setting in $settings.GetEnumerator()) {
    Write-Host "Configuring $($setting.Key) to $($setting.Value)..."
    netsh wlan set interface "$adapterName" $setting.Key=$setting.Value
  }

  Write-Host "Wi-Fi configuration successfully applied."
} else {
  Write-Host "No active Wi-Fi adapter detected."
}

# Check for administrator rights
$adminCheck = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$adminRole = [System.Security.Principal.WindowsPrincipal]::new($adminCheck)
if (-not $adminRole.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Please run this script as an administrator!" -ForegroundColor Red
  exit
}

# Retrieve the active Wi-Fi adapter
$wifiAdapter = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Wireless*"}
if (!$wifiAdapter) {
  Write-Host "No Wi-Fi adapter found!" -ForegroundColor Red
  exit
}

# List of network components to disable for security
$disableComponents = @(
  "ms_server"   # File and Printer Sharing for Microsoft Networks
  "ms_netbios"  # Client for Microsoft Networks
  "ms_pacer"    # QoS Packet Scheduler
  "ms_implat"   # Microsoft Network Adapter Multiplexor Protocol
  "ms_lldp"     # Microsoft LLDP Protocol Driver
  "ms_rspndr"   # Link-Layer Topology Discovery Responder
  "ms_lltdio"   # Link-Layer Topology Discovery Mapper I/O Driver
  "ms_tcpip6"   # Internet Protocol Version 6 (TCP/IPv6)
)

# Disable network components
foreach ($component in $disableComponents) {
  Write-Host "Disabling $component on $($wifiAdapter.Name)..."
  Disable-NetAdapterBinding -Name $wifiAdapter.Name -ComponentID $component -ErrorAction SilentlyContinue
}

Write-Host "Network security configuration successfully applied!" -ForegroundColor Green
