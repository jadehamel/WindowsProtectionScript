# WindowsProtectionScript
This PowerShell script enhances security and optimizes Windows performance by enabling "God Mode," configuring the firewall, applying secure WiFi settings, disabling automatic updates, and cleaning up hidden files. It also disables potentially unwanted network components to strengthen privacy and system protection.

## Prerequisites

Before running the script, ensure you have the **PsExec** tool installed. PsExec allows you to execute commands as the SYSTEM user, granting necessary permissions for full script execution.

## Steps to Run the Script

### 1. Download PsExec
[Download PsExec from Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) and extract it to a known location.

### 2. Open a System-Level PowerShell Session
Run the following command in **Command Prompt (cmd)** with administrator privileges:

```powershell
& PsExec.exe -i -s powershell
```
### Run the code in **WindowsProtectionScript.ps1**
# Features

## 1. **Enable God Mode**
   - **Purpose**: Creates a "God Mode" folder on the desktop, which provides quick access to all Windows administrative tools and settings.
   - **Action**:
     ```powershell
     $godModePath = "$env:UserProfile\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
     if (!(Test-Path $godModePath)) {
       New-Item -ItemType Directory -Path $godModePath | Out-Null
     }
     ```

## 2. **Show Hidden Files, File Extensions, and Protected System Files**
   - **Purpose**: Ensures that hidden files, file extensions, and protected system files are visible in File Explorer.
   - **Action**:
     ```powershell
     Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Value 1
     Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowSuperHidden -Value 1
     Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Value 0
     ```

## 3. **Disable Restrictions on Control Panel and Folder Options**
   - **Purpose**: Removes restrictions that might prevent access to the Control Panel, Folder Options, and the Run dialog.
   - **Action**:
     ```powershell
     $explorerPoliciesPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
     if (-not (Test-Path $explorerPoliciesPath)) {
       New-Item -Path $explorerPoliciesPath -Force | Out-Null
     }
     Set-ItemProperty -Path $explorerPoliciesPath -Name NoControlPanel -Value 0
     Set-ItemProperty -Path $explorerPoliciesPath -Name NoFolderOptions -Value 0
     Set-ItemProperty -Path $explorerPoliciesPath -Name NoRun -Value 0
     ```

## 4. **Enable Visibility of All Network Folders in File Explorer**
   - **Purpose**: Ensures that all network folders are visible in the navigation pane of File Explorer.
   - **Action**:
     ```powershell
     Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name NavPaneShowAllFolders -Value 1
     ```

## 5. **Re-enable Task Manager and Registry Editor if Blocked**
   - **Purpose**: Re-enables Task Manager and Registry Editor if they have been disabled by group policies or other restrictions.
   - **Action**:
     ```powershell
     $systemPoliciesPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
     if (-not (Test-Path $systemPoliciesPath)) {
       New-Item -Path $systemPoliciesPath -Force | Out-Null
     }
     Set-ItemProperty -Path $systemPoliciesPath -Name DisableTaskMgr -Value 0
     Set-ItemProperty -Path $systemPoliciesPath -Name DisableRegistryTools -Value 0
     ```

## 6. **Make the Recycle Bin Visible on the Desktop**
   - **Purpose**: Ensures that the Recycle Bin icon is visible on the desktop.
   - **Action**:
     ```powershell
     Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 0
     ```

## 7. **Unhide Hidden Files on C: Drive**
   - **Purpose**: Unhides all hidden files on the C: drive, making them visible in File Explorer.
   - **Action**:
     ```powershell
     $items = Get-ChildItem -Path C:\ -Hidden -Recurse -ErrorAction SilentlyContinue
     foreach ($item in $items) {
       try {
         $item.Attributes = $item.Attributes -band -bnot [System.IO.FileAttributes]::Hidden
       } catch {
         Write-Host "Unable to modify: $($item.FullName)" -ForegroundColor Yellow
       }
     }
     ```

## 8. **Configure WiFi Adapter for Improved Security and Privacy**
   - **Purpose**: Configures the WiFi adapter to enhance security and privacy by disabling unnecessary features and setting recommended parameters.
   - **Action**:
     ```powershell
     $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
     if ($adapter) {
       $adapterName = $adapter.Name
       netsh wlan set autoconfig enabled=no interface="$adapterName"
       netsh wlan set blocklist add=*
       netsh wlan set hostednetwork mode=disallow
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
       Write-Host "WiFi configuration applied successfully."
     } else {
       Write-Host "No active WiFi adapter detected."
     }
     ```

## 9. **Disable Network Components for Security**
   - **Purpose**: Disables certain network components that could pose security risks, such as File and Printer Sharing, NetBIOS, and IPv6.
   - **Action**:
     ```powershell
     $disableComponents = @(
       "ms_server", "ms_netbios", "ms_pacer", "ms_implat", "ms_lldp", "ms_rspndr", "ms_lltdio", "ms_tcpip6"
     )
     foreach ($component in $disableComponents) {
       Write-Host "Disabling $component on $($wifiAdapter.Name)..."
       Disable-NetAdapterBinding -Name $wifiAdapter.Name -ComponentID $component -ErrorAction SilentlyContinue
     }
     Write-Host "Network security configuration applied successfully!" -ForegroundColor Green
     ```

## 10. **Disable Windows Updates and Automatic Updates**
   - **Purpose**: Stops and disables Windows Update and related services to prevent automatic updates.
   - **Action**:
     ```powershell
     $services = @("wuauserv", "bits", "dosvc", "UsoSvc", "waasmedicsvc")
     foreach ($service in $services) {
       Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
       Set-Service -Name $service -StartupType Disabled
     }
     Write-Host "Windows update services disabled successfully!" -ForegroundColor Green
     ```

## Summary
This script performs a comprehensive set of actions to enhance system security, privacy, and performance by:
- Enabling advanced system settings (God Mode, hidden files, etc.).
- Configuring WiFi settings for improved security.
- Disabling potentially risky network components.
- Stopping and disabling Windows Update services to prevent automatic updates.

**Note**: This script should be used with caution, as some of the changes (e.g., disabling Windows Update) may have significant implications for system security and stability. Always ensure you understand the consequences before running such scripts.


