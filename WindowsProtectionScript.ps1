Protection Script - God Mode-Firewall-Option Enabler - Wifi setting - Disable Updates - CleanUp - Remote disabler

# Liste des services à désactiver et supprimer
$servicesToDisable = @(
  "DiagTrack", "dmwappushservice", "Wecsvc", "WerSvc", # Surveillance / Télémétrie
  "RemoteRegistry", "WinRM", "SessionEnv", "TermService", "UmRdpService", # Gestion à distance
  "Netlogon", "RasAuto", "RemoteAccess", # Services liés aux organisations
  "SharedAccess", "PeerDistSvc", "WpnService" # Services de partage réseau et notifications
)
Stop-Service -Name TrustedInstaller -Force
Set-Service -Name TrustedInstaller -StartupType Manual


foreach ($service in $servicesToDisable) {
  # Vérifie si le service existe
  $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
  if ($serviceObj) {
    Write-Host "Traitement du service : $service"

    # Stoppe le service s'il est en cours d'exécution
    if ($serviceObj.Status -eq "Running") {
      Write-Host " - Arrêt du service..."
      Stop-Service -Name $service -Force
    }

    # Désactive le service
    Write-Host " - Désactivation du service..."
    Set-Service -Name $service -StartupType Disabled

    # Suppression du service si possible
    Write-Host " - Suppression du service..."
    sc.exe delete $service | Out-Null
  } else {
    Write-Host " - Service $service introuvable ou déjà supprimé."
  }
}




# Activer le mode God Mode
$godModePath = "$env:UserProfile\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
if (!(Test-Path $godModePath)) {
  New-Item -ItemType Directory -Path $godModePath | Out-Null
}

# Afficher les fichiers cachés, extensions et fichiers protégés du système
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowSuperHidden -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Value 0

# Désactiver les restrictions sur le panneau de configuration et options de dossiers
$explorerPoliciesPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (-not (Test-Path $explorerPoliciesPath)) {
  New-Item -Path $explorerPoliciesPath -Force | Out-Null
}
Set-ItemProperty -Path $explorerPoliciesPath -Name NoControlPanel -Value 0
Set-ItemProperty -Path $explorerPoliciesPath -Name NoFolderOptions -Value 0
Set-ItemProperty -Path $explorerPoliciesPath -Name NoRun -Value 0

# Activer la visibilité de tous les dossiers réseau dans l'explorateur
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name NavPaneShowAllFolders -Value 1

# Réactiver le gestionnaire des tâches et l'éditeur de registre s'ils sont bloqués
$systemPoliciesPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $systemPoliciesPath)) {
  New-Item -Path $systemPoliciesPath -Force | Out-Null
}
Set-ItemProperty -Path $systemPoliciesPath -Name DisableTaskMgr -Value 0
Set-ItemProperty -Path $systemPoliciesPath -Name DisableRegistryTools -Value 0

# Rendre visible la corbeille sur le bureau
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 0

# Débloquer les fichiers cachés sur C: tout en évitant les erreurs
$items = Get-ChildItem -Path C:\ -Hidden -Recurse -ErrorAction SilentlyContinue
foreach ($item in $items) {
  try {
    $item.Attributes = $item.Attributes -band -bnot [System.IO.FileAttributes]::Hidden
  } catch {
    Write-Host "Impossible de modifier : $($item.FullName)" -ForegroundColor Yellow
  }
}
# Définir les paramètres de l'adaptateur Wi-Fi pour améliorer la sécurité et la confidentialité
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}

# Vérifier si un adaptateur Wi-Fi est actif
if ($adapter) {
  $adapterName = $adapter.Name

  # Appliquer les paramètres recommandés
  netsh wlan set autoconfig enabled=no interface="$adapterName"
  netsh wlan set blocklist add=*
  netsh wlan set hostednetwork mode=disallow
  
  # Définir les propriétés spécifiques
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
    Write-Host "Configuration de $($setting.Key) à $($setting.Value)..."
    netsh wlan set interface "$adapterName" $setting.Key=$setting.Value
  }

  Write-Host "Configuration Wi-Fi appliquée avec succès."
} else {
  Write-Host "Aucun adaptateur Wi-Fi actif détecté."
}

# Vérification des droits administrateurs
$adminCheck = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$adminRole = [System.Security.Principal.WindowsPrincipal]::new($adminCheck)
if (-not $adminRole.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Veuillez exécuter ce script en tant qu'administrateur !" -ForegroundColor Red
  exit
}

# Récupérer l'adaptateur Wi-Fi actif
$wifiAdapter = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Wireless*"}
if (!$wifiAdapter) {
  Write-Host "Aucun adaptateur Wi-Fi trouvé !" -ForegroundColor Red
  exit
}

# Liste des composants réseau à désactiver pour la sécurité
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

# Désactivation des composants réseau
foreach ($component in $disableComponents) {
  Write-Host "Désactivation de $component sur $($wifiAdapter.Name)..."
  Disable-NetAdapterBinding -Name $wifiAdapter.Name -ComponentID $component -ErrorAction SilentlyContinue
}

Write-Host "Configuration de sécurité réseau appliquée avec succès !" -ForegroundColor Green




# Désactivation complète des mises à jour Windows et des mises à jour automatiques

# Vérification des droits administrateurs
$adminCheck = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$adminRole = [System.Security.Principal.WindowsPrincipal]::new($adminCheck)
if (-not $adminRole.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Veuillez exécuter ce script en tant qu'administrateur !" -ForegroundColor Red
  exit
}

# Arrêter et désactiver les services Windows Update et Delivery Optimization
Write-Host "Désactivation des services Windows Update et Delivery Optimization..."

$services = @("wuauserv", "bits", "dosvc", "UsoSvc", "waasmedicsvc")
foreach ($service in $services) {
  Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
  Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
}

# Désactiver via le registre
Write-Host "Modification du registre pour désactiver les mises à jour..."
$regPaths = @(
  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
  "HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc"
)

foreach ($path in $regPaths) {
  if (!(Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
  }
}

# Désactivation complète de Windows Update
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWindowsUpdate" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc" -Name "Start" -Value 4 -Type DWord  # Désactive DoSvc

# Désactiver les tâches planifiées liées aux mises à jour
Write-Host "Désactivation des tâches planifiées Windows Update..."
$tasks = @(
  "\Microsoft\Windows\WindowsUpdate\Scheduled Start",
  "\Microsoft\Windows\WindowsUpdate\Automatic App Update",
  "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
  "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask",
  "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
  "\Microsoft\Windows\UpdateOrchestrator\Reboot",
  "\Microsoft\Windows\UpdateOrchestrator\USO_Broker",
  "\Microsoft\Windows\UpdateOrchestrator\RefreshSettings",
  "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
  "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
)

foreach ($task in $tasks) {
  Write-Host "Désactivation de la tâche planifiée : $task"
  schtasks /change /tn $task /disable 2>$null
}

# Désactiver les mises à jour des pilotes via Windows Update
Write-Host "Désactivation des mises à jour de pilotes..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord

# Désactiver les mises à jour automatiques du Microsoft Store
Write-Host "Désactivation des mises à jour automatiques du Microsoft Store..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -Type DWord

# Bloquer l'accès aux serveurs de mise à jour Windows via le fichier hosts
Write-Host "Blocage des serveurs de mise à jour Windows..."
$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
$entries = @(
  "127.0.0.1 windowsupdate.microsoft.com",
  "127.0.0.1 update.microsoft.com",
  "127.0.0.1 download.windowsupdate.com",
  "127.0.0.1 wustat.windows.com",
  "127.0.0.1 ntservicepack.microsoft.com",
  "127.0.0.1 stats.update.microsoft.com",
  "127.0.0.1 update.microsoft.com.nsatc.net"
)

foreach ($entry in $entries) {
  if (!(Select-String -Path $hostsPath -Pattern $entry -Quiet)) {
    Add-Content -Path $hostsPath -Value $entry
  }
}

Write-Host "Toutes les mises à jour automatiques sont désactivées avec succès. Redémarre ton PC pour appliquer les changements." -ForegroundColor Green



# Création d'un Pare-feu Windows Defender ultra sécurisé
Write-Host "🔒 Configuration d'un pare-feu ultra sécurisé..."
# Désactivation du service "Centre de sécurité Windows"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v Start /t REG_DWORD /d 4 /f
# Désactivation du service "DNS Client"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v Start /t REG_DWORD /d 4 /f

# Création d'un Pare-feu Windows Defender ultra sécurisé
Write-Host "🔒 Configuration d'un pare-feu ultra sécurisé..."

# Réinitialisation du pare-feu pour partir sur une base propre
Write-Host "🔄 Réinitialisation des règles du pare-feu..."
netsh advfirewall reset

# Activer le pare-feu sur tous les profils
Write-Host "🛡️ Activation du pare-feu sur les profils Domaine, Privé et Public..."
netsh advfirewall set allprofiles state on

# Définition des règles par défaut : Bloquer les connexions entrantes, autoriser les connexions sortantes
Write-Host "🔧 Configuration des règles par défaut..."
netsh advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound

# Désactivation complète de la gestion à distance
Write-Host "🚫 Blocage de la gestion à distance..."
$remoteManagementRules = @(
  "Remote Desktop - User Mode (TCP-In)",
  "Remote Desktop - User Mode (UDP-In)",
  "File and Printer Sharing (SMB-In)",
  "File and Printer Sharing (NB-Session-In)",
  "File and Printer Sharing (Echo Request - ICMPv4-In)",
  "File and Printer Sharing (Echo Request - ICMPv6-In)",
  "Windows Remote Management (HTTP-In)",
  "Windows Remote Management (HTTPS-In)",
  "Windows Management Instrumentation (WMI-In)",
  "Remote Event Log Management (NP-In)",
  "Remote Event Log Management (RPC-In)",
  "Remote Event Log Management (RPC-EPMAP)",
  "SNMP Trap (UDP-In)"
)

# Enable Firewall
Set-NetFirewallProfile -Profile Private,Public -Enabled True
Set-NetFirewallProfile -Profile Private,Public -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Private,Public -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Private,Public -NotifyOnListen True



foreach ($rule in $remoteManagementRules) {
  netsh advfirewall firewall set rule name="$rule" new enable=no
}

# Désactivation des services réseau sensibles
Write-Host "🛑 Désactivation des services réseau dangereux..."
$services = @(
  "RemoteRegistry",
  "TermService",      # Bureau à distance (RDP)
  "wscsvc",           # Centre de sécurité Windows (évite la télémétrie)
  "WinRM",            # Windows Remote Management
  "SSDPSRV",          # Découverte réseau SSDP
  "iphlpsvc",         # Tunnel IPv6 (désactive les tunnels non sécurisés)
  "wuauserv"          # Windows Update (désactive les mises à jour automatiques)
)

foreach ($service in $services) {
  sc.exe config $service start= disabled
  sc.exe stop $service
}

# Blocage des protocoles utilisés pour l’espionnage et la surveillance
Write-Host "🚷 Blocage des protocoles d’espionnage..."
$protocolsToBlock = @(
  "137", "138", "139",  # NetBIOS
  "445",               # SMB
  "135", "593",        # RPC
  "161", "162",        # SNMP
  "5353",              # mDNS (multicast DNS)
  "1900",              # SSDP (UPnP)
  "4500",              # IPsec NAT-T (évite les VPN forcés)
  "500"                # IPsec IKE (évite la surveillance via VPN d'entreprise)
)

foreach ($protocol in $protocolsToBlock) {
  netsh advfirewall firewall add rule name="Block Protocol $protocol" protocol=TCP dir=in localport=$protocol action=block
  netsh advfirewall firewall add rule name="Block Protocol $protocol" protocol=UDP dir=in localport=$protocol action=block
}

# Autorisation des ports nécessaires pour Internet et applications essentielles
Write-Host "✅ Autorisation des applications et services essentiels..."

$allowedApps = @(
  "C:\Program Files\Google\Chrome\Application\chrome.exe",
  "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
  "C:\Program Files\Mozilla Firefox\firefox.exe",
  "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
  "C:\Program Files\Discord\app-*\Discord.exe",
  "C:\Users\*\AppData\Local\Programs\Messenger\Messenger.exe",
  "C:\Program Files\Zoom\bin\Zoom.exe",
  "C:\Program Files (x86)\Skype\Phone\Skype.exe",
  "C:\Users\*\AppData\Local\Microsoft\Teams\current\Teams.exe",
  "C:\Program Files\OBS Studio\bin\64bit\obs64.exe"
)

foreach ($app in $allowedApps) {
  netsh advfirewall firewall add rule name="Allow $app" dir=out action=allow program="$app" enable=yes
}

# Autoriser le trafic Web (HTTP/HTTPS)
Write-Host "🌍 Autorisation du trafic Web..."
netsh advfirewall firewall add rule name="Allow Web Browsing" dir=out action=allow protocol=TCP remoteport=80,443

# Autoriser les appels vidéo et vocaux (Messenger, Discord, Zoom, Teams, Skype)
Write-Host "🎥 Autorisation des appels vidéo et vocaux..."
$voipPorts = @("3478-3481", "5004", "10000-20000")
foreach ($port in $voipPorts) {
  netsh advfirewall firewall add rule name="Allow VoIP Port $port" dir=out action=allow protocol=UDP remoteport=$port
}

# Liste complète des services de gestion à distance, cloud et autres outils de surveillance potentielle
$services = @(
  "AarSvc", "ALG", "AppMgmt", "AppReadiness", "AppVClient", "ApxSvc", "AssignedAccessManagerSvc", "autotimesvc",
  "AxInstSV", "BcastDVRUserService", "BITS", "CaptureService", "CDPSvc", "CertPropSvc", "ClipSVC", "CloudBackupRestoreSvc",
  "cloudidsvc", "COMSysApp", "ConsentUxUserSvc", "CredentialEnrollmentManagerUserSvc", "CscService", "dcsvc",
  "defragsvc", "DeviceAssociationBrokerSvc", "DeviceInstall", "DevicePickerUserSvc", "DevQueryBroker", "diagsvc",
  "DialogBlockingService", "DmEnrollmentSvc", "DoSvc", "dot3svc", "DsmSvc", "DsSvc", "EapHost", "edgeupdate",
  "edgeupdatem", "EFS", "embeddedmode", "EntAppSvc", "EventLog", "fdPHost", "FDResPub", "fhsvc", "FrameServer",
  "FrameServerMonitor", "GameInputSvc", "GoogleChromeElevationService", "GoogleUpdaterInternalService",
  "GoogleUpdaterService", "GraphicsPerfSvc", "hidserv", "icssvc", "IKEEXT", "Intel(R) Capability Licensing Service TCP IP Interface",
  "Intel(R) TPM Provisioning Service", "iphlpsvc", "IpxlatCfgSvc", "jhi_service", "KeyIso", "KtmRm", "lltdsvc", "LocalKdc",
  "LxpSvc", "MapsBroker", "McpManagementService", "MDCoreSvc", "MessagingService", "MicrosoftEdgeElevationService",
  "MSDTC", "MSiSCSI", "msiserver", "MsKeyboardFilter", "NaturalAuthentication", "NcaSvc", "NcdAutoSetup", "NetSetupSvc",
  "NetTcpPortSharing", "NlaSvc", "P9RdrService", "PenService", "perceptionsimulation", "PerfHost", "PhoneSvc",
  "PimIndexMaintenanceSvc", "pla", "PolicyAgent", "PrintDeviceConfigurationService", "PrintScanBrokerService",
  "PrintWorkflowUserSvc", "PushToInstall", "refsdedupsvc", "RetailDemo", "RpcEptMapper", "RpcLocator", "RpcSs",
  "SamSs", "SCardSvr", "ScDeviceEnum", "Schedule", "SCPolicySvc", "SDRSVC", "seclogon", "SEMgrSvc", "Sense",
  "SensorDataService", "SensorService", "SensrSvc", "SgrmBroker", "shpamsvc", "smphost", "SmsRouter", "SNMPTrap",
  "Spooler", "sppsvc", "SSDPSRV", "ssh-agent", "svsvc", "swprv", "TapiSrv", "TermService", "TieringEngineService",
  "TrkWks", "TroubleshootingSvc", "TrustedInstaller", "tzautoupdate", "UevAgentService", "UnistoreSvc", "upnphost",
  "UserDataSvc", "UsoSvc", "VaultSvc", "vds", "vmicguestinterface", "vmicheartbeat", "vmickvpexchange", "vmicrdv",
  "vmicshutdown", "vmictimesync", "vmicvmsession", "vmicvss", "VSS", "W32Time", "WaaSMedicSvc", "WalletService",
  "WarpJITSvc", "wbengine", "WbioSrvc", "wcncsvc", "WdiServiceHost", "WebClient", "WEPHOSTSVC", "wercplsupport",
  "WFDSConMgrSvc", "WiaRpc", "wisvc", "wlidsvc", "wlpasvc", "WManSvc", "wmiApSrv", "WMPNetworkSvc", "workfolderssvc",
  "WpcMonSvc", "WPDBusEnum", "WSearch", "wuauserv", "WwanSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc"
)

# Désactivation de tous les services listés
foreach ($service in $services) {
  Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
  Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
  Write-Host "Service $service désactivé."
}

Write-Host "Tous les services de gestion à distance et de surveillance ont été désactivés."

# Bloquer les connexions entrantes non sollicitées
Write-Host "🚨 Blocage des connexions entrantes suspectes..."
netsh advfirewall firewall add rule name="Block All Inbound" dir=in action=block protocol=any

Write-Host "✅ Pare-feu ultra sécurisé activé avec succès ! 🚀 Redémarre ton PC pour appliquer les changements."

# Exécution en mode administrateur requise
Write-Host "🚨 Désactivation des services et fonctionnalités de gestion à distance et de surveillance... 🚨"

# Liste des services à désactiver
$servicesToDisable = @(
  "RemoteRegistry",       # Registre à distance
  "TermService",         # Bureau à distance (RDP)
  "WinRM",               # Windows Remote Management
  "Wecsvc",              # Windows Event Collector
  "Wuauserv",            # Windows Update (désactive les mises à jour automatiques)
  "DiagTrack",           # Connected User Experiences and Telemetry (télémétrie)
  "dmwappushservice",    # DM WAP Push (télémétrie)
  "WMPNetworkSvc",       # Windows Media Player Network Sharing
  "TrkWks",              # Distributed Link Tracking Client (surveille les fichiers et liens)
  "iphlpsvc",            # Tunnel IPv6 (désactive les tunnels non sécurisés)
  "SSDPSRV",             # Découverte réseau SSDP (UPnP)
  "bthserv",             # Bluetooth Support Service (désactive le Bluetooth)
  "MapsBroker",          # Service de cartographie (désactive Bing Maps)
  "SharedAccess",        # Partage de connexion Internet
  "WSearch"              # Windows Search (empêche l'indexation et la collecte de données)
)

# Désactivation des services
foreach ($service in $servicesToDisable) {
  sc.exe config $service start= disabled
  sc.exe stop $service
}

Write-Host "✅ Services de surveillance et de gestion à distance désactivés."

# Désactivation de la télémétrie via le registre
Write-Host "🛠️ Désactivation de la télémétrie et des diagnostics..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v Start /t REG_DWORD /d 4 /f

# Désactivation de Cortana et des suggestions
Write-Host "❌ Désactivation de Cortana et des suggestions de Windows..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f

# Désactivation des connexions entrantes pour la gestion à distance
Write-Host "🚷 Blocage des connexions entrantes pour la gestion à distance..."
$firewallRules = @(
  "Remote Desktop - User Mode (TCP-In)",
  "Remote Desktop - User Mode (UDP-In)",
  "File and Printer Sharing (SMB-In)",
  "File and Printer Sharing (NB-Session-In)",
  "File and Printer Sharing (Echo Request - ICMPv4-In)",
  "File and Printer Sharing (Echo Request - ICMPv6-In)",
  "Windows Remote Management (HTTP-In)",
  "Windows Remote Management (HTTPS-In)",
  "Windows Management Instrumentation (WMI-In)",
  "Remote Event Log Management (NP-In)",
  "Remote Event Log Management (RPC-In)",
  "Remote Event Log Management (RPC-EPMAP)"
)

foreach ($rule in $firewallRules) {
  netsh advfirewall firewall set rule name="$rule" new enable=no
}

# Blocage des ports utilisés pour l’administration distante
Write-Host "🚨 Blocage des ports de gestion à distance..."
$portsToBlock = @(
  "135", "137", "138", "139", # NetBIOS et RPC
  "445",                     # SMB
  "500", "4500",             # VPN et IPsec
  "3389",                    # RDP (Remote Desktop)
  "5985", "5986",            # Windows Remote Management (HTTP & HTTPS)
  "1900",                    # SSDP (UPnP)
  "5353"                     # mDNS (multicast DNS)
)

foreach ($port in $portsToBlock) {
  netsh advfirewall firewall add rule name="Block Port $port" protocol=TCP dir=in localport=$port action=block
  netsh advfirewall firewall add rule name="Block Port $port" protocol=UDP dir=in localport=$port action=block
}

Write-Host "✅ Toutes les connexions non désirées sont bloquées."

# Désinstallation des applications de télémétrie et surveillance intégrées
Write-Host "🗑️ Désinstallation des applications de surveillance..."
$appsToRemove = @(
  "Microsoft.BingWeather",
  "Microsoft.GetHelp",
  "Microsoft.Getstarted",
  "Microsoft.Messaging",
  "Microsoft.Microsoft3DViewer",
  "Microsoft.MicrosoftOfficeHub",
  "Microsoft.MicrosoftSolitaireCollection",
  "Microsoft.NetworkSpeedTest",
  "Microsoft.News",
  "Microsoft.OneConnect",
  "Microsoft.People",
  "Microsoft.Print3D",
  "Microsoft.RemoteDesktop",
  "Microsoft.SkypeApp",
  "Microsoft.StorePurchaseApp",
  "Microsoft.WindowsAlarms",
  "Microsoft.WindowsCamera",
  "Microsoft.WindowsFeedbackHub",
  "Microsoft.WindowsMaps",
  "Microsoft.WindowsSoundRecorder",
  "Microsoft.Xbox.TCUI",
  "Microsoft.XboxApp",
  "Microsoft.XboxGameOverlay",
  "Microsoft.XboxGamingOverlay",
  "Microsoft.XboxIdentityProvider",
  "Microsoft.XboxSpeechToTextOverlay",
  "Microsoft.YourPhone",
  "Microsoft.ZuneMusic",
  "Microsoft.ZuneVideo"
)

foreach ($app in $appsToRemove) {
  Get-AppxPackage -AllUsers $app | Remove-AppxPackage
}

Write-Host "✅ Applications de surveillance et de télémétrie désinstallées."

# Désactivation de Windows Defender (optionnel)
Write-Host "🛡️ Désactivation de Windows Defender (optionnel)..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f

Write-Host "🚀 Désactivation complète de la gestion à distance et de la surveillance terminée ! Redémarre ton PC pour appliquer tous les changements."



# 1️⃣ Vérifier et réparer les fichiers système
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth

# 2️⃣ Vérifier les polices corrompues
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"

# 3️⃣ Modifier les permissions et relancer explorer avec SYSTEM
psexec -i -s explorer.exe

# 4️⃣ Créer un nouvel utilisateur administrateur pour tester
net user TestUser /add
net localgroup Administrators TestUser /add

# Redémarrer l'explorateur pour appliquer les changements
Stop-Process -Name explorer -Force
Start-Process explorer
