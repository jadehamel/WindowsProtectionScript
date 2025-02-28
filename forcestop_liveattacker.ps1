$scriptBlock = {
  while ($true) {
    # Activer le pare-feu et configurer les règles générales
    Set-NetFirewallProfile -Profile Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True
    Write-Host "✅ Pare-feu configuré."

    # Supprimer toutes les règles existantes
    Write-Host "🔄 Suppression des règles de pare-feu..."
    netsh advfirewall firewall delete rule name=all

    # Blocage des protocoles sensibles
    Write-Host "🚷 Blocage des protocoles d’espionnage..."
    $protocols = @("137","138","139","445","135","593","161","162","5353","1900","4500","500")
    foreach ($protocol in $protocols) {
      netsh advfirewall firewall add rule name="Block Protocol $protocol" protocol=TCP,UDP dir=in localport=$protocol action=block
    }

    # Autorisation des applications et services essentiels
    Write-Host "✅ Autorisation des services essentiels..."
    $allowedApps = @("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
    foreach ($app in $allowedApps) {
      netsh advfirewall firewall add rule name="Allow $app" dir=out action=allow program="$app" enable=yes
    }

    # Autoriser le trafic Web et VoIP
    Write-Host "🌍 Autorisation du trafic Web et VoIP..."
    netsh advfirewall firewall add rule name="Allow Web Browsing" dir=out action=allow protocol=TCP remoteport=80,443
    $voipPorts = @("3478-3481", "5004", "10000-20000")
    foreach ($port in $voipPorts) {
      netsh advfirewall firewall add rule name="Allow VoIP Port $port" dir=out action=allow protocol=UDP remoteport=$port
    }

    # Désactivation et suppression des services indésirables
    Write-Host "🛑 Désactivation des services espions..."
    $servicesToDisable = @("DiagTrack", "dmwappushservice", "Wecsvc", "WerSvc", "RemoteRegistry", "WinRM", "SessionEnv", "TermService", "UmRdpService", "Netlogon", "RasAuto", "RemoteAccess", "SharedAccess", "PeerDistSvc", "WpnService")
    foreach ($service in $servicesToDisable) {
      $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
      if ($serviceObj) {
        if ($serviceObj.Status -eq "Running") { Stop-Service -Name $service -Force }
        Set-Service -Name $service -StartupType Disabled
        sc.exe delete $service | Out-Null
      }
    }

    # Désactivation d’autres services de surveillance
    Write-Host "📴 Désactivation des services supplémentaires..."
    $additionalServices = @("wuauserv", "UsoSvc", "WaaSMedicSvc", "DoSvc", "BITS", "wcncsvc", "RemoteRegistry", "DiagTrack", "dmwappushservice", "DPS", "TrkWks", "SEMgrSvc", "WMPNetworkSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc", "wlidsvc", "wisvc", "WSearch", "DiagSvc", "Spooler", "PcaSvc", "Wecsvc", "WbioSrvc", "WdiServiceHost", "WdiSystemHost", "WpnUserService", "WpnService", "CscService", "RasMan", "SessionEnv", "TermService", "UmRdpService", "PolicyAgent", "IKEEXT", "iphlpsvc", "SNMPTrap", "RemoteAccess", "LanmanServer")
    foreach ($service in $additionalServices) {
      Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
      Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    }

    # Désactiver la télémétrie et les mises à jour automatiques
    Write-Host "🚫 Désactivation de la télémétrie et des mises à jour automatiques..."
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
  }
}
Start-Job -ScriptBlock $scriptBlock
