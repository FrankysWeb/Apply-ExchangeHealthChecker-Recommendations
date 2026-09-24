[CmdletBinding()]
Param (
    # Configure static 32GB Pagefile
    # https://aka.ms/HC-PageFile
    [switch]$SetStaticPagefile,

    # Diable NIC power saving
    # https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/SleepyNICCheck/
    [switch]$SetDisableNicPowersaving,

    # Set Power Plan to High Performance
    [switch]$SetPowerPlanToHighPerformance,

    # Set TCP KeepAliveTime to 30min
    # https://aka.ms/HC-TcpIpSettingsCheck
    [switch]$SetTCPKeepAliveTimeTo30Min,

    # Configure TLS settings
    # https://aka.ms/HC-TLSConfigDocs
    [switch]$SetTlsSettings,

    # Configure Download Domains to Autodiscover Hostname
    # https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/DownloadDomainCheck/
    [switch]$SetDownloadDomains,

    # Disable OutlookAnywhere SSL Offloading
    # required for Windows Extended Protection
    [switch]$SetOASslOffloadingToFalse,
	
	# SMB1 uninstall
    # Error "SMB1 Installed = true" and "SMB1 Blocked = false"
    [switch]$SetSMB1Uninstall,
	
	# MSMQuninstall
    # Warning "MSMQ Windows Feature Installed"
    [switch]$SetMSMQ,

	# IanaTimeZoneMappings.xml invalid
	# Correct IanaTimeZoneMappings.xml with external MS Script
    [switch]$SetIanaTimeZoneMappings,

    # Configure Windows Extended Protection
    # https://microsoft.github.io/CSS-Exchange/Security/Extended-Protection/
    [switch]$SetExchangeExtendedProtection,
	
	# Configure PowerShell serialization payload feature?
    # https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/SerializedDataSigningCheck/
    [switch]$SetPowerShellSerializationPayload,

    # Disable Credential Guard (not supported by Exchange Server)
    # https://learn.microsoft.com/de-de/windows/security/identity-protection/credential-guard/configure?tabs=reg
    [switch]$SetDisableCredentialGuard
)
Process {
  if ($SetStaticPagefile) {

    $PageFileSizeMB = (Get-WMIObject -class Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | ForEach-Object {[Math]::Round(($_.sum / 1MB),2)*0.25})
    
    $pagefile = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
    $pagefile.AutomaticManagedPagefile = $false
    $pagefile.put() | Out-Null
    
    $pagefileset = Get-WmiObject Win32_pagefilesetting
    $pagefileset.InitialSize = $PageFileSizeMB
    $pagefileset.MaximumSize = $PageFileSizeMB
    $pagefileset.Put() | Out-Null
  }

  if ($SetDisableNicPowersaving) {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" -Name "PnPCapabilities" -Value 280 -PropertyType "DWord" -Force
  }

  if ($SetPowerPlanToHighPerformance) {
    $PowerPlan = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan -Filter "InstanceID = 'Microsoft:PowerPlan\\{8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}'"
    $PowerPlan.Activate()
  }
  
  if ($SetTCPKeepAliveTimeTo30Min) {
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 1800000 -PropertyType DWord -Force
  }

  if ($SetTlsSettings) {
    # Enable TLS 1.2
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server")) {
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1 -PropertyType "DWord" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -PropertyType "DWord" -Force
    
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client")) {
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 1 -PropertyType "DWord" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -PropertyType "DWord" -Force
    
    If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319")) {
      New-Item "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Force
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Value 1 -PropertyType "DWord" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -PropertyType "DWord" -Force
    
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319")) {
      New-Item "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Force
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Value 1 -PropertyType "DWord" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -PropertyType "DWord" -Force
    
    # Enable TLS 1.2 for .NET 3.5
    If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727")) {
      New-Item "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Force
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Name "SystemDefaultTlsVersions" -Value 1 -PropertyType "DWord" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Name "SchUseStrongCrypto" -Value 1 -PropertyType "DWord" -Force
    
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727")) {
      New-Item "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Force
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name "SystemDefaultTlsVersions" -Value 1 -PropertyType "DWord" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name "SchUseStrongCrypto" -Value 1 -PropertyType "DWord" -Force
    
    # Disable TLS 1.0
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server")) {
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0 -PropertyType "DWord" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force
    
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")) {
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Value 0 -PropertyType "DWord" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force
    
    # Disable TLS 1.1
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server")) {
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0 -PropertyType "DWord" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force
    
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")) {
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Value 0 -PropertyType "DWord" -Force 
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force
    
    # Disable TLS 1.3 (currently not supported by Exchange Server)
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server")) {
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -Value 0 -PropertyType "DWord" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force
    
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client")) {
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name "Enabled" -Value 0 -PropertyType "DWord" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name "DisabledByDefault" -Value 1 -PropertyType "DWord" -Force
  }
  
  if ($SetDownloadDomains) {
    $DownloadDomain = (Get-ClientAccessService).AutoDiscoverServiceInternalUri.Host
    Set-OwaVirtualDirectory -Identity "owa (default Web site)" -ExternalDownloadHostName $DownloadDomain -InternalDownloadHostName $DownloadDomain
    Set-OrganizationConfig -EnableDownloadDomains $true
  }

  if ($SetOASslOffloadingToFalse) {
    Get-OutlookAnywhere -Server $env:computername | Set-OutlookAnywhere -SSLOffloading $false -InternalClientsRequireSsl $true -ExternalClientsRequireSsl $true
  }
  
  if ($SetSMB1Uninstall) {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
  }

  if ($SetMSMQ) {
    Remove-WindowsFeature NET-WCF-MSMQ-Activation45,MSMQ -Confirm:$false
  }

  if ($SetExchangeExtendedProtection) {
    $ScriptPath = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ExchangeExtendedProtectionManagement.ps1"
    Invoke-WebRequest -Uri $ScriptPath -outfile "ExchangeExtendedProtectionManagement.ps1"
    .\ExchangeExtendedProtectionManagement.ps1
  }
  
  if ($SetPowerShellSerializationPayload) {
	New-SettingOverride -Name "EnableSigningVerification" -Component Data -Section EnableSerializationDataSigning -Parameters @("Enabled=true") -Reason "Enabling Signing Verification"
	Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh
  }

  if ($SetIanaTimeZoneMappings) {  
    $ScriptPath = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/Remove-DuplicateEntriesFromIanaMappings.ps1"
    Invoke-WebRequest -Uri $ScriptPath -outfile "Remove-DuplicateEntriesFromIanaMappings.ps1"
    .\Remove-DuplicateEntriesFromIanaMappings.ps1
  }

  if ($SetDisableCredentialGuard) {
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")) {
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Force
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0 -PropertyType "DWord" -Force

    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard")) {
      New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Force
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value 0 -PropertyType "DWord" -Force
  }
}