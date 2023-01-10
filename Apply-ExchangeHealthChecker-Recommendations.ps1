[CmdletBinding()]
Param (
    # Configure static 32GB Pagefile
    # https://aka.ms/HC-PageFile
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Configure static 32GB Pagefile (y/n)?")]
    [ValidateSet("y","n")]
    [string]$SetStaticPagefile,

    # Diable NIC power saving
    # https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/SleepyNICCheck/
    [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Diable NIC power saving (y/n)?")]
    [ValidateSet("y","n")]
    [string]$SetDisableNicPowersaving,

    # Set Power Plan to High Performance
    [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Set Power Plan to High Performance (y/n)?")]
    [ValidateSet("y","n")]
    [string]$SetPowerPlanToHighPerformance,

    # Set TCP KeepAliveTime to 30min
    # https://aka.ms/HC-TcpIpSettingsCheck
    [Parameter(Mandatory = $true, Position = 3, HelpMessage = "Set TCP KeepAliveTime to 30min (y/n)?")]
    [ValidateSet("y","n")]
    [string]$SetTCPKeepAliveTimeTo30Min,

    # Configure TLS settings
    # https://aka.ms/HC-TLSConfigDocs
    [Parameter(Mandatory = $true, Position = 4, HelpMessage = "Configure TLS settings (y/n)?")]
    [ValidateSet("y","n")]
    [string]$SetTlsSettings,

    # Configure Download Domains to Autodiscover Hostname
    # https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/DownloadDomainCheck/
    [Parameter(Mandatory = $true, Position = 5, HelpMessage = "Configure Download Domains to Autodiscover Hostname (y/n)?")]
    [ValidateSet("y","n")]
    [string]$SetDownloadDomains,

    # Disable OutlookAnywhere SSL Offloading
    # required for Windows Extended Protection
    [Parameter(Mandatory = $true, Position = 6, HelpMessage = "Disable OutlookAnywhere SSL Offloading (y/n)?")]
    [ValidateSet("y","n")]
    [string]$SetOASslOffloadingToFalse,

    # Configure Windows Extended Protection
    # https://microsoft.github.io/CSS-Exchange/Security/Extended-Protection/
    [Parameter(Mandatory = $true, Position = 7, HelpMessage = "Configure Windows Extended Protection (y/n)?")]
    [ValidateSet("y","n")]
    [string]$SetExchangeExtendedProtection
	
	# Configure PowerShell serialization payload feature?
    # https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/SerializedDataSigningCheck/
    [Parameter(Mandatory = $true, Position = 8, HelpMessage = "Configure PowerShell serialization payload feature (y/n)?")]
    [ValidateSet("y","n")]
    [string]$SetPowerShellSerializationPayload
)
Process {
  if ($SetStaticPagefile -eq "y") {

    $PageFileSizeMB = (Get-WMIObject -class Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | ForEach-Object {[Math]::Round(($_.sum / 1MB),2)*0.25})
    
    $pagefile = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
    $pagefile.AutomaticManagedPagefile = $false
    $pagefile.put() | Out-Null
    
    $pagefileset = Get-WmiObject Win32_pagefilesetting
    $pagefileset.InitialSize = $PageFileSizeMB
    $pagefileset.MaximumSize = $PageFileSizeMB
    $pagefileset.Put() | Out-Null
  }

  if ($SetDisableNicPowersaving -eq "y") {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" -Name "PnPCapabilities" -Value 280 -PropertyType "DWord" -Force
  }

  if ($SetPowerPlanToHighPerformance -eq "y") {
    $PowerPlan = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan -Filter "InstanceID = 'Microsoft:PowerPlan\\{8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}'"
    $PowerPlan.Activate()
  }
  
  if ($SetTCPKeepAliveTimeTo30Min -eq "y") {
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 1800000 -PropertyType DWord -Force
  }

  if ($SetTlsSettings -eq "y") {
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
  
  if ($SetDownloadDomains -eq "y") {
    $DownloadDomain = (Get-ClientAccessService).AutoDiscoverServiceInternalUri.Host
    Set-OwaVirtualDirectory -Identity "owa (default Web site)" -ExternalDownloadHostName $DownloadDomain -InternalDownloadHostName $DownloadDomain
    Set-OrganizationConfig -EnableDownloadDomains $true
  }

  if ($SetOASslOffloadingToFalse -eq "y") {
    Get-OutlookAnywhere -Server $env:computername | Set-OutlookAnywhere -SSLOffloading $false -InternalClientsRequireSsl $true -ExternalClientsRequireSsl $true
  }

  if ($SetExchangeExtendedProtection -eq "y") {
    $ScriptPath = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ExchangeExtendedProtectionManagement.ps1"
    Invoke-WebRequest -Uri $ScriptPath -outfile "ExchangeExtendedProtectionManagement.ps1"
    .\ExchangeExtendedProtectionManagement.ps1
  }
  
  if ($SetPowerShellSerializationPayload -eq "y") {
	New-SettingOverride -Name "EnableSigningVerification" -Component Data -Section EnableSerializationDataSigning -Parameters @("Enabled=true") -Reason "Enabling Signing Verification"
	Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh
  }
  
}