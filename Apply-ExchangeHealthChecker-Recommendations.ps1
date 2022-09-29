#Only used for confirmation
$title = "Confirm"
$choices  = "&Yes", "&No"

# Set Pagefile to 32778MB
# https://aka.ms/HC-PageFile
$question = "Configure static 32GB Pagefile?"
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
 $pagefile = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
 $pagefile.AutomaticManagedPagefile = $false
 $pagefile.put() | Out-Null

 $pagefileset = Get-WmiObject Win32_pagefilesetting
 $pagefileset.InitialSize = 32778
 $pagefileset.MaximumSize = 32778
 $pagefileset.Put() | Out-Null
}

# Diable NIC power saving
# https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/SleepyNICCheck/
$question = "Disable NIC Power Saving?"
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
 New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" -Name "PnPCapabilities" -Value 280 -PropertyType "DWord" -Force
}

# Set Power Plan to High Performance
$question = "Set PowerPlan to High Performance?"
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
 $PowerPlan = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan -Filter "InstanceID = 'Microsoft:PowerPlan\\{8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}'"
 $PowerPlan.Activate()
}

# Set TCP KeepAliveTime to 30min
# https://aka.ms/HC-TcpIpSettingsCheck
$question = "Set TCP KeepAliveTime to 30min?"
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
 New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 1800000 -PropertyType DWord -Force
}

# Configure TLS settings
# https://aka.ms/HC-TLSConfigDocs
# Enable TLS 1.2
$question = "Configure TLS Settings?"
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
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

# Configure Download Domains to Autodiscover Hostname
# https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/DownloadDomainCheck/
$question = "Configure Download Domains and set it to Autodiscover vDir URL?"
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
 $DownloadDomain = (Get-ClientAccessService).AutoDiscoverServiceInternalUri.Host
 Set-OwaVirtualDirectory -Identity "owa (default Web site)" -ExternalDownloadHostName $DownloadDomain -InternalDownloadHostName $DownloadDomain
 Set-OrganizationConfig -EnableDownloadDomains $true
}

# Disable OutlookAnywhere SSL Offloading
# required for Windows Extended Protection
$question = "Disable SSL Offloading for Outlook Anywhere?"
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
 Get-OutlookAnywhere -Server $env:computername | Set-OutlookAnywhere -SSLOffloading $false -InternalClientsRequireSsl $true -ExternalClientsRequireSsl $true
}

# Configure Windows Extended Protection
# https://microsoft.github.io/CSS-Exchange/Security/Extended-Protection/
$question = "Download ExchangeExtendedProtectionManagement.ps1 and configure Windows Extended Protection?"
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
 $ScriptPath = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ExchangeExtendedProtectionManagement.ps1"
 Invoke-WebRequest -Uri $ScriptPath -outfile "ExchangeExtendedProtectionManagement.ps1"
 .\ExchangeExtendedProtectionManagement.ps1
}
