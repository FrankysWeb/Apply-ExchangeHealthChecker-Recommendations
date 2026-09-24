# Apply-ExchangeHealthChecker-Recommendations

This Script applies basic recommendations from Microsofts Exchange Health Checker Script.
You can use this Script to apply these recommendations:

- Set static Pagefile of 25% of installed memory size
- Disable NIC power saving
- set Power Plan to High Performance
- set TCP KeepAlive to 30 min
- configure TLS Settings
- configure Download Domains
- disable SSL Offloading
- disable and uninstall SMB1
- uninstall MSMQ
- correct duplicate entries in IanaTimeZoneMappings.xml
- configure Windows Extended Protection
- enable PowerShell serialization payload feature (Caution: This will restart IIS server)
- disable CredentialGuard (not supported by Exchange Server)

## Usage

Download the script and copy it to an Exchange Server. Run it from an elevated Exchange Management Shell.

All parameters are optional switches. Only the specified settings are applied; everything else is skipped.

Apply all recommendations:

```powershell
.\Apply-ExchangeHealthChecker-Recommendations.ps1 `
  -SetStaticPagefile `
  -SetDisableNicPowersaving `
  -SetPowerPlanToHighPerformance `
  -SetTCPKeepAliveTimeTo30Min `
  -SetTlsSettings `
  -SetDownloadDomains `
  -SetOASslOffloadingToFalse `
  -SetSMB1Uninstall `
  -SetMSMQ `
  -SetIanaTimeZoneMappings `
  -SetExchangeExtendedProtection `
  -SetPowerShellSerializationPayload `
  -SetDisableCredentialGuard
```

Apply selected recommendations only:

```powershell
.\Apply-ExchangeHealthChecker-Recommendations.ps1 -SetTlsSettings -SetSMB1Uninstall -SetDisableCredentialGuard
```

### Parameters

| Parameter | Description |
|---|---|
| `-SetStaticPagefile` | Sets a static pagefile (25% of RAM) |
| `-SetDisableNicPowersaving` | Disables NIC power saving |
| `-SetPowerPlanToHighPerformance` | Sets the power plan to High Performance |
| `-SetTCPKeepAliveTimeTo30Min` | Sets TCP KeepAliveTime to 30 minutes |
| `-SetTlsSettings` | Applies recommended TLS settings |
| `-SetDownloadDomains` | Configures OWA download domains |
| `-SetOASslOffloadingToFalse` | Disables SSL offloading for Outlook Anywhere |
| `-SetSMB1Uninstall` | Uninstalls and disables SMB1 |
| `-SetMSMQ` | Removes MSMQ |
| `-SetIanaTimeZoneMappings` | Removes duplicate IANA time zone mappings |
| `-SetExchangeExtendedProtection` | Configures Extended Protection |
| `-SetPowerShellSerializationPayload` | Enables PowerShell serialization payload signing |
| `-SetDisableCredentialGuard` | Disables Credential Guard (not supported on Exchange Server) |

A reboot is required for most settings to take effect. Run HealthChecker again afterwards to verify.

## Exchange Health Checker

Download Exchange Health Checker here [Exchange Health Checker](https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/)

## Tested Exchange / Windows Server Versions

- Exchange Server 2016
- Exchange Server 2019
- Windows Server 2022
- Windows Server 2025

## Website

 [FrankysWeb](https://www.frankysweb.de/)
