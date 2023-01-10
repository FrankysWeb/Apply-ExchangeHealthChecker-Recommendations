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
- configure Windows Extended Protection
- enable PowerShell serialization payload feature (Caution: This will restart IIS server)

## Usage

Download and copy this script to an Exchange Server.
Run this script interactive:

```
.\Apply-ExchangeHealthChecker-Recommendations.ps1
```

or with parameters:

```
.\Apply-ExchangeHealthChecker-Recommendations.ps1 -SetStaticPagefile "y" -SetDisableNicPowersaving "y" -SetPowerPlanToHighPerformance "y" 
-SetTCPKeepAliveTimeTo30Min "y" -SetTlsSettings "n" -SetDownloadDomains "n" -SetOASslOffloadingToFalse "y" 
-SetExchangeExtendedProtection "y"
```

## Exchange Health Checker

Download Exchange Health Checker here [Exchange Health Checker](https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/)

## Tested Exchange / Windows Server Versions

- Exchange Server 2019
- Windows Server 2022

## Website

 [FrankysWeb](https://www.frankysweb.de/)
