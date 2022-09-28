# Apply-ExchangeHealthChecker-Recommendations
This Script applies basic recommendations from Microsofts Exchange Health Checker Script.
You can use this Script to apply these recommendations:
  - Set static Pagefile to 32GB
  - Disable NIC power saving
  - set Power Plan to High Performance
  - set TCP KeepAlive to 30 min
  - configure TLS Settings
  - configure Download Domains
  - disable SSL Offloading
  - configure Windows Extented Protection

## Usage
Download and copy this script to an Excchange Server.
Run this script:

```
.\Apply-ExchangeHealthChecker-Recommendations.ps1
```

## Exchange Health Checker
Download Exchange Health Checker here [Exchange Health Checker](https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/)

## Tested Exchange / Windows Server Versions
 - Exchange Server 2019
 - Windows Server 2022

## Website
 [FrankysWeb](https://www.frankysweb.de/)