# Sudden-Network-Slowdown

<p align="center">
  <img src=https://github.com/user-attachments/assets/72c897db-4f25-48a6-8256-74625acb1d7c width="500">
</p>


# Suspected Exfiltration of Company Data
- [Scenario Creation](https://github.com/JordanDanielWest/Exfiltration-of-Company-Data/blob/main/Exfiltration%20of%20Company%20Data%20Event%20Creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Powershell

##  Investigation Scenario: Data Exfiltration from PIPd Employee

An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company. Your task is to investigate John's activities on his corporate device (windows-target-1) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.


- **Check `DeviceProcessEvents`**
- **Check `DeviceFileEvents`**
- **Check `DeviceNetworkEvents`**

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

I ran a query on John Doe’s computer “windows-target-1” to determine if he was archiving company data. I discovered a ProcessCommandLine that indicates the creation of a 7zip file titled “employee-data-20250416124922.zip” which was saved to the ProgramData folder.

**Query used to locate events:**

```kql
let archive_applications = dynamic(["winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe", "Bandizip.exe", "UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"]);
let VMName = "windows-target-1";
DeviceProcessEvents
| where DeviceName == VMName
| where FileName has_any(archive_applications)
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/c6a6ebff-c56e-4cbe-b530-a3d1688507cc)


---

### 2. Searched the `DeviceFileEvents` Table

I took an instance of a zip file being created, copied the Timestamp(2025-04-16T08:49:14.2340327Z) and created a new query under DeviceFileEvents and then observed two minutes after and two minutes before the archive was created. I discovered around the same time that a powershell script was used to install 7zip silently in the background which then collected and zipped employee data into an archive.

**Query used to locate event:**

```kql

let specificTime = datetime(2025-04-16T08:49:14.2340327Z);
let VMName = "windows-target-1";
DeviceFileEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine

```
![image](https://github.com/user-attachments/assets/8154f089-7ecd-45b7-8606-3d38b7f905e5)



---

### 3. Searched the `DeviceNetworkEvents` Table

I then conducted a query within the DeviceNetworkEvents table and discovered no indication of exfiltration of data from the network.

**Query used to locate events:**

```kql
let specificTime = datetime(2025-04-16T08:49:14.2340327Z);
let VMName = "windows-target-1";
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType


```



### Response:

I Immediately isolated the system once archiving of files was discovered.
I relayed all of the information to the employee’s manager, including the information regarding the staging of zipped data into an archive created at regular intervals via powershell script. There was no clear evidence of exfiltration however I felt the situation was still suspicious enough to report as it seems to indicate staging of data T1074 – Data Staged of the MITRE ATT&CK framework.


### MITRE ATT&CK TTPs Identified
- **T1059 – Command and Scripting Interpreter**
  - *T1059.001 – PowerShell*  
	Use of PowerShell script (`exfiltratedata.ps1`) to automate tasks and bypass execution policies.
- **T1560 – Archive Collected Data**
  - *T1560.001 – Archive via Utility*  
	Zipping sensitive files using 7-Zip installed silently via script.
- **T1074 – Data Staged**  
Local staging of proprietary data into a ZIP file prior to potential exfiltration.
- **T1204 – User Execution** 
Script manually executed under suspicious conditions
- **T1105 – Ingress Tool Transfer**  
7-Zip installer was downloaded as part of the process



---

## Chronological Event Timeline 

1. Execution of PowerShell Script – exfiltratedata.ps1

    Timestamp: 2025-04-16T08:49:00.7998534Z

    Event: The user "John Doe" executed a PowerShell script.

    Action: PowerShell script detected.

    File Path: C:\ProgramData\exfiltratedata.ps1

2. Silent Installation of 7-Zip

    Timestamp: 2025-04-16T08:49:07.1290321Z

    Event: 7-Zip was installed silently via the PowerShell script.

    Action: Installation of 7z.exe detected.

    File Path: C:\Program Files\7-Zip\7z.exe

    Command Line: powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\exfiltratedata.ps1

3. Creation of Archive File – employee-data-20250416124922.zip

    Timestamp: 2025-04-16T08:49:14.2340327Z

    Event: An archive containing employee data was created.

    Action: 7z.exe used to zip files.

    File Path: C:\ProgramData\employee-data-20250416124922.zip

    Command Line: "C:\Program Files\7-Zip\7z.exe" a C:\ProgramData\employee-data-20250416124922.zip [source files]

4. Network Activity Check – No Exfiltration Detected

    Timestamp Range: 2025-04-16T08:47:14Z – 2025-04-16T08:51:14Z

    Event: Reviewed outbound connections during and around archive creation.

    Result: No network exfiltration detected from windows-target-1.
---

## Summary

John Doe downloaded a PowerShell script named `exfiltratedata.ps1` from a remote GitHub repository and saved it to the `C:\ProgramData\` directory. He then executed the script with PowerShell, bypassing the default execution policy. As a result, the script simulated data exfiltration, demonstrating how an attacker might collect and transmit sensitive information.

---

