# Topic: Data-Exfiltration



## Research

Data exfiltration is the act of collecting data from a network and moving that data out of that network. This data will typically be compressed and encrypted to help avoid detection and then transffered over to a C2 server. This attack can be carried out by both external and internal threats actors.

### Understanding Data Exfiltration:
- [What is Data Exfiltration?](https://www.paloaltonetworks.com/cyberpedia/data-exfiltration)
- [12 Real-World Examples of data exfiltration](https://gravyty.com/blog/data-exfiltration-examples/)
- [Data Exfiltration: Prevention, Risks & Best Practices](https://www.splunk.com/en_us/blog/learn/data-exfiltration.html)

### Hunting for Data Exfiltration:
- [Exfiltration- MITRE ATT&CK](https://attack.mitre.org/tactics/TA0010/)
- [Detecting data exfiltration activities](https://lantern.splunk.com/Security/UCE/Guided_Insights/Anomaly_detection/Detecting_data_exfiltration_activities#:~:text=When%20attackers%20are%20looking%20to,systems%20and%20observing%20user%20activity.)
- [How To Detect Data Exfiltration](https://www.blumira.com/blog/detecting-data-exfiltration)

## Hypothesis
An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company. John is an administrator on his device and is not limited on which applications he uses. He may try to archive/compress sensitive information and send it to a private drive or server.

## Scope Hunt
Your task is to investigate John's activities on his corporate device (Andrew-Sentinel) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

### **ABLE Framework for Exfiltration Hunt**

- **Actor**: Employee John Doe
- **Behavior**: Based on research, we know that threat actors will typically compress data in order to exfiltrate. We will look for any compression tools used recently by John
- **Location**: Azure VM endpoint (Andrew-Sentinel)
- **Evidence**: Using KQL, query MDE to find any evidence of compression and/or encryption tools being used by John. Also find any evidence of successful exfiltration to a possible C2 server, device, or anything related. 


# Plan

Look for anomalies, patterns, or indicators of compromise (IOCs) using various tools and techniques. 

Query the following tables:

- **DeviceFileEvents**: Contains information about file creation, modification, and other file system events
- **DeviceProcessEvents**: Contains information about process creation and related events
- **DeviceNetworkEvents**: Contains information about network connections and related events

---

# Gathering Data


We searched within MDE ``DeviceFileEvents`` for any zip file activity and observed frequent instances of files being archived and moved to a "backup" folder as part of regular activity.

```
DeviceFileEvents
| where DeviceName == "andrew-sentinel"
| where FileName endswith ".zip"
| order by Timestamp desc
```
![DeviceFileEvents](https://github.com/user-attachments/assets/a8ce2206-115f-4499-8a4b-49e03cdd06f6)


------

I identified an instance of a zip file being created, noted the timestamp, and searched within ``DeviceProcessEvents`` for any activity occurring two minutes before and after the archive's creation. During this timeframe, I discovered that a PowerShell script had silently installed 7-Zip and then used it to compress employee data into an archive.

```
let VMName = "andrew-sentinel";
let specificTime = datetime(2025-03-17T00:04:21.1003474Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
![deviceprocessevents](https://github.com/user-attachments/assets/3cf0cf14-c7b0-44da-8355-dc93b9d9f385)



## Analyze

However, even after searching around the same time period, there was no indication of successful data exfiltration within the Network Event logs. After adjusting the Timestamp to search a day before and after, there were still no indications of successfull exfiltration or even attempt to try.

```
let VMName = "andrew-sentinel";
let specificTime = datetime(2025-03-17T00:04:21.1003474Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, ActionType = "ConnectionSuccess", RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### **Executive Summary**
> **On (2025-03-17T00:04:21.1003474Z) evidence was found that John Doe used a powershell script to compress data into a 7zip file and archived it into a "backup" folder, no evidence was found of that data being exfiltrated. However his account should still be monitored just in case. Adjustments need to be made such as what employees can have administrative privledges on there devices. Also update policies that prevent users from running automated powershell scripts on company devices**

---

# Wrapping Up the Investigation

## Preserve Hunt
A summary of this hunt can be used in the future if suspected data exfiltration is seen
- Hunt topic: Exfiltration
- Data sources: Microsoft Defender for Endpoint(MDE). Microsoft Sentinel. Azure VMs
- Analysis techniques: Search for compression/encryption tools. Utilize network logs to find that data was successfully exfiltrated. Keep the timeframe relevant to your hypothesis.
- KQL Tables:
```
  DeviceFileEvents
  DeviceProcessEvents
  DeviceNetworkEvents
```

## Document Findings
Though there was no evidence of successful data exfiltration, employee John Doe was able to run a PowerShell script with administrative privileges to compress and archive files.

# Detection Rules for Microsoft Sentinel

## 1. PowerShell Suspicious Activity Alert

**Description:** Detects when PowerShell executes administrative commands related to file compression.

**Log Source:** Microsoft Defender for Endpoint logs (SecurityEvent, DeviceProcessEvents)

```kql
SecurityEvent  
| where EventID == 4688  // Process creation event  
| where NewProcessName contains "powershell.exe"  
| where CommandLine contains "Compress-Archive" or CommandLine contains "7z.exe a"
```

---

## 2. Unexpected Software Installation Alert

**Description:** Detects installation of compression tools like 7-Zip, WinRAR, or other utilities used for data exfiltration.

**Log Source:** DeviceProcessEvents

```kql
SecurityEvent  
| where EventID == 4688  
| where NewProcessName contains "msiexec.exe" or NewProcessName contains "choco.exe" or NewProcessName contains "winget.exe"
| where CommandLine contains "7zip" or CommandLine contains "winrar"
```

---

## 3. Abnormal File Archiving and Movement

**Description:** Monitors when a user archives files and moves them to an external or unusual directory.

**Log Source:** DeviceFileEvents

```kql
DeviceFileEvents  
| where FileName endswith ".zip" or FileName endswith ".7z"  
| where FolderPath contains "C:\\Users\\Public" or FolderPath contains "D:\\Backup"
```

---

## 4. File Upload to External Location

**Description:** Alerts if a newly created archive is uploaded to cloud storage (OneDrive, Google Drive) or sent via email.

**Log Source:** Microsoft Defender for Cloud Apps logs

```kql
CloudAppEvents  
| where ActionType contains "Upload"  
| where Destination contains "drive.google.com" or Destination contains "onedrive.com"
| where FileName endswith ".zip" or FileName endswith ".7z"
```

---

## Mitigation & Response Actions

- **Block execution of unauthorized PowerShell scripts** using Windows Defender Application Control (WDAC) or Attack Surface Reduction (ASR) rules.
- **Restrict software installation permissions** to prevent users from installing 7-Zip or other tools without approval.
- **Enable file integrity monitoring (FIM)** to detect unauthorized changes to sensitive folders.
- **Monitor endpoint activity in real-time** using MDE’s Live Response feature for deeper forensic analysis.



# Incident Report: Suspected Data Exfiltration

### Audience: SOC, System Owners, Security Teams 

### Summary  
A PowerShell script executed with administrative privileges was used to silently install 7-Zip, compress sensitive employee data into an archive, and store it in a backup folder. No evidence of successful data exfiltration was found, but this activity indicates a potential insider threat or unauthorized automation.

## Impact Assessment  
- **Risk Level:** Medium-High  
- **Potential Consequences:** Data exfiltration risk, unauthorized software installations, privilege misuse.  
- **Affected Systems:** Workstations with local admin privileges.  

---

## Recommendations & Next Steps  

### For the SOC Team:  
✅ Enable **detections in Microsoft Defender for Endpoint (MDE)** for:  
   - PowerShell executions with administrative privileges.  
   - Silent installations of 7-Zip or similar software.  
   - Archiving of sensitive data using unauthorized tools.  

✅ **Implement hunting queries in Microsoft Sentinel** (KQL queries provided).  

✅ Conduct **additional threat hunting** to verify whether similar activity has occurred elsewhere.  

---

### For System Owners & Security Teams:  
🔒 **Restrict PowerShell Execution Policies** to prevent unauthorized script execution.  

🚫 **Block Unapproved Software Installations** via Group Policy or Application Control (WDAC/ASR).  

📂 **Enable File Integrity Monitoring (FIM)** on directories storing sensitive employee data.  

🔍 **Monitor Cloud Storage and Email Uploads** for unexpected data transfers.  

---

## Next Steps & Follow-Up Actions  
📅 **SOC Team:** Review and implement Sentinel detections within **48 hours**.  
📅 **System Owners:** Restrict installation privileges by **end of the week**.  
📅 **Security Teams:** Conduct **follow-up investigations** on similar activity.  

---
