# Hypothesis-Driven Threat Hunting with PEAK


## Topic: Data-Exfiltration



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

# Execute

## Gather Data


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
> **On (2025-03-17T00:04:21.1003474Z) evidence was found that John Doe used a powershell script to compress data into a 7zip file and archived it into a "backup" folder, no evidence was found of that data being exfiltrated.**

---
## Refine Hypothesis
This step is optional but may be necessary when you are unable to confirm or deny your initial hypothesis. In our sample hunt, we managed to find traces of cryptomining activities on both approaches, which confirmed our initial hypothesis, hence there is no need to refine it.


# Act: Wrapping Up the Investigation
The “Act” phase is all about making sure the knowledge gained from your hunt is captured and acted on. It’s what allows hunting to drive security improvement in your organization. 

## Preserve Hunt
The techniques used in your hunt can be archived as **detection rules** for future hunts. Archive the following:
- Hunt topic 
- Hypothesis
- Data sources
- Analysis techniques
- Queries and code samples

## Document Findings
Your documentation of findings represents the significance and impact of your hunt. Include:
- Malicious activities found
- Affected assets/accounts/applications
- Potential incidents escalated
- Data or detection gaps found
- Misconfigurations identified

## Create Detections
Regardless of how your organization’s change process is, your findings should be converted into production detection rules or signatures to catch similar threats in the future. Using your hunts to improve automated detection is the other key driver behind the continuous improvement of your organization’s security posture. 

Keep in mind that, according to PEAK’s Hierarchy of Detection Outputs, you have multiple options for the detections you create. For example, while the DNS analysis might make a great choice for an automated alert, the CPU usage analysis is only suggestive of cryptomining, and not suitable for automated alerting. In this case, it might be better to create a dashboard using those results and have an analyst review it on a regular basis.

## Re-Add Topic to Backlog
If new insights arise, add them to your hunt backlog for future investigation.

## Communicate Findings
Share your hunting discoveries with relevant stakeholders, such as the **SOC, system owners, or security teams**. Methods can include:
- Reports
- Briefings
- Emails summarizing findings

---

**This concludes our threat hunting process using Splunk for detecting unauthorized cryptocurrency mining.** 🚀
