#Hypothesis-Driven Threat Hunting with PEAK


## Topic: Data-Exfiltration



## Research Topic

### Understanding Data Exfiltration:
- [What is Data Exfiltration](https://www.paloaltonetworks.com/cyberpedia/data-exfiltration)
- [What is Cryptojacking and how does it work?](#)
- [Ransomware May Be Dying Out, But Cryptojacking Is Up 399%](#)
- [The Cryptomining Malware Family](#)
- [A First Look at Browser-Based Cryptojacking](#)
- [Who and What is Coinhive?](#)

### Hunting for Cryptomining:
- [Detecting XMRig CPU or GPU mining](#)
- [Resource Hijacking (MITRE ATT&CK)](#)
- [Cryptocurrency mining domain lists](#)

## Generate Hypothesis
Building on the research conducted, the next step is to generate a hypothesis that will serve as the basis for your hunt. Make sure your hypothesis is testable so that you can either confirm or refute it while hunting. For this example, our hypothesis is:

> **“There might be unauthorized cryptocurrency mining happening on the network.”**

## Scope Hunt
With your hypothesis set and ready, it is time to define the boundaries of investigation for the scope of your hunt. The scope will include setting a maximum duration for the hunt and utilizing the **Actor, Behavior, Location, Evidence (ABLE) framework** to assist in capturing the essential elements of your hunting hypothesis. 

### **ABLE Framework for Cryptomining Hunt**

- **Actor**: None. This is reasonably common for things such as cryptomining, which may not be strongly tied to a specific threat actor.
- **Behavior**: Based on our research, we know that cryptominers typically require large amounts of CPU and/or GPU time, which can be costly for legitimate miners. This is why many cryptocurrency-oriented threat actors resort to stealing resources. We’re looking for a variant of MITRE ID T1496, “Resource Hijacking”. 
- **Location**: “Servers and cloud-based systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Resource Hijacking and cryptocurrency mining” (MITRE ATT&CK, Resource Hijacking). Due to the small data, we are looking at all hosts, but in a "real" hunt with more data, we might hunt on specific sets of endpoints, for example DMZ servers, first.
- **Evidence**: There are two data sources within BOTSv3 that are relevant to this hunt.
  - **PerfmonMk:Process**: Windows performance monitoring logs.
  - **stream:dns**: DNS query logs to check for cryptomining domains.

# Plan
Now that your research is comprehensive and the ABLE data is organized, the next crucial step involves formulating a plan for the approaches you intend to use in validating your hypothesis. For our example, here are the approaches we are going to incorporate in our plan, both based on MITRE ATT&CK detections for Resource Hijacking:

### **Approach 1: Sensor Health (DS0013)**
- Hunt for hijacking of computer resources via CPU utilization spikes or sustained high CPU usage.
- Investigate any suspicious processes exhibiting high CPU utilization.

### **Approach 2: Network Traffic (DS0029)**
- Hunt for network traffic flows or connection creations.
- Use known blacklists of cryptomining domains to identify connections.

---

# Execute: Rooting Out the Bad Guys

## Gather Data
The first step is to gather the data needed for your hunt. The path to data collection may vary, especially if your organization already has a SIEM collecting the various data sources into a central location for analysis. In cases where SIEM is not in place or does not cover all the required data sources, you might have to identify the specific server(s) and locations on disk from which to collect the data, then manually transfer them to the analysis system. In our example, the data we need has already been loaded into Splunk.

The perfmon data (sourcetype=PerfmonMk:Process) has information about processes running on the system, as captured in roughly 10 second intervals by Microsoft’s Performance Monitor. Events here are periodic snapshots of process data with point-in-time CPU utilization information with fields such as  process_name, process_cpu_used_percent and process_mem_used. This would be useful in our Approach 1 as we will be able to observe how some processes are utilizing CPU across time and we will be able to drill down to processes with notably high CPU utilization. For illustration purposes, here are several entries for the same process, a particular instance of MsMpEng.exe, during its lifetime.

![image](https://github.com/user-attachments/assets/b9850fac-8d55-4320-a2a3-0b1e8fc88b8e)

The DNS query data (sourcetype=stream:dns) is more straightforward. It has information about DNS requests gathered from DNS server logs. The entries contain fields such as dest_ip, src_ip, dest_port, src_port, bytes, and query. This would be used in Approach 2 to find out if any of the hosts made any successful connections to known cryptomining domains. 


## Pre-Process Data
There are times when the collected data may not be in the optimal state for analysis. This can be due to data having missing values, malformed or corrupted entries, or even just because the data format is not compatible with your analysis system (e.g., you need CSV format, but it’s in JSON). If the data is already in Splunk, there’s a good chance that it’s already been cleaned and normalized, though this isn’t guaranteed. This step may require you to do some data cleaning and normalization in order for you to begin your analysis.

In our example, the BOTSv3 data is ready for analysis, hence sparing us the need for extensive cleaning and normalization. 

## Analyze
You have gathered and cleaned up all your essential data, it is time to execute your plan and analyze the data to look for evidence that supports or refutes your hypothesis.

### **Approach 1: Sensor Health (DS0013) - Detecting High CPU Usage**
```spl
index=botsv3 sourcetype="perfmonmk:process" 
    [search index=botsv3 sourcetype="perfmonmk:process" process_cpu_used_percent>=90 Elapsed_Time>=300
    | table host, process_name, process_id 
    | dedup host, process_name, process_id]
| eval high_cpu=if(process_cpu_used_percent>=90, 1, 0)
| stats count, earliest(_time) as et, latest(_time) as lt, max(Elapsed_Time) as elapsed, min(process_cpu_used_percent), max(process_cpu_used_percent), avg(process_cpu_used_percent) as avg_cpu, sum(high_cpu) as high_cpu by host, process_name, process_id
| convert ctime(et), ctime(lt)
| eval risk_score=(high_cpu/elapsed)*100
| sort - risk_score
```

According to MITRE ATT&CK, we should consider monitoring process resource usage to determine anomalous activity associated with malicious hijacking of computer resources such as CPU or GPU resources. None of our systems have much GPU power to speak of, so we’ll concentrate on long-running processes with significant, sustained CPU usage. 

Our SPL searches for any process that lasts for at least five minutes and above and has a CPU utilization of 90% or more throughout its lifetime. This cutoff of 90% is arbitrary and should be set according to the threat hunter’s own risk appetite, their knowledge of their network environment, and any threat intelligence available. Additionally, there are summary statistics included to help the hunter with information such as minimum, maximum, and average CPU utilization, and also counts of CPU utilization spikes. We calculate a simple risk score based on the number of events showing high CPU usage over the process's lifetime. Processes with higher risk scores are more likely related to cryptomining activities.
Note that the five-minute threshold is an artifact of our simulated dataset. In a production computing environment, a cryptominer would probably run for far longer. If you reproduce this hunt with your own data, you’ll almost certainly want to extend this time. 30 minutes, or even longer, would probably be more useful.
The search returns three processes that have sustained CPU utilization across most of their runtime, all on the host BSTOLL-L. However, the Chrome process (chrome#4) immediately stands out as it has the highest risk score and the highest number of high CPU events over the second-longest elapsed time. Also, the other two results are legitimate Windows processes and are known to use large amounts of CPU from time to time. 

While high utilization from a Chrome process does not confirm the existence of cryptomining, it does suggest that if this were a cryptominer, it would most likely be browser-based. From our research, we know that families such as CoinHive, Crypto-Loot, and JSEcoin are miners that run inside browser tabs, so this Chrome process is a plausible candidate for a cryptominer. However, we can’t jump to conclusions; more investigation is required to verify that this is actually a cryptominer. 
### **Approach 2: Network Traffic (DS0029) - Detecting Cryptomining Domains**
```spl
index=botsv3 sourcetype="stream:dns" 
| lookup cryptocurrency_mining_list_large.csv domain AS query OUTPUTNEW domain AS domain_matched
| stats min(_time) as first_seen, max(_time) as last_seen, count  by host, domain_matched
| table domain_matched, host, first_seen, last_seen, count
| convert ctime(first_seen), ctime(last_seen)
| sort +first_seen
```
According to MITRE ATT&CK, we could monitor for newly constructed network connections that are sent or received by untrusted hosts, look for connections to/from strange ports, check the reputation of IPs and URLs, and monitor network data for uncommon data flows. There are many ways we might identify cryptominers, but just looking for anomalous network connections is time-consuming and not really focused on our topic, specifically. Instead, we want to find connections to known blacklisted cryptomining domains, which we’ll identify using DNS query logs.

In our research, we found some lists of domains used by CoinHive and similar JavaScript bitcoin miners. In total, we found about 4.6k domains, which we uploaded to our Splunk search head as a CSV file. The following query will identify DNS queries for any of the uploaded domains:
# Escalate Critical Findings
We found **BSTOLL-L running a cryptominer**, as evidenced by:
1. **High CPU utilization** from a Chrome process.
2. **DNS queries to Coinhive domains.**
These results show that there were DNS lookups for coinhive[.]com and five of its subdomains, all from the same computer (BSTOLL-L). This is the same system that hosted the suspicious Chrome process. The two findings support each other, and we can be reasonably sure that a cryptominer was running on BSTOLL-L.
### **Executive Summary**
> **Between 13:38:19 PM and 13:39:30 PM on Aug 20, 2018, host BSTOLL-L was observed querying Coinhive cryptocurrency mining domains. Shortly after, the ‘chrome#4’ browser (PID 3400) showed CPU utilization surging to 100% for 26 minutes, suggesting unauthorized cryptomining.**

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
