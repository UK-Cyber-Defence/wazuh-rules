# Rule ID Collision Report

**Generated:** 2026-03-26  
**Repository:** UK-Cyber-Defence/wazuh-rules

---

## Summary

A total of **63 rule IDs** are duplicated across **17 collision groups** involving **21 files**.

The primary source of collisions is `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml`, which contains 864 rules spanning IDs 100100–101282. Many smaller rule files use IDs within this range, causing overlaps. A secondary source is `100750-CiscoMeraki.xml`, which uses IDs 100000–100061 that collide with several other files.

### Collision Summary by File

| File to Reassign | Colliding IDs | Collides With |
|------------------|---------------|---------------|
| `100750-CiscoMeraki.xml` | 100020–100061 (10 IDs) | 5 files (ransomware, AWS, autoruns, sigcheck) |
| `100725-Forcepoint.xml` | 100100–100140 (5 IDs) | Sysmon Event 1 |
| `100535-win_powershell_rules.xml` | 100535–100550 (12 IDs) | Sysmon Event 1 |
| `100700-Synology.xml` | 100700–100707 (8 IDs) | Sysmon Event 1 |
| `101111-Sosaso_malware.xml` | 101111–101117 (7 IDs) | Sysmon Event 1 |
| `100610-domain_stats_rules.xml` | 100610–100615 (6 IDs) | Sysmon Event 1 |
| `100630-maltrail.xml` | 100630–100634 (5 IDs) | Sysmon Event 1 |
| `100620-misp.xml` | 100620–100622 (3 IDs) | Sysmon Event 1 |
| `100623-opencti.xml` | 100623–100625 (3 IDs) | Sysmon Event 1 |
| `800100-socfortress_added.xml` | 800101 (1 ID) | 800000-malware.xml |
| `101101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT2.xml` | 101101 (1 ID) | Sysmon Event 1 |
| `100651-abuseipdb.xml` | 100651 (1 ID) | Sysmon Event 1 |
| `100660-beelzebub.xml` | 100660 (1 ID) | Sysmon Event 1 |
| `999500-InvisibleFerret.xml` | 999501 (1 ID) | 920000-soc365.xml |

---

## Collision Details

### Group 1: `100020-doge_big_balls_ransomware_rules.xml` ↔ `100750-CiscoMeraki.xml`

**2 colliding ID(s):** 100020, 100021

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100020 | `100020-doge_big_balls_ransomware_rules.xml` | 3 | A log file $(win.eventdata.targetFilename) was created to log the output of the reconnaissance activ |
| 100020 | `100750-CiscoMeraki.xml` | 34 | Firewall Denied Connection - $(srcip):$(srcport) to $(dstip):$(dstport), protocol: $(protocol) |
| 100021 | `100020-doge_big_balls_ransomware_rules.xml` | 13 | The command $(win.eventdata.commandLine) is executed for reconnaissance activities. Suspicious activ |
| 100021 | `100750-CiscoMeraki.xml` | 43 | VPN Firewall Denied Connection - $(srcip) to $(dstip) |

### Group 2: `100030-amazon_aws_cloudwatch.xml` ↔ `100750-CiscoMeraki.xml`

**4 colliding ID(s):** 100030, 100031, 100040, 100041

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100030 | `100030-amazon_aws_cloudwatch.xml` | 3 | Wazuh AWS Integration |
| 100030 | `100750-CiscoMeraki.xml` | 52 | VPN connection established from $(srcip) |
| 100031 | `100030-amazon_aws_cloudwatch.xml` | 10 | AWS WAF Event - WAF Action $(action) By Rule Type: $(terminatingRuleType) |
| 100031 | `100750-CiscoMeraki.xml` | 59 | VPN login failed from $(srcip) |
| 100040 | `100030-amazon_aws_cloudwatch.xml` | 61 | AWS WAF - Sensitive path probe detected. |
| 100040 | `100750-CiscoMeraki.xml` | 67 | Blocked content access attempt - Category: $(mercategory), URL: $(url) |
| 100041 | `100030-amazon_aws_cloudwatch.xml` | 69 | AWS WAF - Unusual HTTP method observed. |
| 100041 | `100750-CiscoMeraki.xml` | 75 | Accessed risky site - $(url) |

### Group 3: `100050-win_autoruns_rules.xml` ↔ `100750-CiscoMeraki.xml`

**1 colliding ID(s):** 100050

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100050 | `100050-win_autoruns_rules.xml` | 2 | Windows Autoruns - VirusTotal Hit |
| 100050 | `100750-CiscoMeraki.xml` | 84 | Client $(mersubevent): $(srcip) |

### Group 4: `100060-win_sigcheck_rules.xml` ↔ `100750-CiscoMeraki.xml`

**2 colliding ID(s):** 100060, 100061

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100060 | `100060-win_sigcheck_rules.xml` | 2 | Windows Sigcheck - VirusTotal Hit |
| 100060 | `100750-CiscoMeraki.xml` | 93 | New network flow started - $(srcip):$(srcport) to $(dstip):$(dstport) |
| 100061 | `100060-win_sigcheck_rules.xml` | 13 | Windows Sigcheck - VirusTotal Hit Above 10 Matches |
| 100061 | `100750-CiscoMeraki.xml` | 100 | Network flow ended - $(srcip):$(srcport) to $(dstip):$(dstport) |

### Group 5: `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` ↔ `100725-Forcepoint.xml`

**5 colliding ID(s):** 100100, 100110, 100120, 100130, 100140

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100100 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2 | Sysmon - Event 1: Process creation $(win.eventdata.description) |
| 100100 | `100725-Forcepoint.xml` | 4 | Forcepoint log detected |
| 100110 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 101 | rundll32.exe |
| 100110 | `100725-Forcepoint.xml` | 10 | Forcepoint Traffic: Blocked connection attempt |
| 100120 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 201 | Security Software Discovery |
| 100120 | `100725-Forcepoint.xml` | 18 | Forcepoint Audit: Failed action |
| 100130 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 301 | Compile After Delivery |
| 100130 | `100725-Forcepoint.xml` | 26 | Forcepoint System: Error reported |
| 100140 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 401 | Inhibit System Recovery |
| 100140 | `100725-Forcepoint.xml` | 34 | Forcepoint Audit: Password change detected |

### Group 6: `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` ↔ `100535-win_powershell_rules.xml`

**12 colliding ID(s):** 100535, 100536, 100537, 100538, 100539, 100540, 100541, 100542, 100543, 100544, 100545, 100550

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100535 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1212 | System Network Configuration Discovery |
| 100535 | `100535-win_powershell_rules.xml` | 3 | Powershell Information EventLog |
| 100536 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1223 | Process Discovery |
| 100536 | `100535-win_powershell_rules.xml` | 13 | Powershell Warning EventLog |
| 100537 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1234 | System Network Connections Discovery |
| 100537 | `100535-win_powershell_rules.xml` | 24 | Powershell Error EventLog |
| 100538 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1245 | Remote System Discovery |
| 100538 | `100535-win_powershell_rules.xml` | 34 | Powershell Critical EventLog |
| 100539 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1256 | File and Directory Discovery |
| 100539 | `100535-win_powershell_rules.xml` | 44 | Short-time multiple Windows Powershell error events |
| 100540 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1267 | Access Token Manipulation |
| 100540 | `100535-win_powershell_rules.xml` | 53 | Short-time multiple Windows Powershell critical events |
| 100541 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1278 | Modify Registry |
| 100541 | `100535-win_powershell_rules.xml` | 62 | Powershell script $(win.eventdata.scriptBlockText) Executed |
| 100542 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1289 | Security Software Discovery |
| 100542 | `100535-win_powershell_rules.xml` | 71 | Disregard Powershell Text |
| 100543 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1300 | Account Discovery |
| 100543 | `100535-win_powershell_rules.xml` | 79 | Malicious Powershell Command $(win.eventdata.scriptBlockText) Executed |
| 100544 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1311 | Indicator Removal on Host |
| 100544 | `100535-win_powershell_rules.xml` | 88 | Disregard Powershell Prompt Text |
| 100545 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1322 | Scheduled Task |
| 100545 | `100535-win_powershell_rules.xml` | 96 | Disregard Powershell Prompt Text |
| 100550 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 1377 | PowerShell |
| 100550 | `100535-win_powershell_rules.xml` | 104 | Powershell Information EventLog |

### Group 7: `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` ↔ `100610-domain_stats_rules.xml`

**6 colliding ID(s):** 100610, 100611, 100612, 100613, 100614, 100615

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100610 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2037 | Exchange Transport Agent Installation |
| 100610 | `100610-domain_stats_rules.xml` | 2 | DNS Stats |
| 100611 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2048 | Tor Proxy Usage |
| 100611 | `100610-domain_stats_rules.xml` | 8 | DNS Stats - Low Frequency Score in Queried Domain |
| 100612 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2059 | Psiphon Proxy |
| 100612 | `100610-domain_stats_rules.xml` | 19 | DNS Stats - Domain Queried for the first time |
| 100613 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2070 | PowerShell Compress-Archive |
| 100613 | `100610-domain_stats_rules.xml` | 29 | DNS Stats - DNS Query to Recently Created Domain |
| 100614 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2081 | Hashcat Password Cracking |
| 100614 | `100610-domain_stats_rules.xml` | 39 | DNS Stats - Error connecting to API |
| 100615 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2092 | Steal Web Session Cookie |
| 100615 | `100610-domain_stats_rules.xml` | 46 | DNS Stats - RDAP Error Querying Domain |

### Group 8: `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` ↔ `100620-misp.xml`

**3 colliding ID(s):** 100620, 100621, 100622

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100620 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2147 | PowerShell Search Removable Media |
| 100620 | `100620-misp.xml` | 2 | MISPs |
| 100621 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2158 | PowerShell Compress-Archive ZIP Staging |
| 100621 | `100620-misp.xml` | 8 | MISP - Error connecting to API |
| 100622 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2169 | PowerShell Download discovery.bat |
| 100622 | `100620-misp.xml` | 15 | MISP - IoC found in Threat Intel - Category: $(misp.category), Attribute: $(misp.value) |

### Group 9: `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` ↔ `100623-opencti.xml`

**3 colliding ID(s):** 100623, 100624, 100625

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100623 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2180 | PowerShell Email Collection Get-Inbox.ps1 |
| 100623 | `100623-opencti.xml` | 2 | OpenCTI |
| 100624 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2191 | PowerShell Email Collection Get-Inbox.ps1 |
| 100624 | `100623-opencti.xml` | 8 | OpenCTI - Error connecting to API |
| 100625 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2202 | CMD copy Admin Share |
| 100625 | `100623-opencti.xml` | 15 | OpenCTI - IoC found in Threat Intel - $(opencti.observable_value) |

### Group 10: `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` ↔ `100630-maltrail.xml`

**5 colliding ID(s):** 100630, 100631, 100632, 100633, 100634

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100630 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2257 | PDQ Deploy Console Execution |
| 100630 | `100630-maltrail.xml` | 10 | Maltrail messages grouped. |
| 100631 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2268 | Radmin Viewer Execution |
| 100631 | `100630-maltrail.xml` | 15 | Low critical Maltrail event triggered |
| 100632 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2279 | technique_name=NetUse QUIC |
| 100632 | `100630-maltrail.xml` | 21 | Medium critical Maltrail event triggered |
| 100633 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2290 | PowerSharpPack Sharpweb |
| 100633 | `100630-maltrail.xml` | 27 | High critical Maltrail event triggered |
| 100634 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2301 | Esentutl Chrome Login Dump |
| 100634 | `100630-maltrail.xml` | 33 | Too many critical Maltrail events triggered, possible infection detected. |

### Group 11: `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` ↔ `100651-abuseipdb.xml`

**1 colliding ID(s):** 100651

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100651 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2488 | Clear Event Logs via wevtutil |
| 100651 | `100651-abuseipdb.xml` | 2 | IP with $(abuseipdb.abuse_confidence_score)% confidence of abuse was connected to. |

### Group 12: `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` ↔ `100660-beelzebub.xml`

**1 colliding ID(s):** 100660

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100660 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 2587 | JuicyPotato Execution |
| 100660 | `100660-beelzebub.xml` | 2 | Honeypot SSH Terminal Session Interaction. |

### Group 13: `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` ↔ `100700-Synology.xml`

**8 colliding ID(s):** 100700, 100701, 100702, 100703, 100704, 100705, 100706, 100707

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 100700 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 3027 | PtH via Mimikatz |
| 100700 | `100700-Synology.xml` | 3 | Synology NAS log detected |
| 100701 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 3038 | Remove VIB via plink.exe |
| 100701 | `100700-Synology.xml` | 9 | Synology NAS: Login succeeded |
| 100702 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 3049 | Install VIB via plink.exe |
| 100702 | `100700-Synology.xml` | 17 | Synology NAS: Login failed |
| 100703 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 3060 | Load Component via pscp.exe |
| 100703 | `100700-Synology.xml` | 25 | Synology NAS: System startup detected |
| 100704 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 3071 | Suspicious LNK File Execution |
| 100704 | `100700-Synology.xml` | 32 | Synology NAS: Volume error detected |
| 100705 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 3082 | Office spawning WScript |
| 100705 | `100700-Synology.xml` | 40 | Synology NAS: Drive failure |
| 100706 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 3093 | Excel launching CMD |
| 100706 | `100700-Synology.xml` | 48 | Synology NAS: Firmware upgrade completed |
| 100707 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 3104 | Word launching PowerShell |
| 100707 | `100700-Synology.xml` | 56 | Synology NAS: Multiple login failures followed by a success |

### Group 14: `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` ↔ `101101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT2.xml`

**1 colliding ID(s):** 101101

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 101101 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 7438 | PowerShell AddToHistoryHandler override |
| 101101 | `101101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT2.xml` | 3 | Sysmon - Event 2: A process changed a file creation time by $(win.eventdata.image) |

### Group 15: `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` ↔ `101111-Sosaso_malware.xml`

**7 colliding ID(s):** 101111, 101112, 101113, 101114, 101115, 101116, 101117

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 101111 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 7548 | Use of Phant0m Script |
| 101111 | `101111-Sosaso_malware.xml` | 4 | Suspicious execution: mshta.exe running electronica-2024.pdf detected.Potential Sosano malware activ |
| 101112 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 7559 | Stop EventLog Service |
| 101112 | `101111-Sosaso_malware.xml` | 15 | The process $(win.eventdata.image) loads file $(win.eventdata.targetFilename) associated with Sosano |
| 101113 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 7570 | Disable EventLog Service |
| 101113 | `101111-Sosaso_malware.xml` | 23 | The process $(win.eventdata.image) looks for file $(win.eventdata.targetFilename). Activity associat |
| 101114 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 7581 | Disable Logging with wevtutil |
| 101114 | `101111-Sosaso_malware.xml` | 31 | The process $(win.eventdata.image) looks for file $(win.eventdata.targetFilename). Activity associat |
| 101115 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 7592 | Disable Logging Tools |
| 101115 | `101111-Sosaso_malware.xml` | 39 | The process $(win.eventdata.image) loads $(win.eventdata.targetFilename). Activity associated with S |
| 101116 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 7603 | PowerShell Add Firewall Rule |
| 101116 | `101111-Sosaso_malware.xml` | 46 | The process $(win.eventdata.image) extracts file $(win.eventdata.targetFilename). Activity associate |
| 101117 | `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` | 7614 | netsh add firewall rule |
| 101117 | `101111-Sosaso_malware.xml` | 54 | Sosano backdoor malware added URL file $(win.eventdata.targetObject) to registry runkey to be execut |

### Group 16: `800000-malware.xml` ↔ `800100-socfortress_added.xml`

**1 colliding ID(s):** 800101

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 800101 | `800000-malware.xml` | 127 | Changes were made to the registry settings on the $(win.system.computer) endpoint. Blackbit ransomwa |
| 800101 | `800100-socfortress_added.xml` | 9 | ETW Tampering Technique was ran. |

### Group 17: `920000-soc365.xml` ↔ `999500-InvisibleFerret.xml`

**1 colliding ID(s):** 999501

| Rule ID | File | Line | Description |
|---------|------|------|-------------|
| 999501 | `920000-soc365.xml` | 1528 | Possible malware detected - 2 or more files being encrypted. Active Response Quarentined |
| 999501 | `999500-InvisibleFerret.xml` | 3 | Suspicious file created: "$(eventdata.targetFilename)"- Possible InvisibleFerret malware activity de |

---

## Suggested Rule ID Changes

### Approach

- **Keep** the large `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml` (864 rules, IDs 100100–101282) unchanged
- **Keep** all other non-colliding files unchanged
- **Reassign** the 14 smaller colliding files to free ID ranges
- New ranges are placed in the gap between 101283 and 102100 (or other documented free ranges)

### Detailed Reassignment Plan

#### `100750-CiscoMeraki.xml`

- **Current IDs:** 100000–100061
- **Suggested new range:** 102500–102512
- **Reason:** Filename implies range starting at 100750, but that falls within the Sysmon Event 1 range (100100–101282). Current IDs (100000–100061) collide with 5 other files. Suggested range 102500+ is in a clear gap (102140–102502).

| Current ID | New ID |
|------------|--------|
| 100000 | 102500 |
| 100001 | 102501 |
| 100010 | 102502 |
| 100011 | 102503 |
| 100020 | 102504 |
| 100021 | 102505 |
| 100030 | 102506 |
| 100031 | 102507 |
| 100040 | 102508 |
| 100041 | 102509 |
| 100050 | 102510 |
| 100060 | 102511 |
| 100061 | 102512 |

#### `100725-Forcepoint.xml`

- **Current IDs:** 100100–100140
- **Suggested new range:** 107250–107254
- **Reason:** README already documents the intended range as 107250–107254. Current IDs collide with Sysmon Event 1. Range 107250+ is in a clear gap (106132–107999).

| Current ID | New ID |
|------------|--------|
| 100100 | 107250 |
| 100110 | 107251 |
| 100120 | 107252 |
| 100130 | 107253 |
| 100140 | 107254 |

#### `100535-win_powershell_rules.xml`

- **Current IDs:** 100535–100550
- **Suggested new range:** 101300–101311
- **Reason:** Current IDs fall within Sysmon Event 1 range. Move to 101300+ (first free block after Sysmon Event 1 max of 101282).

| Current ID | New ID |
|------------|--------|
| 100535 | 101300 |
| 100536 | 101301 |
| 100537 | 101302 |
| 100538 | 101303 |
| 100539 | 101304 |
| 100540 | 101305 |
| 100541 | 101306 |
| 100542 | 101307 |
| 100543 | 101308 |
| 100544 | 101309 |
| 100545 | 101310 |
| 100550 | 101311 |

#### `100610-domain_stats_rules.xml`

- **Current IDs:** 100610–100615
- **Suggested new range:** 101320–101325
- **Reason:** Current IDs fall within Sysmon Event 1 range.

| Current ID | New ID |
|------------|--------|
| 100610 | 101320 |
| 100611 | 101321 |
| 100612 | 101322 |
| 100613 | 101323 |
| 100614 | 101324 |
| 100615 | 101325 |

#### `100620-misp.xml`

- **Current IDs:** 100620–100622
- **Suggested new range:** 101330–101332
- **Reason:** Current IDs fall within Sysmon Event 1 range.

| Current ID | New ID |
|------------|--------|
| 100620 | 101330 |
| 100621 | 101331 |
| 100622 | 101332 |

#### `100623-opencti.xml`

- **Current IDs:** 100623–100625
- **Suggested new range:** 101335–101337
- **Reason:** Current IDs fall within Sysmon Event 1 range.

| Current ID | New ID |
|------------|--------|
| 100623 | 101335 |
| 100624 | 101336 |
| 100625 | 101337 |

#### `100630-maltrail.xml`

- **Current IDs:** 100629–100634
- **Suggested new range:** 101340–101344
- **Reason:** Current IDs fall within Sysmon Event 1 range.

| Current ID | New ID |
|------------|--------|
| 100630 | 101340 |
| 100631 | 101341 |
| 100632 | 101342 |
| 100633 | 101343 |
| 100634 | 101344 |

#### `100651-abuseipdb.xml`

- **Current IDs:** 100651
- **Suggested new range:** 101350–101350
- **Reason:** Current ID falls within Sysmon Event 1 range.

| Current ID | New ID |
|------------|--------|
| 100651 | 101350 |

#### `100660-beelzebub.xml`

- **Current IDs:** 100660
- **Suggested new range:** 101355–101355
- **Reason:** Current ID falls within Sysmon Event 1 range.

| Current ID | New ID |
|------------|--------|
| 100660 | 101355 |

#### `100700-Synology.xml`

- **Current IDs:** 100700–100707
- **Suggested new range:** 101360–101367
- **Reason:** Current IDs fall within Sysmon Event 1 range.

| Current ID | New ID |
|------------|--------|
| 100700 | 101360 |
| 100701 | 101361 |
| 100702 | 101362 |
| 100703 | 101363 |
| 100704 | 101364 |
| 100705 | 101365 |
| 100706 | 101366 |
| 100707 | 101367 |

#### `101101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT2.xml`

- **Current IDs:** 101101
- **Suggested new range:** 101370–101370
- **Reason:** Current ID falls within Sysmon Event 1 range (100100–101282).

| Current ID | New ID |
|------------|--------|
| 101101 | 101370 |

#### `101111-Sosaso_malware.xml`

- **Current IDs:** 101111–101117
- **Suggested new range:** 101375–101381
- **Reason:** Current IDs fall within Sysmon Event 1 range.

| Current ID | New ID |
|------------|--------|
| 101111 | 101375 |
| 101112 | 101376 |
| 101113 | 101377 |
| 101114 | 101378 |
| 101115 | 101379 |
| 101116 | 101380 |
| 101117 | 101381 |

#### `800100-socfortress_added.xml`

- **Current IDs:** 800100–800101
- **Suggested new range:** 800114–800115
- **Reason:** ID 800101 collides with 800000-malware.xml. Move to 800114+ (first free after malware rules end at 800113).

| Current ID | New ID |
|------------|--------|
| 800100 | 800114 |
| 800101 | 800115 |

#### `999500-InvisibleFerret.xml`

- **Current IDs:** 999501–999505
- **Suggested new range:** 999506–999510
- **Reason:** ID 999501 collides with 920000-soc365.xml. Move to 999506+ (next free block).

| Current ID | New ID |
|------------|--------|
| 999501 | 999506 |
| 999502 | 999507 |
| 999503 | 999508 |
| 999504 | 999509 |
| 999505 | 999510 |

---

## Cross-Reference Analysis (`<if_sid>` Dependencies)

When changing rule IDs, any `<if_sid>` references to those IDs must also be updated. The following internal references within files being moved need updating:

**`100535-win_powershell_rules.xml`:**

| Line | Current `<if_sid>` | Update To |
|------|-------------------|-----------|
| 72 | 100541 | 101306 |
| 80 | 100541 | 101306 |
| 89 | 100541 | 101306 |
| 97 | 100541 | 101306 |
| 105 | 100535 | 101300 |

**`100610-domain_stats_rules.xml`:**

| Line | Current `<if_sid>` | Update To |
|------|-------------------|-----------|
| 9 | 100610 | 101320 |
| 20 | 100610 | 101320 |
| 30 | 100610 | 101320 |
| 40 | 100610 | 101320 |
| 47 | 100610 | 101320 |

**`100620-misp.xml`:**

| Line | Current `<if_sid>` | Update To |
|------|-------------------|-----------|
| 9 | 100620 | 101330 |
| 16 | 100620 | 101330 |

**`100623-opencti.xml`:**

| Line | Current `<if_sid>` | Update To |
|------|-------------------|-----------|
| 9 | 100623 | 101335 |
| 16 | 100623 | 101335 |

**`100630-maltrail.xml`:**

| Line | Current `<if_sid>` | Update To |
|------|-------------------|-----------|
| 16 | 100630 | 101340 |
| 22 | 100630 | 101340 |
| 28 | 100630 | 101340 |

**`100700-Synology.xml`:**

| Line | Current `<if_sid>` | Update To |
|------|-------------------|-----------|
| 10 | 100700 | 101360 |
| 18 | 100700 | 101360 |
| 26 | 100700 | 101360 |
| 33 | 100700 | 101360 |
| 41 | 100700 | 101360 |
| 49 | 100700 | 101360 |

**`100725-Forcepoint.xml`:**

| Line | Current `<if_sid>` | Update To |
|------|-------------------|-----------|
| 11 | 100100 | 107250 |
| 19 | 100100 | 107250 |
| 27 | 100100 | 107250 |
| 35 | 100100 | 107250 |

> **Note:** The colliding IDs also exist in the files that are being kept (e.g., `100100-MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml`). The `<if_sid>` references in those kept files are referencing their own rules and do **not** need to change.

---

## Implementation Priority

| Priority | File | Colliding IDs | Impact |
|----------|------|---------------|--------|
| 1 | `100750-CiscoMeraki.xml` | 10 | Collides with 5 different files |
| 2 | `100535-win_powershell_rules.xml` | 12 | All IDs collide with Sysmon Event 1 |
| 3 | `100700-Synology.xml` | 8 | All IDs collide with Sysmon Event 1 |
| 4 | `101111-Sosaso_malware.xml` | 7 | All IDs collide with Sysmon Event 1 |
| 5 | `100610-domain_stats_rules.xml` | 6 | All IDs collide with Sysmon Event 1 |
| 6 | `100725-Forcepoint.xml` | 5 | README already documents correct range |
| 7 | `100630-maltrail.xml` | 5 | All IDs collide with Sysmon Event 1 |
| 8 | `100620-misp.xml` | 3 | All IDs collide with Sysmon Event 1 |
| 9 | `100623-opencti.xml` | 3 | All IDs collide with Sysmon Event 1 |
| 10 | `800100-socfortress_added.xml` | 1 | Collides with malware detection rules |
| 11 | `101101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT2.xml` | 1 | Collides with Sysmon Event 1 |
| 12 | `100651-abuseipdb.xml` | 1 | Collides with Sysmon Event 1 |
| 13 | `100660-beelzebub.xml` | 1 | Collides with Sysmon Event 1 |
| 14 | `999500-InvisibleFerret.xml` | 1 | Collides with SOC365 rules |

---

## Implementation Notes

### Steps to Apply Changes

1. For each file being reassigned, update all `<rule id="...">` attributes to the new IDs
2. Update any `<if_sid>` references within the same file (see Cross-Reference Analysis above)
3. Consider renaming rule files to match new starting IDs (e.g., `100750-CiscoMeraki.xml` → `102500-CiscoMeraki.xml`)
4. Update the Rule ID Range Registry in `README.md`
5. Verify with `sudo /var/ossec/bin/wazuh-analysisd -t`

### External Dependencies to Check

- **`ossec.conf` active response rules** may reference specific rule IDs
- **SIEM dashboards and alerting rules** may filter on specific rule IDs
- **Wazuh API queries** filtering by rule ID will need updating
- **Documentation and runbooks** referencing specific rule IDs should be updated

### Suggested File Renames

| Current Filename | Suggested Filename |
|------------------|--------------------|
| `100750-CiscoMeraki.xml` | `102500-CiscoMeraki.xml` |
| `100725-Forcepoint.xml` | `107250-Forcepoint.xml` |
| `100535-win_powershell_rules.xml` | `101300-win_powershell_rules.xml` |
| `100610-domain_stats_rules.xml` | `101320-domain_stats_rules.xml` |
| `100620-misp.xml` | `101330-misp.xml` |
| `100623-opencti.xml` | `101335-opencti.xml` |
| `100630-maltrail.xml` | `101340-maltrail.xml` |
| `100651-abuseipdb.xml` | `101350-abuseipdb.xml` |
| `100660-beelzebub.xml` | `101355-beelzebub.xml` |
| `100700-Synology.xml` | `101360-Synology.xml` |
| `101101-MITRE_TECHNIQUES_FROM_SYSMON_EVENT2.xml` | `101370-MITRE_TECHNIQUES_FROM_SYSMON_EVENT2.xml` |
| `101111-Sosaso_malware.xml` | `101375-Sosaso_malware.xml` |
| `800100-socfortress_added.xml` | `800114-socfortress_added.xml` |
| `999500-InvisibleFerret.xml` | `999506-InvisibleFerret.xml` |

