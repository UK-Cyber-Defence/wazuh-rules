# Wazuh Rules — UK Cyber Defence

Community-driven collection of custom [Wazuh](https://wazuh.com/) SIEM detection rules maintained by **UK Cyber Defence**.

## Overview

This repository provides production-ready Wazuh rule files that extend the default Wazuh ruleset with focused detection capabilities. Each rule file targets a specific threat domain and is mapped to the [MITRE ATT&CK](https://attack.mitre.org/) framework.

### Forcepoint Rules

**File:** `rules/100725-Forcepoint.xml` · **Decoder:** `decoders/Forcepoint.xml` · **Rule IDs:** 107250–107254 · **5 rules**

Detects security-relevant events from Forcepoint appliances including blocked traffic, failed authentication, system errors, and password changes. A custom decoder is included to parse Forcepoint traffic, system, and audit log formats.

#### Detection Categories

| Category | Examples |
|---|---|
| Traffic — Blocked Connections | Connection attempts blocked by Forcepoint policy |
| Audit — Failed Actions | Failed administrative or user actions |
| System — Errors | Error conditions reported by Forcepoint components |
| Audit — Password Changes | Password change events |

#### Severity Levels

| Level | Meaning | Count |
|-------|---------|-------|
| 0 | Base rule (internal grouping) | 1 |
| 13 | Very high-severity event | 2 |
| 14 | Critical event | 1 |
| 15 | Maximum-severity event | 1 |

---

### Google Workspace Audit Log Rules

**File:** `rules/108500-google_workspace.xml` · **Rule IDs:** 108500–108599 · **10 rules**

Provides base detection for Google Workspace audit events ingested via the Wazuh gcloud module or a custom integration.

#### Covered Applications

| Application | Description | Rule ID |
|---|---|---|
| *(all)* | Base Google Workspace audit event | 108500 |
| `drive` | Google Drive file operations | 108501 |
| `admin` | Admin console activities | 108510 |
| `login` | Authentication events | 108520 |
| `token` | OAuth token activities | 108530 |
| `groups` | Google Groups management | 108540 |
| `rules` | DLP and alerting rules | 108550 |
| `user_accounts` | User account management | 108560 |
| `mobile` | Mobile device management | 108570 |
| `saml` | SAML SSO events | 108580 |

#### MITRE ATT&CK Coverage

`T1078` `T1136` `T1528`

---

### Data Loss Prevention (DLP) Rules

**File:** `rules/150000-data_loss_prevention.xml` · **Rule IDs:** 150000–150163 · **114 rules**

Detects data exfiltration, unauthorised transfers, and sensitive-data exposure across Windows, Linux, and macOS endpoints, as well as cloud platforms.

#### Detection Categories

| Category | Examples |
|---|---|
| Large / Bulk File Transfers | `robocopy`, `xcopy` from sensitive directories |
| Cloud Storage Exfiltration | `rclone`, MEGA tools, AWS S3 / Azure / GCP CLI uploads |
| Email-based Exfiltration | Command-line email with attachments |
| USB / Removable Media | File copies to removable drives, new USB device registration |
| Network-based Exfiltration | HTTP uploads, FTP/SCP/SFTP transfers, netcat/socat tunnels |
| DNS-based Exfiltration | DNS tunnelling tools (`iodine`, `dnscat2`) |
| Sensitive Data Pattern Exposure | Searches for credentials, PII, and financial data |
| Database Exfiltration | Database export utilities (`mysqldump`, `pg_dump`, `bcp`) |
| Steganography / Covert Data Hiding | Steganography tools, alternate data streams |
| Print / Screenshot Data Theft | Screen capture utilities |
| Clipboard Data Theft | Clipboard access and monitoring |
| Encrypted / Encoded Exfiltration | Data encoding or encryption prior to transfer |
| Office 365 / Cloud DLP | Sensitive file downloads, external sharing, mail-flow rule changes |
| AWS DLP | S3 bucket access and policy modifications |
| Frequency-based Alerts | Repeated or high-volume exfiltration activity |

#### Supported Data Sources

- **Windows Sysmon** — Events 1, 3, 10, 11, 12, 13, 15, 22, 23
- **Linux Sysmon** — Events 1, 3, 11, 23
- **macOS Sysmon** — Events 1, 3, 11, 23
- **Office 365** audit logs
- **AWS CloudWatch** logs

#### MITRE ATT&CK Coverage

Rules are mapped to the following techniques:

`T1003` `T1003.001` `T1003.008` `T1005` `T1027.003` `T1039` `T1048` `T1048.001` `T1048.003` `T1052.001` `T1059` `T1059.002` `T1070.004` `T1071.004` `T1074.001` `T1083` `T1112` `T1113` `T1114.003` `T1115` `T1119` `T1132.001` `T1485` `T1530` `T1552.001` `T1555.001` `T1560.001` `T1562.001` `T1564.004` `T1567` `T1567.002`

## Installation

1. Copy the rule and decoder files to your Wazuh manager:

   ```bash
   sudo cp rules/*.xml /var/ossec/etc/rules/
   sudo cp decoders/*.xml /var/ossec/etc/decoders/
   ```

2. Verify the rules are valid:

   ```bash
   sudo /var/ossec/bin/wazuh-analysisd -t
   ```

3. Restart the Wazuh manager to load the new rules:

   ```bash
   sudo systemctl restart wazuh-manager
   ```

> **Note:** Rule IDs in this repository use dedicated ranges to avoid conflicts with the default Wazuh ruleset (0–100999) and other common community rules.

## Prerequisites

- [Wazuh](https://wazuh.com/) 4.x or later
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) deployed on monitored endpoints (Windows, Linux, or macOS) for Sysmon-based rules
- Office 365 and/or AWS integrations configured in Wazuh for the corresponding cloud rules
- Google Workspace audit log ingestion via the Wazuh gcloud module or custom integration for Google Workspace rules
- Forcepoint syslog forwarding configured for Forcepoint rules

## Severity Levels

Rules across all files use the following Wazuh severity levels:

| Level | Meaning | Count |
|-------|---------|-------|
| 0 | Base rule (internal grouping) | 1 |
| 3 | Low-interest event | 7 |
| 5 | Moderate event | 4 |
| 8 | Notable event | 4 |
| 10 | Suspicious activity | 39 |
| 12 | High-severity event | 39 |
| 13 | Very high-severity event | 17 |
| 14 | Critical event | 17 |
| 15 | Maximum-severity event | 1 |

## Contributing

Contributions are welcome. To add or improve rules:

1. Fork this repository.
2. Create a feature branch (`git checkout -b my-new-rules`).
3. Add or modify rule files following the existing naming and ID conventions.
4. Ensure every rule includes a `<description>`, appropriate `<group>` tags, and MITRE ATT&CK `<id>` mappings where applicable.
5. Test your rules with `wazuh-analysisd -t` before submitting.
6. Open a pull request with a clear description of the changes.

### Rule ID Ranges

To prevent conflicts, each rule file uses a dedicated ID range:

| File | ID Range |
|---|---|
| `rules/100725-Forcepoint.xml` | 107250–107254 |
| `rules/108500-google_workspace.xml` | 108500–108599 |
| `rules/150000-data_loss_prevention.xml` | 150000–150199 |

When adding a new rule file, choose an unused range and document it in this table.

## Licence

This project is open source. See the repository for licence details.

## Author

**Peter Bassill** — [UK Cyber Defence](https://cyber-defence.io) ([peter@cyber-defence.io](mailto:peter@cyber-defence.io))