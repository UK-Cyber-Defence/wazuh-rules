# Wazuh Rules — UK Cyber Defence

Community-driven collection of custom [Wazuh](https://wazuh.com/) SIEM detection rules maintained by **UK Cyber Defence**.

## Overview

This repository provides production-ready Wazuh rule files that extend the default Wazuh ruleset with focused detection capabilities. Each rule file targets a specific threat domain and is mapped to the [MITRE ATT&CK](https://attack.mitre.org/) framework.

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

1. Copy the rule file(s) to your Wazuh manager's custom rules directory:

   ```bash
   sudo cp rules/150000-data_loss_prevention.xml /var/ossec/etc/rules/
   ```

2. Verify the rules are valid:

   ```bash
   sudo /var/ossec/bin/wazuh-analysisd -t
   ```

3. Restart the Wazuh manager to load the new rules:

   ```bash
   sudo systemctl restart wazuh-manager
   ```

> **Note:** Rule IDs in this repository start at **150000** to avoid conflicts with the default Wazuh ruleset (0–100999) and other common community rules.

## Prerequisites

- [Wazuh](https://wazuh.com/) 4.x or later
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) deployed on monitored endpoints (Windows, Linux, or macOS) for Sysmon-based rules
- Office 365 and/or AWS integrations configured in Wazuh for the corresponding cloud rules

## Severity Levels

Rules use the following Wazuh severity levels:

| Level | Meaning | Count |
|-------|---------|-------|
| 3 | Low-interest event | 1 |
| 8 | Notable event | 4 |
| 10 | Suspicious activity | 39 |
| 12 | High-severity event | 39 |
| 13 | Very high-severity event | 15 |
| 14 | Critical event | 16 |

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
| `rules/150000-data_loss_prevention.xml` | 150000–150199 |

When adding a new rule file, choose an unused range and document it in this table.

## Licence

This project is open source. See the repository for licence details.

## Author

**Peter Bassill** — [UK Cyber Defence](https://cyber-defence.io) ([peter@cyber-defence.io](mailto:peter@cyber-defence.io))