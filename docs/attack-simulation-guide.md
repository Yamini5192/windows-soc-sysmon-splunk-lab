# Safe Telemetry Validation and Investigation Guide

This guide documents the harmless activities used to validate endpoint telemetry collection, network investigation, threat-intelligence enrichment, and dashboard visibility in the Windows SOC lab.

This is not an attack simulation framework. No offensive tools or destructive activity are required.

---

## 1. Lab Requirements

The current lab uses:

- Windows endpoint.
- Microsoft Sysmon.
- Windows Event Log channel: `Microsoft-Windows-Sysmon/Operational`.
- Splunk Enterprise.
- Splunk index: `main`.
- AbuseIPDB enrichment CSV lookup.

Verify that Sysmon and Splunk are running.

~~~powershell
Get-Service -Name '*Sysmon*'
Get-Service -Name Splunkd
~~~

## 2. Test Process Creation with Notepad

Launch Notepad:

~~~powershell
Start-Process notepad.exe
~~~

Verify locally:

~~~powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message
~~~

Verify in Splunk:

~~~spl
index=main earliest=-30m "Notepad.exe"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>\d+)</Data>"
| search EventID=1
| table _time EventID Image ParentImage ProcessId
~~~

Expected result: Notepad process creation records within the selected time range.

This test was performed successfully.

## 3. Test Windows PowerShell Process Creation

Launch another Windows PowerShell process:

~~~powershell
Start-Process powershell.exe
~~~

In the new window, run:

~~~powershell
Get-Date
~~~

Verify in Splunk:

~~~spl
index=main earliest=-15m "powershell.exe"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search EventID=1 Image="*\\WindowsPowerShell\\v1.0\\powershell.exe"
| table _time EventID Image ParentImage CommandLine
| sort -_time
~~~

Expected result: a Windows PowerShell process creation event.

This test was performed successfully.

## 4. Network Connection Investigation

Sysmon Event ID 3 records network connection activity.

The lab uses observed network events to investigate destination IP addresses, destination ports, and associated processes.

Run this SPL query in Splunk:

~~~spl
index=main
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>\d+)</Data>"
| search EventID=3
| stats count by DestinationIp DestinationPort
| sort -count
~~~

Expected result: destination IP and port combinations observed in collected network events.

This investigation was performed successfully.

**Evidence:** `docs/screenshots/05-network-destination-analysis.png`

## 5. AbuseIPDB Threat Intelligence Enrichment

Selected observed destination IP addresses were checked using AbuseIPDB API v2.

The reputation data is stored in:

`lookups/abuseipdb-enrichment.csv`

The CSV was uploaded to Splunk as a lookup named `abuseipdb-enrichment.csv`.

Verify enrichment in Splunk:

~~~spl
index=main earliest=-7d
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>\d+)</Data>"
| search EventID=3
| lookup abuseipdb-enrichment.csv ipAddress AS DestinationIp OUTPUT abuseConfidenceScore countryCode isp domain totalReports lastReportedAt
| where isnotnull(abuseConfidenceScore)
| table _time Image DestinationIp DestinationPort abuseConfidenceScore totalReports isp domain
| sort -_time
~~~

Expected result: network events whose destination IP addresses match entries in the uploaded lookup.

This enrichment search was validated successfully.

**Important:** Reputation information is a point-in-time snapshot. Historical reports or reputation scores alone do not establish that an observed connection is malicious.

**Evidence:** `docs/screenshots/06-abuseipdb-enrichment-splunk.png`

## 6. Splunk Dashboard Validation

A five-panel dashboard was created and saved in Splunk Dashboard Studio.

**Dashboard title:** Windows SOC - Endpoint & Threat Intelligence Overview

The dashboard contains:

1. Process Creation Activity - Sysmon Event ID 1 line chart.
2. Network Connection Activity - Sysmon Event ID 3 area chart.
3. Top 10 Destination IPs - destination IP frequency bar chart.
4. AbuseIPDB Threat Intelligence Enrichment - enriched network event table.
5. IP Reputation Summary - reputation metadata table.

Open Splunk Web:

`http://127.0.0.1:8001`

Navigate to the saved dashboard and review the panels against the available event data and lookup records.

The dashboard was saved successfully.

**Evidence:** `docs/screenshots/07-windows-soc-threat-intelligence-dashboard.png`

The dashboard provides investigation visibility. It is not a validated automated alerting or incident-response system.

## 7. Evidence Index

The following evidence is maintained in `docs/screenshots/`:

| Filename | Evidence |
|---|---|
| `00-splunk-search-verification.png` | Splunk search and ingestion verification |
| `01-sysmon-notepad-event-redacted.txt` | Redacted local Notepad event evidence |
| `02-sysmon-process-creation-splunk.png` | Notepad process investigation |
| `03-powershell-process-creation-splunk.png` | PowerShell process investigation |
| `04-powershell-query-validation.png` | PowerShell SPL query validation |
| `05-network-destination-analysis.png` | Network destination analysis |
| `06-abuseipdb-enrichment-splunk.png` | AbuseIPDB lookup enrichment |
| `07-windows-soc-threat-intelligence-dashboard.png` | Five-panel Splunk dashboard |

See `docs/screenshots/README.md` for the evidence index and descriptions.

## 8. Safety and Scope

The validation activities use ordinary Windows applications, observed network activity, and harmless commands.

The following activities are not part of the completed lab testing:

- LSASS memory dumping.
- Credential theft or extraction.
- Registry or scheduled-task persistence.
- Brute-force attacks.
- PsExec or lateral movement.
- Malicious download cradles.
- Atomic Red Team execution.
- Kali Linux attack simulations.

No automated attack-simulation scripts are included in the current project.

## 9. Validation Principle

A successful telemetry test confirms that an event was generated, collected, and investigated.

A successful enrichment test confirms that selected event data can be matched against the configured threat-intelligence lookup.

A saved dashboard confirms that the configured panels can present the available telemetry and enrichment results.

These results do not automatically prove that a security detection, alert, or automated response works.

Only describe a detection as validated after its query or alert has been tested against relevant event data and its results have been reviewed.
