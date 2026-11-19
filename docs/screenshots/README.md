# Lab Screenshots & Evidence

This folder contains evidence collected during the Windows SOC lab.

The lab uses Windows, Sysmon, and Splunk Enterprise. Screenshots document telemetry collection, event ingestion, SPL investigations, threat-intelligence enrichment, and dashboard implementation.

## Evidence Index

| Filename | Evidence | What It Demonstrates |
|---|---|---|
| `00-splunk-search-verification.png` | Splunk Search & Reporting | A successful Splunk search |
| `01-sysmon-notepad-event-redacted.txt` | Redacted Sysmon event | A sanitized Notepad process creation event (Event ID 1) |
| `02-sysmon-process-creation-splunk.png` | Splunk process investigation | Notepad process creation, parent process, and extracted XML fields |
| `03-powershell-process-creation-splunk.png` | Splunk process investigation | Windows PowerShell process creation and parent process |
| `04-powershell-query-validation.png` | SPL query validation | A tested query returning a Windows PowerShell Event ID 1 record |
| `05-network-destination-analysis.png` | Network investigation | Public IPv4 destination and port frequency analysis from Sysmon Event ID 3, grouped by executable name rather than full path |
| `06-abuseipdb-enrichment-splunk.png` | Threat-intelligence enrichment | Observed network events enriched with AbuseIPDB reputation data |
| `07-windows-soc-threat-intelligence-dashboard.png` | Splunk Dashboard Studio | Five-panel Windows endpoint and threat-intelligence dashboard |

## Evidence Notes

- Sysmon Event ID 1 represents process creation.
- Sysmon Event ID 3 represents network connections.
- Sysmon events are collected from `Microsoft-Windows-Sysmon/Operational`.
- Splunk stores the collected events in the `main` index.
- XML fields are extracted in the tested SPL queries using `rex`.
- AbuseIPDB data represents a point-in-time reputation snapshot; reputation information alone does not establish malicious activity.
- Screenshots show observed lab results, not proof of malicious activity.
- The original unredacted event is stored outside the project folder in a private evidence directory. Only the sanitized copy belongs in this repository.

## Future Evidence

Additional screenshots can be added as the lab grows. Only include evidence for configurations, investigations, and detections that have actually been tested.
