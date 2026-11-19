# Lab Execution & Validation Log

This document records the configurations, tests, observations, and validation results completed in the Windows SOC lab.

Only activities actually performed and verified are documented as completed.

---

## 1. Lab Environment

| Component | Configuration |
|---|---|
| Endpoint | Local Windows desktop |
| Telemetry | Microsoft Sysmon |
| Sysmon configuration schema | 4.91 |
| SIEM | Splunk Enterprise 9.3.14 |
| Splunk Web | http://127.0.0.1:8001 |
| Event channel | Microsoft-Windows-Sysmon/Operational |
| Splunk index | main |
| Event format | XML |
| Query language | Splunk Processing Language (SPL) |

This implementation uses the local Windows environment. No virtual machines or separate attacker systems are part of the verified work.

---

## 2. Sysmon Installation and Configuration

### Configuration

Created a minimal Sysmon configuration using schema version 4.91.

The configuration uses SHA-256 hashing and includes process creation and network connection monitoring.

### Installation

Installed Sysmon using the local configuration file.

### Validation

Verified the following:

- Sysmon service was running.
- Sysmon service startup type was Automatic.
- Sysmon Operational event channel was enabled.
- Process creation events (Event ID 1) were recorded.

### Result

**SUCCESS - Sysmon installation and process telemetry collection verified.**

---

## 3. Splunk Installation and Event Collection

Installed Splunk Enterprise 9.3.14 and verified that Splunk Web and the Splunkd service were operational.

Configured the following Windows Event Log input:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
renderXml = 1
```

Restarted Splunk and searched for collected Sysmon events.

### Validation

Confirmed that events were searchable in the main index.

Observed source:

`WinEventLog:Microsoft-Windows-Sysmon/Operational`

Observed sourcetype:

`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Result

**SUCCESS - Sysmon event ingestion into Splunk verified.**

---

## 4. Test 1 - Notepad Process Creation

### Test Activity

Launched Notepad using PowerShell:

```powershell
Start-Process notepad.exe
```

### Observed Telemetry

- Sysmon Event ID 1 recorded process creation.
- Process image and parent process information were available.
- The packaged Windows Notepad executable was observed.
- A Notepad child process was also recorded.

### Splunk Investigation

Used SPL with `rex` to extract the following fields from raw XML:

- EventID
- Image
- ParentImage
- ProcessId

The query returned two matching process creation events.

### Result

**SUCCESS - Notepad process creation investigation validated.**

Evidence: `docs/screenshots/02-sysmon-process-creation-splunk.png`

---

## 5. Test 2 - Windows PowerShell Process Creation

### Test Activity

Launched Windows PowerShell 5.1 manually and executed a harmless date command.

### Observed Telemetry

- Sysmon Event ID 1 recorded Windows PowerShell process creation.
- Parent process information was available.
- Splunk background processes were also observed and distinguished from the interactive PowerShell process.

### Splunk Investigation

Developed an SPL query to identify Windows PowerShell process creation events and extract:

- EventID
- Image
- ParentImage
- CommandLine

### Result

**SUCCESS - Windows PowerShell process creation query validated.**

The tested query returned one matching event during validation.

Evidence: `docs/screenshots/04-powershell-query-validation.png`

---

## 6. Process Baseline Investigation

Reviewed process creation events collected over a rolling 30-minute window.

Investigated frequently observed processes, including:

- splunk-optimize.exe
- splunkd.exe
- python3.9.exe
- splunk-powershell.exe
- chrome.exe
- cmd.exe
- powershell.exe

### Observations

- Splunk-generated background processes contributed significantly to process creation volume.
- splunk-optimize.exe events showed splunkd.exe as their parent.
- Several cmd.exe events executed the Windows version command `ver`, with Splunk's Python process as the parent.
- Splunk PowerShell integration activity was distinguishable from manually launched Windows PowerShell.

These observations were consistent with the associated process relationships and command lines. They were not treated as confirmed malicious activity.

### Result

**COMPLETED - Initial process baseline investigation documented.**

---

## 7. Query Validation Status

The following queries have been tested against actual lab events:

| Query | Data | Status |
|---|---|---|
| Notepad process creation | Sysmon Event ID 1 | Validated |
| Windows PowerShell process creation | Sysmon Event ID 1 | Validated |
| Network connection field extraction | Sysmon Event ID 3 | Validated |
| Network destination analysis | Sysmon Event ID 3, public IPv4 destinations | Validated |
| AbuseIPDB threat intelligence enrichment | Sysmon Event ID 3 and CSV lookup | Validated |

Both queries use `rex` to extract fields from XML-formatted events.

The validated queries are maintained in:

`detections/splunk-queries.spl`

Five validated investigation queries are maintained in detections/splunk-queries.spl.

---

## 8. Current Limitations

The following activities have not yet been completed:

- Custom Splunk alert creation and validation.
- PowerShell abuse detection testing.
- Registry modification monitoring and investigation.
- Scheduled task detection testing.
- File creation investigation.
- Detection tuning and false-positive validation.
- End-to-end incident response simulation.

These are potential future development areas, not completed lab results.

---

## 9. Evidence

Screenshots and supporting evidence are maintained in:

`docs/screenshots/`

The evidence index is documented in `docs/screenshots/README.md`.

Raw event evidence may contain local account names, paths, and other machine-specific information. Public copies must be reviewed and redacted before publication.

---

## 10. Validation Principle

A query or detection is described as validated only when it has been executed against actual collected event data and its results have been reviewed.

Reference rules, untested simulations, and planned capabilities are not presented as successful detections.



---

## 11. Splunk Dashboard Implementation

**Date:** 2026-11-18

A five-panel dashboard was created and saved successfully in Splunk Dashboard Studio.

Dashboard title: `Windows SOC - Endpoint & Threat Intelligence Overview`

The dashboard contains:

1. **Process Creation Activity** — Sysmon Event ID 1, displayed as a line chart with five-minute aggregation.
2. **Network Connection Activity** — Sysmon Event ID 3, displayed as an area chart with five-minute aggregation.
3. **Top 10 Destination IPs** — public IPv4 destination frequency analysis using extracted network event fields.
4. **AbuseIPDB Threat Intelligence Enrichment** — table of observed network events matched against the two-address AbuseIPDB CSV lookup.
5. **IP Reputation Summary** — table displaying the two IP addresses and their reputation metadata.

The dashboard was saved successfully and all five panels were visible in the saved dashboard view.

Evidence:
- `docs/screenshots/07-windows-soc-threat-intelligence-dashboard.png`

The dashboard uses actual collected Sysmon telemetry and the previously validated AbuseIPDB lookup data. Reputation information represents a point-in-time snapshot and does not independently establish malicious activity.
