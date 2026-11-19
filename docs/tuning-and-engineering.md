# Detection Engineering & Investigation Notes

This document records the investigation and query-development decisions made during the Windows SOC lab.

The lab documents endpoint telemetry analysis, SPL field extraction, process and network investigations, threat-intelligence enrichment, and dashboard development. The emphasis is on evidence-backed investigation and distinguishing observed activity from confirmed malicious behavior.

Only verified observations and completed work are documented as results.

---

## 1. Investigation Approach

Detection engineering requires more than matching a process name or command-line string.

An analyst should examine:

- Process image and executable path.
- Parent process image.
- Command line.
- Available process context and execution details.
- Event timestamp.
- Related process activity.
- Whether the observed behavior is expected in the environment.

A process should not be classified as malicious based on its name alone.

The current lab uses Sysmon Event ID 1 (Process Create) and Event ID 3 (Network Connect) as its primary investigation sources.

---

## 2. SPL Field Extraction from XML Events

### Initial Challenge

Sysmon events were successfully collected in Splunk, but the expected fields were not extracted using the initial `spath` attempt.

The raw events were XML-formatted Windows Event Log records.

### Investigation and Correction

Used Splunk `rex` commands to extract fields directly from the raw XML.

Example:

```spl
index=main earliest=-30m "Notepad.exe"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>\d+)</Data>"
| search EventID=1
| table _time EventID Image ParentImage ProcessId
```

### Result

The query returned two Notepad process creation events during validation.

This confirmed that the required fields could be extracted from the collected XML event data.

---

## 3. Process Baseline Investigation

Reviewed Sysmon process creation events over a rolling 30-minute window.

Used SPL statistics to identify frequently observed process images and parent processes.

### Frequently Observed Processes

The investigation identified activity from:

- splunk-optimize.exe
- splunkd.exe
- python3.9.exe
- splunk-powershell.exe
- chrome.exe
- cmd.exe
- powershell.exe

### Observation: Splunk Background Processes

A large number of process creation events were associated with `splunk-optimize.exe`.

Further investigation showed:

- Its parent process was `splunkd.exe`.
- Its command lines referenced Splunk internal database locations.
- The observed arguments were consistent with Splunk bucket optimization activity.

This provided contextual evidence that the high event volume was associated with Splunk's own background operations.

The activity was not classified as malicious based on the evidence reviewed.

---

## 4. Parent Process Investigation

Parent-child process relationships were examined to understand how processes were launched.

### Observation: cmd.exe

Several `cmd.exe` events were investigated.

One recurring command was:

```text
cmd.exe /c "ver"
```

The parent process was:

`C:\Program Files\Splunk\bin\python3.9.exe`

The `ver` command displays the Windows version. The observed command and parent relationship were consistent with background Splunk activity.

A separate WSL-related command was also observed with `wslhost.exe` as its parent.

These observations demonstrate why command-line and parent-process context are important during triage.

---

## 5. PowerShell Process Investigation

The lab produced process creation events for both Splunk's PowerShell integration and Windows PowerShell.

### Distinguishing the Processes

Splunk integration activity included:

`C:\Program Files\Splunk\bin\splunk-powershell.exe`

Interactive Windows PowerShell activity included:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

The parent process and executable path helped distinguish these activities.

A harmless manual PowerShell launch was used to validate process creation telemetry.

### Result

A tested SPL query successfully returned a Windows PowerShell Event ID 1 event during validation.

This confirms process telemetry and query functionality. It does not represent a PowerShell abuse detection.

---

## 6. Investigation and Query Validation Summary

| Investigation | Technique | Result |
|---|---|---|
| Notepad process creation | Sysmon Event ID 1 | Query validated |
| Windows PowerShell process creation | Sysmon Event ID 1 | Query validated |
| Splunk process baseline | Process image statistics | Investigation completed |
| Parent process analysis | ParentImage statistics | Investigation completed |
| cmd.exe command-line review | CommandLine extraction | Investigation completed |
| Splunk PowerShell activity | Executable and parent review | Investigation completed |

The validated process investigation queries are maintained in:

`detections/splunk-queries.spl`

---

## 7. Network Connection Investigation (Sysmon Event ID 3)

### Telemetry Configuration

Updated the Sysmon configuration to collect network connection events using:

```xml
<NetworkConnect onmatch="exclude" />
```

Applied the configuration successfully and verified that Sysmon recorded Event ID 3 events.

### Network Telemetry Validation

Generated harmless outbound HTTPS activity using:

- `Test-NetConnection` to `www.microsoft.com` on TCP port 443.
- `Invoke-WebRequest` to `https://example.com` using an HTTP HEAD request.

The request to example.com returned HTTP 200 OK.

Sysmon recorded outbound TCP connections initiated by Windows PowerShell, including destination port 443.

### Splunk Ingestion and Field Extraction

Confirmed that Splunk ingested Sysmon Event ID 3 records into the `main` index.

Successfully extracted the following fields from XML events using `rex`:

- `Image`
- `Protocol`
- `SourceIp`
- `DestinationIp`
- `DestinationPort`

A network activity query returned 545 Event ID 3 records in the captured search window.

### Network Baseline Investigation

Grouped network events by process image, destination IP, and destination port.

Observed activity included:

- Splunk processes communicating with localhost on port 8089.
- Chrome DNS-related connections to the local gateway on port 53.
- External HTTPS connections on port 443.
- LLMNR-related traffic on port 5355.
- mDNS-related traffic on port 5353.

These are observations from this endpoint, not universal indicators of benign or malicious behavior.

### Process-to-Network Correlation

Investigated network events initially attributed to `<unknown process>`.

Correlated network events containing PID `43692` with Sysmon Event ID 1 process creation records.

The process creation records identified:

- Executable: Splunk's bundled `python3.9.exe`
- Parent: `splunkd.exe`
- Command lines referencing `quarantine_files.py` and `instrumentation.py`

The same numeric PID appeared in separate process lifetimes. Both process creation records were consistent with Splunk internal application activity. The network events involved communication with `127.0.0.1:8089`.

Because Windows can reuse process IDs, ProcessGuid-based correlation would provide stronger confirmation of the exact process lifetime associated with each network event.

No evidence of malicious behavior was established in this investigation.

### Limitations

- Network telemetry has been validated, but no custom network detection alert has been implemented.
- AbuseIPDB reputation enrichment has been implemented and validated against observed network events.
- Two observed public IPv4 addresses have been assessed using AbuseIPDB; results are point-in-time reputation data.
- IPv4 and IPv6 events are both present; analysis must account for both.
- Some events have incomplete process attribution and require correlation with other telemetry.

---

## 8. Future Engineering Work

Potential future development includes:

1. Investigate registry activity and expand Sysmon telemetry coverage.
2. Develop detection hypotheses based on observed process and network telemetry.
3. Write SPL detection logic using the actual collected event fields.
4. Develop and validate network and process detection queries.
5. Evaluate automated refresh of threat-intelligence data and additional reputation sources.
6. Validate detections using harmless, controlled test activity.
7. Review benign matches and tune detection conditions.
8. Create Splunk alerts only after query validation.
9. Document test evidence, false positives, and limitations for each detection.

These are planned activities, not completed results.
## 9. Engineering Principle

A reliable detection process requires evidence, context, and validation.

This lab follows three principles:

- Do not label a process malicious based only on its name.
- Investigate parent processes and command lines before drawing conclusions.
- Describe a query or detection as validated only after executing it against actual event data and reviewing its results.

The goal is to build repeatable investigations and evidence-backed detections rather than claim success from untested rules.

---

## 10. Threat Intelligence Enrichment (AbuseIPDB)

### Objective

Enrich observed Sysmon network connection events with external IP reputation information to support investigation and triage.

### Threat Intelligence Source

Used the AbuseIPDB API v2 to check two public IPv4 addresses observed in Sysmon Event ID 3 telemetry.

The lookups used a 90-day reporting window.

### Reproducible API Request

The following is a reusable example, not a record of the exact command used during the original lookup. Set `ABUSEIPDB_KEY` in the current PowerShell session before running it; do not place the key in project files.

```powershell
$headers = @{
    Key = $env:ABUSEIPDB_KEY
    Accept = 'application/json'
}

 = '161.69.236.107'
$uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90"
Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
```

Repeat with the second assessed address, `172.64.148.235`. The original lookups were performed on 2026-11-16.

The API returned the following results:

| Field | 161.69.236.107 | 172.64.148.235 |
|---|---|---|
| Abuse confidence score | 0 | 0 |
| Country code | US | US |
| ISP | McAfee, LLC | Cloudflare, Inc. |
| Domain | mcafee.com | cloudflare.com |
| Total reports | 0 | 14 |
| Last reported | Not available | 2026-11-11 |

The results were captured on 2026-11-16.

### CSV Lookup Integration

Stored the returned reputation information in:

`lookups/abuseipdb-enrichment.csv`

The CSV contains the IP address, lookup date, confidence score, country, ISP, domain, report count, last reported timestamp, and observed event context.

The API key was not stored in the project lookup file.

Uploaded the CSV to Splunk and verified that its records could be read using `inputlookup`.

### Splunk Enrichment and Validation

Used Splunk's `lookup` command to match the event's `DestinationIp` field against the CSV's `ipAddress` field.

The enrichment query extracted Sysmon Event ID 3 fields and added:

- Abuse confidence score
- Country code
- ISP
- Domain
- Total report count
- Last reported timestamp

Validation returned nine matching network events across the two IP addresses.

The results included HTTPS connections on TCP port 443 and events on destination port 137.

**Evidence:** `docs/screenshots/06-abuseipdb-enrichment-splunk.png`

**Query:** Section 5 of `detections/splunk-queries.spl`.

### Investigation Interpretation and Limitations

- Both addresses returned an Abuse Confidence Score of 0 at lookup time.
- Cloudflare's 14 historical reports do not establish that the observed Chrome connection was malicious.
- Reputation data describes an IP address, not necessarily the intent or safety of a particular connection.
- Shared hosting, CDN, and security-service infrastructure can serve many unrelated customers and applications.
- The CSV is a point-in-time snapshot and does not update automatically.
- The observed events and enrichment results do not establish a confirmed security incident or malicious activity.

The enrichment is an investigation aid, not a standalone detection or alert.




---

## 11. Splunk Dashboard Studio Implementation

### Dashboard

**Title:** Windows SOC - Endpoint & Threat Intelligence Overview

**Implementation date:** 2026-11-18

Created and saved a five-panel dashboard in Splunk Dashboard Studio using the collected Sysmon telemetry and AbuseIPDB lookup data.

### Dashboard Panels

| Panel | Visualization | Data Source |
|---|---|---|
| Process Creation Activity | Line chart | Sysmon Event ID 1 |
| Network Connection Activity | Area chart | Sysmon Event ID 3 |
| Top 10 Destination IPs | Bar chart | Extracted destination IP frequency |
| AbuseIPDB Threat Intelligence Enrichment | Table | Enriched network connection events |
| IP Reputation Summary | Table | AbuseIPDB CSV lookup |

Both activity charts use five-minute timechart aggregation. The dashboard's global time range was set to Past 24 hours.

### Validation and Evidence

The dashboard was saved successfully, and all five panels were visible in the saved dashboard view.

**Evidence:** `docs/screenshots/07-windows-soc-threat-intelligence-dashboard.png`

### Interpretation and Limitations

- The dashboard visualizes collected endpoint and network telemetry.
- Threat-intelligence panels display reputation information from a point-in-time CSV snapshot.
- A reputation match does not independently establish malicious activity.
- The dashboard provides investigation visibility; it does not implement automated incident response or validated malicious-activity alerts.
