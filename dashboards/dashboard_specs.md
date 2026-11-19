# Windows SOC - Endpoint & Threat Intelligence Dashboard

## Status

**Implemented and saved:** 2026-11-18

The dashboard was created using Splunk Dashboard Studio and saved successfully.

**Dashboard title:** `Windows SOC - Endpoint & Threat Intelligence Overview`

**Description:** Windows endpoint telemetry, network investigations, and AbuseIPDB threat intelligence enrichment using Sysmon and Splunk.

## Data Sources

- Index: `main`
- Source: `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- Sourcetype: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- Telemetry: Microsoft Sysmon
- Threat intelligence: AbuseIPDB CSV lookup (`abuseipdb-enrichment.csv`)

## Implemented Dashboard Panels

### 1. Process Creation Activity
- Visualization: Line chart
- Source: Sysmon Event ID 1
- Aggregation: Five-minute intervals
- Purpose: Show process creation activity over time.

### 2. Network Connection Activity
- Visualization: Area chart
- Source: Sysmon Event ID 3
- Aggregation: Five-minute intervals
- Purpose: Show network connection activity over time.

### 3. Top 10 Destination IPs
- Visualization: Bar chart
- Source: Sysmon Event ID 3
- Purpose: Identify frequently observed destination IP addresses.

### 4. AbuseIPDB Threat Intelligence Enrichment
- Visualization: Table
- Source: Sysmon Event ID 3 and AbuseIPDB CSV lookup
- Time constraint: Past 24 hours (inherited from the dashboard global time range)
- Purpose: Display observed network events matched with available IP reputation information.
- Fields: Timestamp, process image, destination IP, destination port, abuse confidence score, total reports, ISP, and domain.

### 5. IP Reputation Summary
- Visualization: Table
- Source: AbuseIPDB CSV lookup
- Purpose: Summarize reputation metadata for enriched IP addresses.
- Fields: IP address, confidence score, total reports, country, ISP, domain, and last reported time.

## Dashboard Configuration

- Platform: Splunk Dashboard Studio
- Saved global time range: Past 24 hours
- All five panels were visible in the saved dashboard view.
- Dashboard searches use collected Sysmon telemetry and the validated threat-intelligence lookup.

## Evidence

Dashboard screenshot:

`docs/screenshots/07-windows-soc-threat-intelligence-dashboard.png`

Additional investigation and enrichment evidence is indexed in `docs/screenshots/README.md`.

## Interpretation and Limitations

- Process and network activity represent observed endpoint telemetry, not confirmed malicious behavior.
- Destination frequency alone does not establish malicious activity.
- AbuseIPDB reputation information is a point-in-time snapshot.
- Historical reports do not independently establish that an observed connection was malicious.
- The current lookup contains two enriched IP addresses.
- The dashboard supports investigation and visibility; it does not currently provide automated incident response.

## Potential Future Enhancements

- Additional Sysmon event types and investigation panels.
- Severity classification.
- MITRE ATT&CK technique mapping.
- Alert creation, testing, and tuning.
- Automated threat-intelligence refresh.
- Automated alert triage and response.
- Additional reputation sources.

Only capabilities that have been implemented and tested should be described as completed.

