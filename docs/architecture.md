# Windows SOC Lab Architecture

This document describes the implemented architecture of the local Windows SOC lab using Microsoft Sysmon, Splunk Enterprise, and AbuseIPDB threat-intelligence enrichment.

## 1. Architecture Overview

A local Windows endpoint generates security telemetry. Sysmon records endpoint activity in the Windows Event Log, and Splunk collects those events for investigation. Selected destination IP addresses are enriched using AbuseIPDB data and presented through a Splunk Dashboard Studio dashboard.

    flowchart TD
        A["Windows Endpoint"] --> B["Microsoft Sysmon"]
        B --> C["Sysmon Operational Event Log"]
        C --> D["Splunk Enterprise"]
        D --> E["main Index"]
        E --> F["SPL Investigations"]
        F --> G["Process Investigation"]
        F --> H["Network Investigation"]
        H --> I["AbuseIPDB CSV Lookup"]
        I --> J["Threat Intelligence Enrichment"]
        E --> K["Splunk Dashboard Studio"]
        J --> K

## 2. Lab Components

| Component | Implementation |
|---|---|
| Endpoint | Local Windows desktop |
| Telemetry collection | Microsoft Sysmon |
| Sysmon schema | 4.91 |
| Sysmon service | Running automatically |
| Event channel | Microsoft-Windows-Sysmon/Operational |
| SIEM platform | Splunk Enterprise 9.3.14 |
| Splunk Web | http://127.0.0.1:8001 |
| Splunk index | main |
| Event format | XML |
| Query language | Splunk Processing Language (SPL) |
| Threat intelligence | AbuseIPDB API v2 data in CSV lookup |
| Visualization | Splunk Dashboard Studio |

No virtual machines, separate Linux systems, Kali attacker systems, or Wazuh servers are part of the verified implementation.

## 3. Sysmon Telemetry Collection

Sysmon is configured using schema version 4.91 and SHA-256 hashing. Process creation and network connection monitoring are enabled.

| Event ID | Event Type | Lab Usage |
|---|---|---|
| 1 | Process Create | Process creation investigation |
| 3 | Network Connect | Network connection and destination IP investigation |
| 5 | Process Terminated | Not enabled in this lab |

Process creation events can provide process image, parent image, process ID, user, command line, and file hashes.

Network connection events can provide process image, protocol, source IP, destination IP, and destination port.

Individual fields depend on the event and Sysmon configuration.

## 4. Splunk Event Ingestion

Splunk collects events from the Sysmon Operational event channel through a Windows Event Log input.

Configured input:

    [WinEventLog://Microsoft-Windows-Sysmon/Operational]
    disabled = 0
    index = main
    renderXml = 1

**Event source:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`

**Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

**Index:** `main`

Events are searchable through Splunk Search & Reporting. Relevant XML fields are extracted in tested SPL searches using `rex`.

## 5. Investigation Workflow

1. Generate harmless process or network activity on the Windows endpoint.
2. Verify that Sysmon records the activity.
3. Confirm that Splunk ingests the corresponding event.
4. Extract relevant fields from raw XML using SPL `rex`.
5. Investigate process creation and parent-child relationships.
6. Investigate network connections and destination IP addresses.
7. Enrich selected observed destination IP addresses using AbuseIPDB reputation data.
8. Review results through SPL searches and the Splunk dashboard.

Testing included Notepad and Windows PowerShell process creation, as well as observed network connection events.

## 6. Threat Intelligence Enrichment

Selected observed destination IP addresses were checked using AbuseIPDB API v2.

The reputation information is stored in:

`lookups/abuseipdb-enrichment.csv`

The CSV contains IP address, lookup date, abuse confidence score, country code, ISP, domain, total reports, and last reported timestamp.

The CSV was uploaded to Splunk as a lookup and used to match destination IP addresses extracted from Sysmon Event ID 3 records.

The current lookup contains two enriched IP addresses.

Reputation information is a point-in-time snapshot. Historical reports or reputation scores alone do not establish that an observed connection is malicious.

## 7. Dashboard and Visualization

A five-panel dashboard was created and saved in Splunk Dashboard Studio.

**Dashboard title:** `Windows SOC - Endpoint & Threat Intelligence Overview`

Implemented panels:

1. **Process Creation Activity** â€” Sysmon Event ID 1, line chart.
2. **Network Connection Activity** â€” Sysmon Event ID 3, area chart.
3. **Top 10 Destination IPs** â€” destination IP frequency analysis, bar chart.
4. **AbuseIPDB Threat Intelligence Enrichment** â€” table of observed network events matched against reputation data.
5. **IP Reputation Summary** â€” table of reputation metadata from the CSV lookup.

The dashboard uses collected Sysmon telemetry and the validated AbuseIPDB lookup.

**Dashboard evidence:** `docs/screenshots/07-windows-soc-threat-intelligence-dashboard.png`

## 8. Network and Access Scope

The lab currently uses local services on the Windows desktop.

| Service | Access |
|---|---|
| Splunk Web | http://127.0.0.1:8001 |
| Sysmon Event Log | Local Windows event channel |
| Splunk event collection | Local Windows Event Log input |
| Threat intelligence | Uploaded CSV lookup in Splunk |

No separate agent-to-server network, attacker subnet, or inter-VM communication is configured.

## 9. Current Limitations and Future Work

The following capabilities have not yet been implemented or validated:

- Registry activity investigation.
- File creation monitoring and investigation.
- Dedicated PowerShell abuse detection logic.
- Custom Splunk alert generation and testing.
- Automated threat-intelligence refresh.
- Automated incident response.
- Multi-endpoint log collection.
- Linux telemetry collection.
- End-to-end incident response simulation.
- MITRE ATT&CK technique mapping.

These are potential future improvements, not completed capabilities.

## 10. Architecture Validation

The implementation is supported by the following verified activities:

- Sysmon installation and service verification.
- Sysmon Operational event channel verification.
- Splunk Windows Event Log input configuration.
- Successful Sysmon event ingestion into Splunk.
- Notepad process creation investigation.
- Windows PowerShell process creation investigation.
- Network connection event collection and investigation.
- Destination IP and port frequency analysis.
- AbuseIPDB reputation enrichment using a CSV lookup.
- Validation of the enrichment search.
- Creation and saving of the five-panel Splunk dashboard.

Supporting screenshots and evidence are maintained in `docs/screenshots/`.

