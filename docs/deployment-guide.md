# Windows SOC Lab Deployment Guide

This guide documents how to reproduce the Windows endpoint monitoring, network investigation, threat-intelligence enrichment, and dashboard environment implemented in this project.

The lab uses a local Windows endpoint, Microsoft Sysmon, and Splunk Enterprise.

No virtual machines, Linux endpoints, Wazuh server, or attacker system are required.

---

## 1. Prerequisites

| Requirement | Used in this lab |
|---|---|
| Operating system | Windows 10, 64-bit |
| Administrator access | Required for Sysmon installation and configuration |
| Endpoint telemetry | Microsoft Sysmon |
| SIEM | Splunk Enterprise 9.3.14 |
| Query language | Splunk Processing Language (SPL) |
| Threat intelligence | AbuseIPDB API v2 data |
| Visualization | Splunk Dashboard Studio |

The original lab was implemented on Windows 10 with 16 GB RAM.

The commands below should be run in an elevated PowerShell session when administrator privileges are required.

## 2. Install and Configure Sysmon

### Step 2.1: Obtain Sysmon

Download Sysmon from the official Microsoft Sysinternals website:

https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

Extract the downloaded package.

Open PowerShell in the extracted directory.

### Step 2.2: Check the Sysmon version and schema

Run the executable supplied in the package. For example:

~~~powershell
.\Sysmon64.exe -s
~~~

This displays the supported configuration schema.

The project configuration uses schema version 4.91.

### Step 2.3: Apply the project configuration

From the project root directory, verify that the configuration file exists:

~~~powershell
Test-Path .\configs\sysmon\sysmonconfig.xml
~~~

For a fresh installation, run:

~~~powershell
.\Sysmon64.exe -accepteula -i .\configs\sysmon\sysmonconfig.xml
~~~

If Sysmon is already installed, update its configuration instead:

~~~powershell
.\Sysmon64.exe -c .\configs\sysmon\sysmonconfig.xml
~~~

Use the executable name supplied in your downloaded package. It may differ from `Sysmon64.exe`.

### Step 2.4: Verify the Sysmon service

~~~powershell
Get-Service -Name '*Sysmon*'
~~~

Expected state:

- Service status: Running
- Startup type: Automatic

Check the Sysmon Operational event channel:

~~~powershell
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' |
Select-Object LogName, IsEnabled, RecordCount
~~~

The event channel should be enabled.

## 3. Install and Configure Splunk Enterprise

Install Splunk Enterprise for Windows using the official Splunk installer:

https://www.splunk.com/en_us/download/splunk-enterprise.html

After installation, verify that the Splunk service is running:

~~~powershell
Get-Service Splunkd
~~~

Open Splunk Web locally:

`http://127.0.0.1:8001`

The port may differ depending on the port selected during installation.

## 4. Configure Windows Event Log Collection

Splunk must collect events from the Sysmon Operational event channel.

Create or edit:

`C:\Program Files\Splunk\etc\system\local\inputs.conf`

Add:

~~~ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
renderXml = 1
~~~

The `main` index must exist in Splunk.

Restart Splunk:

~~~powershell
Restart-Service Splunkd
Get-Service Splunkd
~~~

## 5. Verify Event Ingestion

Open Splunk Search & Reporting.

Run:

~~~spl
index=main earliest=-15m
| stats count by source sourcetype
~~~

Look for the Sysmon event source:

`WinEventLog:Microsoft-Windows-Sysmon/Operational`

Expected sourcetype:

`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

Event availability depends on recent endpoint activity and the selected search time range.

The project uses `rex` to extract fields from XML-formatted event data.

## 6. Generate Harmless Test Activity

Launch Notepad:

~~~powershell
Start-Process notepad.exe
~~~

Launch Windows PowerShell:

~~~powershell
Start-Process powershell.exe
~~~

These activities generate ordinary process creation events.

Sysmon Event IDs used in the lab:

| Event ID | Event type | Investigation |
|---|---|---|
| 1 | Process Create | Process creation |
| 3 | Network Connect | Network connections |
| 5 | Process Terminated | Not enabled in this lab |

## 7. Investigate Process and Network Events

The project includes tested investigation queries in:

`detections/splunk-queries.spl`

The queries cover process creation, network connection analysis, destination IP investigation, and threat-intelligence enrichment.

Example network investigation:

~~~spl
index=main
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>\d+)</Data>"
| search EventID=3
| stats count by DestinationIp DestinationPort
| sort -count
~~~

The query summarizes observed destination IP and port combinations.

Additional investigation queries are documented in the project detection file and the safe telemetry validation guide.

## 8. Configure AbuseIPDB Threat Intelligence Enrichment

The project uses selected destination IP addresses checked through AbuseIPDB API v2.

The prepared lookup file is:

`lookups/abuseipdb-enrichment.csv`

The CSV contains reputation information such as:

- IP address.
- Lookup date.
- Abuse confidence score.
- Country code.
- ISP.
- Domain.
- Total reports.
- Last reported timestamp.

### Step 8.1: Upload the lookup to Splunk

1. Open Splunk Web.
2. Navigate to Settings.
3. Open Lookups.
4. Select Lookup table files.
5. Upload `abuseipdb-enrichment.csv`.
6. Make the lookup available to the Search app or the app containing the searches.

The lookup must be accessible to the user running the searches.

### Step 8.2: Verify enrichment

Run:

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

The current project lookup contains two enriched IP addresses.

**Security note:** The API key is not stored in this repository. Do not publish API keys or other credentials.

Reputation information is a point-in-time snapshot. Historical reports alone do not establish that an observed connection is malicious.

## 9. Create the Splunk Dashboard

The implemented dashboard is:

**Windows SOC - Endpoint & Threat Intelligence Overview**

It was created and saved using Splunk Dashboard Studio.

The dashboard contains five panels:

1. Process Creation Activity - Event ID 1 line chart.
2. Network Connection Activity - Event ID 3 area chart.
3. Top 10 Destination IPs - destination IP frequency bar chart.
4. AbuseIPDB Threat Intelligence Enrichment - enriched network event table.
5. IP Reputation Summary - reputation metadata table.

To reproduce the dashboard:

1. Open Splunk Web.
2. Navigate to Dashboards.
3. Create a new Dashboard Studio dashboard.
4. Use the title above.
5. Configure the five panels as described in `dashboards/dashboard_specs.md`. The validated investigation queries are maintained in `detections/splunk-queries.spl`.
6. Set the dashboard time range to Past 24 hours.
7. Save the dashboard.

The dashboard requires the Sysmon events and the AbuseIPDB lookup to be available.

The dashboard provides investigation visibility. It is not a validated automated alerting or incident-response system.

## 10. Troubleshooting Checks

### Sysmon service status

~~~powershell
Get-Service -Name '*Sysmon*'
~~~

### Sysmon event channel status

~~~powershell
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
~~~

### Recent Sysmon events

~~~powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10
~~~

### Splunk service status

~~~powershell
Get-Service Splunkd
~~~

### Splunk input configuration

~~~powershell
Get-Content 'C:\Program Files\Splunk\etc\system\local\inputs.conf'
~~~

If events do not appear in Splunk, verify the input configuration, service status, selected index, event channel, and search time range.

If enrichment searches return no results, verify that the lookup file was uploaded, is accessible to the Search app, and contains matching IP addresses.

## 11. Current Implementation Scope

The verified implementation covers:

- Sysmon installation and configuration.
- Windows process creation telemetry.
- Windows network connection telemetry.
- Sysmon Operational event collection in Splunk.
- XML field extraction using SPL.
- Notepad process investigation.
- Windows PowerShell process investigation.
- Destination IP and port analysis.
- AbuseIPDB CSV lookup enrichment.
- Five-panel Splunk Dashboard Studio dashboard.

The following are not part of the completed deployment:

- Wazuh server or agents.
- Linux auditd.
- Kali Linux.
- Atomic Red Team.
- Automated attack simulation.
- Custom Splunk alert deployment.
- Automated incident response.
- Production multi-endpoint monitoring.
- Automated threat-intelligence refresh.

These capabilities should only be documented as completed after implementation and validation.

## 12. Evidence

Refer to `docs/screenshots/README.md` for the evidence index.

The screenshots and supporting files document actual installation checks, event collection, process and network investigations, threat-intelligence enrichment, and the saved dashboard.

Before publishing the project, review evidence for local usernames, paths, API keys, tokens, and other machine-specific information.

