# Security Investigation

## 1. Investigation Objective

The objective of this investigation was to monitor authentication activity against an internet-facing Windows virtual machine and identify unsuccessful login attempts using Microsoft Sentinel.

The investigation focused on:

- Detecting failed authentication attempts
- Identifying affected accounts
- Identifying source IP addresses
- Enriching IP addresses with geographic information
- Visualizing authentication activity geographically

---

## 2. Windows Authentication Events

Windows Security Event ID **4625** was used as the primary indicator of failed authentication attempts.

The event provides useful information for investigation, including:

- Timestamp
- Computer
- Account
- Source IP address
- Logon type

These fields can help establish when an authentication attempt occurred, which account was targeted, and where the connection originated.

---

## 3. Centralized Monitoring

Security events generated on the Windows VM were forwarded to Azure Log Analytics using the Azure Monitor Agent (AMA).

Microsoft Sentinel was connected to the Log Analytics Workspace, allowing the security telemetry to be queried centrally using KQL.

This provides a more scalable approach to monitoring compared with investigating events exclusively through Windows Event Viewer.

---

## 4. Detection Query

The following KQL query was used to identify failed Windows authentication attempts:

```kql
SecurityEvent
| where TimeGenerated > ago(3h)
| where EventID == 4625
| project
    TimeGenerated,
    Computer,
    Account,
    IpAddress,
    LogonType,
    Activity
| order by TimeGenerated desc
```

### Investigation Fields

| Field | Purpose |
|---|---|
| `TimeGenerated` | Determines when the event occurred |
| `Computer` | Identifies the affected host |
| `Account` | Identifies the targeted account |
| `IpAddress` | Identifies the source of the authentication attempt |
| `LogonType` | Provides context about the authentication method |

---

## 5. IP Address Enrichment

The Windows Security Events contained source IP addresses but did not directly provide geographic information.

A GeoIP dataset was imported into Microsoft Sentinel as a Watchlist using the `network` field as the search key.

The IP address from the security event was then matched against the GeoIP data using the `ipv4_lookup` operator.

This allowed the investigation to associate authentication attempts with geographic information like:

- Country
- City
- Latitude
- Longitude

---

## 6. Geographic Attack Visualization

The enriched authentication events were used as the data source for a Microsoft Sentinel Workbook.

The workbook aggregates failed authentication attempts by source IP and geographic location.

The visualization provides:

- Number of failed authentication attempts
- Source IP addresses
- Geographic coordinates
- City and country information

This makes it easier to identify patterns in authentication activity and provides a visual overview of where observed connection attempts originated.

---

## 7. Investigation Workflow

The overall investigation workflow was:

```text
Authentication Attempt
        ↓
Windows Event ID 4625
        ↓
Azure Monitor Agent
        ↓
Data Collection Rule
        ↓
Log Analytics Workspace
        ↓
Microsoft Sentinel
        ↓
KQL Investigation
        ↓
GeoIP Watchlist Enrichment
        ↓
Sentinel Workbook
        ↓
Geographic Attack Visualization
```

---

## 8. Security Analyst Perspective

In a real security operations environment, repeated failed authentication attempts could indicate activity such as password guessing/brute forcing or other unauthorized access attempts.

Event ID 4625 alone does not establish that an attack has occurred. Additional context would be required, including:

- Number of attempts
- Time period
- Targeted accounts
- Source IP reputation
- Logon type
- Successful logons associated with the same source
- Other activity from the affected host

The investigation therefore demonstrates the importance of correlating authentication telemetry with additional security data rather than treating a single event as conclusive evidence of compromise.

---

## 9. Skills Demonstrated

This investigation demonstrates practical experience with:

- Microsoft Azure
- Microsoft Sentinel
- SIEM monitoring
- Windows Security Events
- KQL
- Log Analytics
- Azure Monitor Agent
- Data Collection Rules
- Sentinel Watchlists
- IP address enrichment
- Security event investigation
- Security visualization
- Cloud security monitoring
