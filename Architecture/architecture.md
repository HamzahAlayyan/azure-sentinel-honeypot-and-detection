## Architecture

The environment follows this security monitoring pipeline:

```text
┌──────────────────────┐
│  Simulated Attacker  │
│                      │
│ Authentication       │
│ Attempts             │
└──────────┬───────────┘
           │
           │ Failed Logons
           │ Event ID 4625
           ▼
┌──────────────────────┐
│   Azure Windows VM   │
│      Honeypot        │
│                      │
│ Windows Security     │
│ Events               │
└──────────┬───────────┘
           │
           │ Security Telemetry
           ▼
┌──────────────────────┐
│ Azure Monitor Agent  │
│        (AMA)         │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Data Collection Rule │
│        (DCR)         │
└──────────┬───────────┘
           │
           │ Forwarded Events
           ▼
┌──────────────────────────┐
│   Log Analytics          │
│      Workspace           │
│                          │
│ Centralized Security     │
│ Logs                     │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│   Microsoft Sentinel     │
│                          │
│   SIEM & Investigation   │
└──────────┬───────────────┘
           │
           ├───────────────────────┐
           │                       │
           ▼                       ▼
┌──────────────────────┐   ┌──────────────────────┐
│     KQL Queries      │   │   GeoIP Watchlist    │
│                      │   │                      │
│ Failed Login         │   │ IP → Location        │
│ Investigation        │   │ City / Country       │
└──────────┬───────────┘   │ Latitude / Longitude │
           │               └──────────┬───────────┘
           │                          │
           └──────────────┬───────────┘
                          ▼
               ┌──────────────────────┐
               │ Sentinel Workbook    │
               │                      │
               │  Geographic Attack   │
               │       Map            │
               └──────────────────────┘
```
