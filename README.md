# ThreatIQ — Threat Intelligence Platform

A full-stack Security Operations Center (SOC) platform simulating real-world threat detection, intelligence, and response workflows across 7 architectural layers.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1 │ DATA SOURCES                                      │
│  Endpoints · Servers · Firewalls · Cloud · Identity · Email  │
│  Network Devices · Applications · OT/IoT                     │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 2 │ LOG COLLECTION & INGESTION                        │
│  Agents · Syslog · API Connectors · Event Streaming          │
│  Log Normalization · Parsing · Enrichment                    │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 3 │ SIEM CORE                                         │
│  Central Log Storage · Correlation Rules · Detection         │
│  UEBA · Dashboards · Compliance Reporting                    │
└──────────────────────┬──────────────────────────────────────┘
              Alerts / Events / Incidents
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 4 │ THREAT INTELLIGENCE                               │
│  External Feeds · IOC Enrichment · Reputation Services       │
│  MITRE ATT&CK Mapping · Threat Contextualization            │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 5 │ SOAR                                              │
│  Case Management · Playbook Automation · Alert Triage        │
│  Incident Orchestration · Workflow Automation                │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 6 │ RESPONSE & SECURITY CONTROLS                      │
│  EDR/XDR · Firewall Blocking · Identity Access Control       │
│  Ticketing · Vulnerability Management · Forensics            │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 7 │ SOC ANALYSTS & GOVERNANCE                         │
│  Tier 1 / T2 / T3 Analysts · Threat Hunting · IR Team        │
│  MTTD / MTTR Reporting · Continuous Improvement              │
└─────────────────────────────────────────────────────────────┘
```

---

## Features

### Dashboard Sections

| Section | Layer | Description |
|---|---|---|
| Overview | All | KPI cards, alert severity donut, live ingestion rate chart, critical alert feed |
| Architecture | Reference | Interactive 7-layer SOC architecture diagram |
| Data Sources | 1 | 38 connected sources across 8 types — live status, logs/min rate |
| Log Stream | 2 | Real-time scrolling log feed with severity and keyword filters |
| SIEM Alerts | 3 | Live alert table with MITRE ATT&CK tags, geo enrichment, status management |
| Correlation Rules | 3 | 18 detection rules mapped to MITRE ATT&CK techniques |
| Threat Intel / IOCs | 4 | 7 threat feed status cards + IOC database with confidence scoring |
| Incidents (Kanban) | 5 | 4-column kanban board: Open → Investigating → Contained → Resolved |
| Playbooks | 5 | 10 automated response playbooks with live execution tracking |
| SOC Metrics | 7 | MTTD, MTTR, false positive rate, analyst performance, coverage score |

### Real-Time Capabilities

- WebSocket connection streams live events every 0.6–2.2 seconds
- New logs, alerts, IOCs, and incidents appear without page refresh
- Critical/high alerts trigger toast notifications
- Playbook execution steps update in real time
- KPI counters increment live

### Detection Content (18 Correlation Rules)

| Rule | MITRE Technique | Severity |
|---|---|---|
| Brute Force Login Attempt | T1110.001 | High |
| Lateral Movement Detected | T1021.002 | Critical |
| Data Exfiltration Suspected | T1041 | Critical |
| C2 Beaconing Activity | T1071.001 | High |
| Privilege Escalation Attempt | T1548.002 | High |
| Ransomware Behavior Detected | T1486 | Critical |
| SQL Injection Attempt | T1190 | Medium |
| Phishing Link Clicked | T1566.002 | High |
| Suspicious PowerShell Execution | T1059.001 | High |
| Mimikatz Credential Dump | T1003.001 | Critical |
| Kerberoasting Attack | T1558.003 | Critical |
| Pass-the-Hash Activity | T1550.002 | Critical |
| Outbound DNS Tunneling | T1048.003 | High |
| Cloud Storage Bucket Exposed | T1530 | High |
| Port Scan Detected | T1046 | Low |
| Account Created Outside Hours | T1136.001 | Medium |
| Firewall Rule Modified | T1562.004 | Medium |
| Suspicious Scheduled Task | T1053.005 | Medium |

### Threat Intelligence Feeds

- AlienVault OTX
- VirusTotal
- Abuse.ch
- MISP Community
- EmergingThreats
- Cisco Talos
- Shodan Intel

### Response Playbooks (10)

1. Phishing Response
2. Malware Containment
3. Account Compromise
4. DDoS Mitigation
5. Ransomware Response
6. Insider Threat
7. Cloud Misconfiguration
8. Credential Stuffing
9. Kerberoasting Defense
10. Zero-Day Response

---

## Getting Started

### Requirements

- Python 3.9+

### Installation & Run

```bash
# Clone or navigate to the project directory
cd "threat-intel-platform"

# Run the platform (creates virtualenv and installs deps automatically)
bash run.sh
```

Then open **http://localhost:8001** in your browser.

### Manual Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8001
```

---

## Project Structure

```
threat-intel-platform/
├── main.py              # FastAPI backend — all API routes, WebSocket, data generator
├── requirements.txt     # Python dependencies
├── run.sh               # Quick-start script
└── frontend/
    └── index.html       # Single-page SOC dashboard (HTML + CSS + JS)
```

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | Platform-wide KPI statistics |
| `/api/sources` | GET | Data source inventory and status |
| `/api/logs` | GET | Recent log entries (filterable by severity, source type) |
| `/api/alerts` | GET | SIEM alerts (filterable by severity, status) |
| `/api/alerts/{id}/status` | PUT | Update alert status |
| `/api/threats/iocs` | GET | IOC database (filterable by type, threat type) |
| `/api/threats/feeds` | GET | Threat feed status |
| `/api/incidents` | GET | Incident list (filterable by status) |
| `/api/incidents/{id}/status` | PUT | Update incident status |
| `/api/playbooks` | GET | Playbook definitions |
| `/api/playbook-runs` | GET | Playbook execution history |
| `/api/rules` | GET | Correlation rule library |
| `/api/metrics` | GET | SOC performance metrics |
| `/ws` | WS | Real-time event stream |
| `/api/docs` | GET | Interactive Swagger UI |

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python · FastAPI · Uvicorn |
| Real-time | WebSocket (native FastAPI) |
| Frontend | Vanilla HTML/CSS/JavaScript |
| Charts | Chart.js 4.4 |
| Data | In-memory stores with live simulation |

---

## Screenshots

Open **http://localhost:8001** to see:

- **Overview** — Live KPI counters and charts updating in real time
- **Log Stream** — Continuous feed of normalized security events
- **SIEM Alerts** — Color-coded alert table with MITRE ATT&CK context
- **Incident Kanban** — Drag-and-drop style incident tracking board
- **Playbooks** — Step-by-step automated response execution
- **SOC Metrics** — Analyst performance and platform health
