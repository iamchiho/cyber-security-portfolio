# AI Vulnerability Prioritization

This project combines **Nessus vulnerability scan results**, **open source threat intelligence**, and **Claude AI** to produce risk-prioritised, actionable security reports.

---

## How It Works

```
Nessus Scan → Aggregate Results → Enrich with Threat Intel → Criticality Scoring → AI Analysis → HTML Report
```

| Step | Tool | Output |
|------|------|--------|
| Vulnerability scanning | Nessus Essentials | Raw scan findings |
| Data aggregation | `aggreage_nessus_reports.py` | Structured JSON (vulns + assets) |
| Threat intelligence | `threat_intel.py` → CISA KEV | Confirmed exploitation data |
| Criticality scoring | `criticality.py` | Risk scores per asset (0–100) |
| AI analysis | Claude (Anthropic) | Prioritised remediation guidance |
| Report generation | `generate_report.py` | Standalone HTML report |

---

## Criticality Scoring Model

This section explains how each asset's **Criticality Score** (0–100) is calculated.

---

## Overview

Every asset is scored across three independent dimensions, then a device-type multiplier is applied:

```
Score = min(100, round((Internet Exposure + Service Criticality + Vuln Risk) × Multiplier))
```

| Dimension             | Max points | What it measures |
|-----------------------|:----------:|------------------|
| Internet Exposure     | 40         | How likely the asset is reachable from an untrusted network |
| Service Criticality   | 35         | How business-critical the running services are |
| Vulnerability Risk    | 25         | Severity, exploitability, and active exploitation probability |
| **Device Multiplier** | ×0.4–×1.4  | Scales the subtotal based on device type |

---

## Criticality Tiers

| Score     | Tier     |
|-----------|----------|
| ≥ 70      | Critical |
| 45 – 69   | High     |
| 25 – 44   | Medium   |
| < 25      | Low      |

---

## Dimension 1 — Internet Exposure (0–40)

Estimates how exposed the asset is to external or untrusted traffic.

**Starting points by device type:**

| Device Nature               | Base points |
|-----------------------------|:-----------:|
| Router / Gateway            | 38          |
| Router / Gateway (inferred) | 32          |
| Firewall                    | 30          |
| Network Device              | 18          |
| NAS                         | 8           |
| Windows / Linux Server      | 5           |
| Hypervisor                  | 5           |
| macOS, Linux Workstation    | 0           |
| Windows Workstation         | 0           |
| Mobile (iOS / Android)      | 0           |

**Additional points are added for open ports associated with internet-facing services:**

| Port(s)        | Service          | Points |
|----------------|------------------|:------:|
| 443            | HTTPS            | +25    |
| 23             | Telnet           | +28    |
| 3389           | RDP              | +28    |
| 80             | HTTP             | +20    |
| 8443 / 9392    | HTTPS-alt / Mgmt | +20    |
| 5900 / 5901    | VNC              | +22    |
| 25 / 465       | SMTP / SMTPS     | +20    |
| 53             | DNS              | +18    |
| 8080 / 3128    | HTTP Proxy       | +18    |
| 21             | FTP              | +15    |
| 587            | SMTP Submit      | +15    |
| 8000 / 3000    | HTTP Dev         | +15    |
| 1194 / 500 / 4500 | VPN / IPsec  | +15    |

Additional points are also added when scan plugins detect Telnet, RDP, VNC, or firewall services by name.

> **Note:** The score reflects *inferred* internet exposure based on service types found during an internal scan. Confirmed internet-facing status requires an external/perimeter scan.

---

## Dimension 2 — Service Criticality (0–35)

Measures how valuable or sensitive the services running on the asset are, regardless of network exposure.

**Points are accumulated from three sources:**

### Open ports mapped to critical services

| Port(s)       | Service                  | Points |
|---------------|--------------------------|:------:|
| 445 / 139     | SMB / NetBIOS            | 25 / 20 |
| 2049          | NFS                      | 22     |
| 67            | DHCP Server              | 20     |
| 23            | Telnet (admin)           | 20     |
| 161           | SNMP                     | 18     |
| 548           | AFP (Apple Filing)       | 18     |
| 5555          | ADB / Service            | 15     |
| 22            | SSH                      | 12     |
| 111           | RPC Portmapper           | 15     |
| 1900          | SSDP / UPnP              | 12     |
| 9001          | Tor / Service            | 12     |
| 162           | SNMP Trap                | 12     |

### Nessus plugin families detected

| Plugin Family         | Service Label    | Points |
|-----------------------|------------------|:------:|
| CGI abuses            | Web Application  | 25     |
| Web Servers           | Web Server       | 20     |
| Firewalls             | Firewall Service | 22     |
| DNS                   | DNS Server       | 18     |
| SMTP problems         | Mail Server      | 20     |
| Windows               | Windows Service  | 15     |
| Oracle Linux LSC      | Oracle Linux     | 15     |
| RPC                   | RPC Services     | 12     |

### CPE (software inventory) keywords

| Software              | Points |
|-----------------------|:------:|
| MySQL / PostgreSQL / MariaDB | 30 |
| Kubernetes            | 30     |
| MongoDB               | 28     |
| Docker / Redis / Elasticsearch | 25 |
| Tomcat                | 25     |
| Apache / Nginx / IIS  | 20     |
| Samba                 | 22     |
| Postfix / Sendmail    | 20     |
| vsftpd                | 15     |
| OpenSSH               | 12     |

> Points from all three sources are accumulated but the dimension is **capped at 35**.

---

## Dimension 3 — Vulnerability Risk (0–25)

Scores the asset based on the actual vulnerabilities found, weighted by severity and exploitability.

### Severity counts

| Finding      | Points                         |
|--------------|--------------------------------|
| Critical CVE | +3 per finding, up to 12 total |
| High CVE     | +1 per finding, up to 8 total  |

### EPSS (Exploit Prediction Scoring System)

EPSS is a probability (0–100%) that a given CVE will be exploited in the wild within 30 days.

| Max EPSS on the asset | Points |
|-----------------------|:------:|
| ≥ 50%                 | +8     |
| 10% – 49%             | +4     |
| < 10%                 | +0     |

### Exploit code maturity

| Maturity level on any finding | Points |
|-------------------------------|:------:|
| High or Functional exploit    | +5     |

### CISA KEV (Known Exploited Vulnerabilities)

CISA KEV is a free catalog maintained by the US Cybersecurity and Infrastructure Security Agency listing CVEs confirmed to be actively exploited by real threat actors in the wild. This is the strongest available signal for exploitation risk — beyond CVSS scores or EPSS predictions.

| Condition                              | Points |
|----------------------------------------|:------:|
| Any CVE on this asset is in CISA KEV  | +10    |

The KEV catalog is automatically fetched and cached locally (refreshed every 24 hours). Assets with KEV-matching CVEs will display a **KEV** badge in the report.

> The dimension is **capped at 25**.

---

## Device-Type Multiplier

The subtotal (Exposure + Service + Vuln) is multiplied by a factor that reflects the inherent risk of the device type, regardless of findings.

| Device Nature               | Multiplier |
|-----------------------------|:----------:|
| Router / Gateway            | ×1.40      |
| Router / Gateway (inferred) | ×1.30      |
| Firewall                    | ×1.30      |
| Hypervisor                  | ×1.30      |
| Windows / Linux Server      | ×1.20      |
| Network Device              | ×1.20      |
| NAS                         | ×1.15      |
| macOS / Linux               | ×1.00      |
| Windows Workstation         | ×0.90      |
| Mobile (iOS / Android)      | ×0.40      |

The final score is capped at **100**.

---

## Port Evidence Quality

Nessus collects port data from two sources with different confidence levels:

| Source                          | Plugin IDs    | Confidence |
|---------------------------------|---------------|------------|
| Netstat (credentialed SSH scan) | 14272, 64582  | High — authoritative list of listening ports inside the OS |
| SYN scanner (network-level)     | all others    | Medium — network-visible only; may be blocked by host firewall |

When credentialed netstat data is available, it is used as the primary evidence for service detection. Both sources are combined for exposure scoring.

---

## Badges on Asset Cards and Vuln Table

| Badge             | Meaning |
|-------------------|---------|
| 🌐 **Boundary**   | Device is a Router or Gateway — near-certain network boundary device |
| ⚠ **Exposed Services** | Has services that would be dangerous if internet-exposed (inferred from service type, not confirmed by external scan) |
| ⚠ **No Cred**     | OS-type host where Nessus credentialed scan was not completed — patch-level and access-control findings may be missing |
| 🔴 **KEV**        | One or more CVEs on this vulnerability are in the CISA Known Exploited Vulnerabilities catalog — confirmed active exploitation in the wild |

---

## Score Example

**Asset: 192.168.1.24 (NAS)**

| Dimension             | Calculation                                          | Points |
|-----------------------|------------------------------------------------------|:------:|
| Internet Exposure     | Base 8 (NAS) + Port 80 +20 + Port 443 +25 + Port 23 +28 ... (capped) | 40 |
| Service Criticality   | Port 445 SMB +25 + NFS +22 ... (capped)              | 35     |
| Vuln Risk             | 1 Critical ×3 + 1 High ×1 + EPSS 91% +8             | 17     |
| **Subtotal**          | 40 + 35 + 17                                         | **92** |
| Multiplier            | ×1.15 (NAS)                                          |        |
| **Final Score**       | round(92 × 1.15) → capped at 100                    | **100** |
| **Tier**              | ≥ 70                                                 | **Critical** |
