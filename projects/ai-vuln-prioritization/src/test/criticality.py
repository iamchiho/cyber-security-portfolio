#!/usr/bin/env python3
"""
criticality.py — Asset Criticality Scoring Model

Rule-based scoring across three dimensions (max 100):
  1. Internet Exposure  (0–40)  — what services face the network boundary
  2. Service Criticality (0–35) — how business-critical are the running services
  3. Vulnerability Risk  (0–25) — severity, exploitability, EPSS

Output tier:  Critical (≥70) · High (45–69) · Medium (25–44) · Low (<25)

Each result carries human-readable factors so the report can explain the score.
"""

from __future__ import annotations
from dataclasses import dataclass, field

# ── Port → (service label, internet-exposure points) ──────────────────────────
# Ports that strongly suggest the host is (or should be treated as) internet-facing.
INET_PORTS: dict[int, tuple[str, int]] = {
    80:   ("HTTP",        20),
    443:  ("HTTPS",       25),
    8080: ("HTTP-alt",    18),
    8443: ("HTTPS-alt",   20),
    8000: ("HTTP-dev",    15),
    3000: ("HTTP-dev",    15),
    25:   ("SMTP",        20),
    465:  ("SMTPS",       20),
    587:  ("SMTP-submit", 15),
    21:   ("FTP",         15),
    53:   ("DNS",         18),
    23:   ("Telnet",      28),   # cleartext remote admin = very high exposure
    3389: ("RDP",         28),
    5900: ("VNC",         22),
    5901: ("VNC",         22),
    1194: ("OpenVPN",     15),
    500:  ("IKE/IPsec",   15),
    4500: ("IPsec-NAT",   15),
    9392: ("OpenVAS",     20),   # management interface
    3128: ("HTTP Proxy",  18),
}

# ── Port → (service label, service-criticality points) ────────────────────────
# Ports that indicate high-value services regardless of internet exposure.
SVC_PORTS: dict[int, tuple[str, int]] = {
    # File & network sharing
    445:  ("SMB/CIFS",          25),
    139:  ("NetBIOS/SMB",       20),
    2049: ("NFS",               22),
    548:  ("AFP (Apple Filing)",18),
    515:  ("LPD/Print",         10),
    631:  ("IPP/Print",         10),
    # Remote management
    22:   ("SSH",               12),
    23:   ("Telnet (admin)",    20),
    161:  ("SNMP",              18),
    162:  ("SNMP Trap",         12),
    # RPC / directory
    111:  ("RPC Portmapper",    15),
    662:  ("RPC",               10),
    892:  ("RPC",               10),
    # Apple / mDNS
    427:  ("SLP",                8),
    5353: ("mDNS",               8),
    5355: ("LLMNR",              8),
    # Misc services with critical data
    9001: ("Tor/Service",       12),
    9091: ("Service",           10),
    5000: ("Service",           10),
    5001: ("Service",           10),
    7000: ("AFS/Service",       10),
    7100: ("Service",           10),
    1900: ("SSDP/UPnP",        12),
    3702: ("WS-Discovery",     10),
    6668: ("IRC-like",         10),
    67:   ("DHCP Server",       20),   # DHCP server = likely infrastructure
    5555: ("ADB/Service",       15),
    9100: ("RAW Print",         10),
}

# ── Plugin family → (service label, criticality points) ───────────────────────
FAMILY_SVC: dict[str, tuple[str, int]] = {
    "Web Servers":                          ("Web Server",          20),
    "CGI abuses":                           ("Web Application",     25),
    "CGI abuses (XSS)":                     ("Web Application",     20),
    "DNS":                                  ("DNS Server",          18),
    "Firewalls":                            ("Firewall Service",    22),
    "Windows":                              ("Windows Service",     15),
    "Oracle Linux Local Security Checks":   ("Oracle Linux",        15),
    "RPC":                                  ("RPC Services",        12),
    "Artificial Intelligence":              ("AI/LLM Software",     10),
    "SMTP problems":                        ("Mail Server",         20),
}

# ── CPE product keyword → (service label, criticality points) ─────────────────
CPE_SVC: dict[str, tuple[str, int]] = {
    "apache":        ("Apache HTTP Server", 20),
    "nginx":         ("Nginx Web Server",   20),
    "iis":           ("IIS Web Server",     20),
    "tomcat":        ("Tomcat App Server",  25),
    "mysql":         ("MySQL Database",     30),
    "postgresql":    ("PostgreSQL",         30),
    "mariadb":       ("MariaDB Database",   30),
    "mongodb":       ("MongoDB",            28),
    "redis":         ("Redis",              25),
    "openssh":       ("SSH Server",         12),
    "samba":         ("Samba File Server",  22),
    "vsftpd":        ("FTP Server",         15),
    "postfix":       ("Mail Server",        20),
    "sendmail":      ("Mail Server",        20),
    "docker":        ("Docker",             25),
    "kubernetes":    ("Kubernetes",         30),
    "elasticsearch": ("Elasticsearch",      25),
}

# ── Plugin name keywords → (service label, where-to-add, points) ──────────────
# "where": "inet" = internet score, "svc" = service score
PLUGIN_SIGNALS: list[tuple[str, str, str, int]] = [
    ("HTTP Server",          "svc",  "Web Server",        18),
    ("HTTP Information",     "svc",  "Web Server",        15),
    ("HyperText Transfer",   "svc",  "Web Server",        15),
    ("Web Server",           "svc",  "Web Server",        18),
    ("OpenSSH",              "svc",  "SSH Server",        12),
    ("SSH",                  "svc",  "SSH Server",        12),
    ("SMB",                  "svc",  "SMB/Windows",       20),
    ("NFS Server",           "svc",  "NFS File Server",   22),
    ("Apple Filing",         "svc",  "AFP File Server",   18),
    ("DNS Server",           "svc",  "DNS Server",        18),
    ("SNMP",                 "svc",  "SNMP Management",   18),
    ("DHCP",                 "svc",  "DHCP Server",       20),
    ("Telnet",               "inet", "Telnet (exposed)",  25),
    ("RDP",                  "inet", "RDP (exposed)",     25),
    ("VNC",                  "inet", "VNC (exposed)",     22),
    ("FTP",                  "svc",  "FTP Server",        15),
    ("AI/LLM",               "svc",  "AI Software",       10),
]

# ── Device nature → (base internet-exposure pts, score multiplier) ─────────────
NATURE_WEIGHTS: dict[str, tuple[int, float]] = {
    "Router/Gateway":            (38, 1.40),
    "Router/Gateway (inferred)": (32, 1.30),
    "Firewall":                  (30, 1.30),
    "Network Device":            (18, 1.20),
    "NAS":                       (8,  1.15),
    "Windows Server":            (5,  1.20),
    "Linux Server":              (5,  1.20),
    "Hypervisor":                (5,  1.30),
    "macOS":                     (0,  1.00),
    "Linux":                     (0,  1.00),
    "Windows Workstation":       (0,  0.90),
    "Mobile (iOS)":              (0,  0.40),
    "Mobile (Android)":          (0,  0.40),
}

# ── Criticality tiers ──────────────────────────────────────────────────────────
TIERS: list[tuple[int, str, str, str]] = [
    (70, "Critical", "#E84040", "#2d0808"),
    (45, "High",     "#E87840", "#2d1808"),
    (25, "Medium",   "#E8B030", "#2d2008"),
    (0,  "Low",      "#E8D040", "#282200"),
]


@dataclass
class CriticalityResult:
    score:            int
    tier:             str
    tier_color:       str
    tier_bg:          str
    # "boundary_device" = Router/Gateway confirmed at network edge
    # "exposure_risk"   = has internet-reachable-type services (inferred, not confirmed)
    # Neither can confirm internet-reachable without an external/perimeter scan
    boundary_device:  bool
    exposure_risk:    bool
    netstat_ports:    list[int]  # ports confirmed by credentialed netstat scan
    inet_score:       int        # 0-40
    svc_score:        int        # 0-35
    vuln_score:       int        # 0-25
    kev_cves:         list[str] = field(default_factory=list)   # CVEs confirmed in CISA KEV
    services:         list[str] = field(default_factory=list)
    inet_signals:     list[str] = field(default_factory=list)
    factors:          list[str] = field(default_factory=list)


def _nature_key(nature: str) -> str:
    for k in NATURE_WEIGHTS:
        if k in nature:
            return k
    return ""


def assess(asset: dict, host_vulns: list[dict], kev_lookup: dict | None = None) -> CriticalityResult:
    """
    Score one asset.  host_vulns should contain only findings for this host.
    """
    nature  = asset.get("host_nature", "Unknown")
    nat_key = _nature_key(nature)
    base_inet, multiplier = NATURE_WEIGHTS.get(nat_key, (0, 1.0))

    # ── Collect evidence from scan findings ───────────────────────────────────
    # Netstat plugins (14272 = Netstat Portscanner SSH, 64582 = Netstat Connection Info)
    # run inside the OS via credentials → authoritative listening-port list.
    # SYN-scanner ports are network-visible but may miss localhost-only services
    # and can be blocked by host firewalls, so they are lower-confidence.
    NETSTAT_PLUGINS = {"14272", "64582"}

    netstat_ports: set[int] = set()   # confirmed by credentialed netstat
    syn_ports:     set[int] = set()   # seen by network-level SYN scanner
    plugin_names:  list[str] = []
    families:      set[str] = set()

    for v in host_vulns:
        pid = str(v.get("plugin_id", ""))
        try:
            p = int(v.get("port", 0))
            if p > 0:
                if pid in NETSTAT_PLUGINS:
                    netstat_ports.add(p)
                else:
                    syn_ports.add(p)
        except (ValueError, TypeError):
            pass
        pname = v.get("plugin_name", "")
        if pname:
            plugin_names.append(pname)
        fam = v.get("plugin_family", "")
        if fam:
            families.add(fam)

    # Netstat-confirmed ports are used for service detection with higher weight.
    # All ports (union) are used for exposure scoring.
    open_ports = netstat_ports | syn_ports

    # ── 1. Internet Exposure Score (capped at 40) ──────────────────────────────
    inet_score = base_inet
    inet_signals: list[str] = []
    inet_seen: set[str] = set()

    def _add_inet(label: str, pts: int) -> None:
        if label not in inet_seen:
            inet_seen.add(label)
            inet_signals.append(label)
            nonlocal inet_score
            inet_score += pts

    if "Router" in nature or "Gateway" in nature:
        inet_signals.append("Network boundary device")

    for port in open_ports:
        if port in INET_PORTS:
            label, pts = INET_PORTS[port]
            _add_inet(f"Port {port} ({label})", pts)

    for pname in plugin_names:
        pname_l = pname.lower()
        for keyword, where, label, pts in PLUGIN_SIGNALS:
            if where == "inet" and keyword.lower() in pname_l:
                _add_inet(label, pts)
                break

    if "Firewalls" in families:
        _add_inet("Firewall service", 15)

    inet_score = min(inet_score, 40)

    # boundary_device: only Router/Gateway — near-certain network edge device
    boundary_device = "Router" in nature or "Gateway" in nature
    # exposure_risk: has services that would be dangerous if internet-exposed
    # NOTE: this is inferred from service type, NOT confirmed by external scan
    exposure_risk = inet_score >= 15

    # ── 2. Service Criticality Score (capped at 35) ────────────────────────────
    svc_score = 0
    services: list[str] = []
    svc_seen: set[str] = set()

    def _add_svc(label: str, pts: int) -> None:
        if label not in svc_seen:
            svc_seen.add(label)
            services.append(label)
            nonlocal svc_score
            svc_score += pts

    for port in open_ports:
        if port in SVC_PORTS:
            label, pts = SVC_PORTS[port]
            _add_svc(label, pts)

    for fam, (label, pts) in FAMILY_SVC.items():
        if fam in families:
            _add_svc(label, pts)

    cpe_str = (asset.get("cpe") or "").lower()
    for keyword, (label, pts) in CPE_SVC.items():
        if keyword in cpe_str:
            _add_svc(label, pts)

    for pname in plugin_names:
        pname_l = pname.lower()
        for keyword, where, label, pts in PLUGIN_SIGNALS:
            if where == "svc" and keyword.lower() in pname_l:
                _add_svc(label, pts)
                break

    svc_score = min(svc_score, 35)

    # ── 3. Vulnerability Risk Score (capped at 25) ────────────────────────────
    critical_n = asset.get("critical_count", 0)
    high_n     = asset.get("high_count", 0)
    vuln_score = min(critical_n * 3, 12) + min(high_n, 8)

    max_epss = max(
        (float(v.get("epss_score") or 0) for v in host_vulns),
        default=0.0,
    )
    if max_epss >= 0.5:
        vuln_score += 8
    elif max_epss >= 0.1:
        vuln_score += 4

    exploit_levels = {v.get("exploit_code_maturity", "") for v in host_vulns}
    if "High" in exploit_levels or "Functional" in exploit_levels:
        vuln_score += 5

    # CISA KEV — confirmed active exploitation in the wild
    kev_hits: list[str] = []
    if kev_lookup:
        seen: set[str] = set()
        for v in host_vulns:
            cve_field = (v.get("cve") or "")
            cves = [c.strip() for c in cve_field.split(";") if c.strip()]
            for cve in cves:
                if cve not in seen and cve in kev_lookup:
                    kev_hits.append(cve)
                    seen.add(cve)
        if kev_hits:
            vuln_score += 10   # strongest possible signal: real-world active exploitation

    vuln_score = min(vuln_score, 25)

    # ── 4. Final score + tier ──────────────────────────────────────────────────
    raw   = inet_score + svc_score + vuln_score
    score = min(100, round(raw * multiplier))

    tier, tier_color, tier_bg = "Low", "#3fb950", "#0d2a1a"
    for threshold, t_name, t_color, t_bg in TIERS:
        if score >= threshold:
            tier, tier_color, tier_bg = t_name, t_color, t_bg
            break

    # ── 5. Human-readable explanation ─────────────────────────────────────────
    factors: list[str] = []
    if boundary_device:
        factors.append("Network boundary device (Router/Gateway)")
    elif exposure_risk and inet_signals:
        top = ", ".join(inet_signals[:3])
        factors.append(f"Exposure risk {inet_score}/40 — {top} (inferred, not confirmed external)")
    if services:
        src = f"{len(netstat_ports)} netstat-confirmed port(s)" if netstat_ports else "SYN scan"
        factors.append(f"Services {svc_score}/35 via {src} — {', '.join(services[:3])}")
    if critical_n or high_n:
        factors.append(f"Vuln risk {vuln_score}/25 — {critical_n} Critical / {high_n} High")
    if max_epss >= 0.1:
        factors.append(f"EPSS {max_epss:.1%} exploitation probability")
    if kev_hits:
        factors.append(f"CISA KEV: {len(kev_hits)} CVE(s) confirmed actively exploited — {', '.join(kev_hits[:3])}")
    if multiplier > 1.0:
        factors.append(f"Device-type multiplier ×{multiplier:.1f} ({nature})")

    return CriticalityResult(
        score=score,
        tier=tier,
        tier_color=tier_color,
        tier_bg=tier_bg,
        boundary_device=boundary_device,
        exposure_risk=exposure_risk,
        netstat_ports=sorted(netstat_ports),
        inet_score=inet_score,
        svc_score=svc_score,
        vuln_score=vuln_score,
        kev_cves=kev_hits,
        services=services,
        inet_signals=inet_signals,
        factors=factors,
    )


def assess_all(assets: list[dict], vulns: list[dict], kev_lookup: dict | None = None) -> dict[str, CriticalityResult]:
    """
    Assess all assets.  Groups vulns by host first then calls assess() for each.
    Returns {host_ip: CriticalityResult}.
    """
    host_vuln_map: dict[str, list[dict]] = {}
    for v in vulns:
        for h in (v.get("currently_impacted_hosts") or "").split(";"):
            h = h.strip()
            if h:
                host_vuln_map.setdefault(h, []).append(v)

    return {
        a["host_ip"]: assess(a, host_vuln_map.get(a["host_ip"], []), kev_lookup=kev_lookup)
        for a in assets
    }
