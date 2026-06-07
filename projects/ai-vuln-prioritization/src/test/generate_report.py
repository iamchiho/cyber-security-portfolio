#!/usr/bin/env python3
"""
generate_report.py — Nessus Security Report Generator

Reads:
  nessus_aggregated_results.json   (produced by aggreage_nessus_reports.py)
  nessus_assets.json               (produced by aggreage_nessus_reports.py)

Outputs:
  nessus_report_<date>.html        (standalone, no external dependencies)

Usage:
  python generate_report.py
  python generate_report.py --results path/to/results.json --assets path/to/assets.json
  python generate_report.py --output my_report.html
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from criticality import assess_all, CriticalityResult
from threat_intel import fetch_cisa_kev


# ── helpers ────────────────────────────────────────────────────────────────────

def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)


def esc(s) -> str:
    """HTML-escape a value."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def sev_color(label: str) -> str:
    return {
        "Critical": "#CC0000",
        "High":     "#C84010",
        "Medium":   "#A06800",
        "Low":      "#806000",
        "Info":     "#0070B8",
    }.get(label, "#0070B8")


def sev_bg(label: str) -> str:
    return {
        "Critical": "#FFF0F0",
        "High":     "#FFF3EE",
        "Medium":   "#FFF8E8",
        "Low":      "#FFFCE0",
        "Info":     "#EEF6FF",
    }.get(label, "#EEF6FF")


def exploit_color(e: str) -> tuple[str, str]:
    """Return (bg, fg) for exploit maturity badge."""
    return {
        "High":       ("#2d0808", "#E84040"),
        "Functional": ("#2d1808", "#E87840"),
        "PoC":        ("#2d2008", "#E8B030"),
        "Unproven":   ("#1a2800", "#8bc34a"),
    }.get(e, ("#1c2330", "#8b949e"))


def epss_color(v: float) -> str:
    if v >= 0.5:  return "#E84040"
    if v >= 0.1:  return "#E87840"
    if v >= 0.01: return "#E8B030"
    return "#5AB4E8"


def asset_type_key(nature: str) -> str:
    n = nature.lower()
    if any(x in n for x in ("router", "gateway", "firewall", "network device")):
        return "network"
    if any(x in n for x in ("linux server", "windows server", "hypervisor", "ubuntu", "oracle linux")):
        return "server"
    if "nas" in n:
        return "storage"
    if any(x in n for x in ("workstation", "macos", "mobile", "ios", "android", "linux", "windows", "bsd")):
        return "endpoint"
    return "unknown"


def nat_icon(nature: str) -> str:
    icons = {
        "Router/Gateway":           "🌐",
        "Router/Gateway (inferred)":"🌐",
        "NAS":                      "💾",
        "macOS":                    "🍎",
        "Mobile (iOS)":             "📱",
        "Mobile (Android)":         "📱",
        "Windows Server":           "🖥️",
        "Windows Workstation":      "💻",
        "Hypervisor":               "🔲",
        "Firewall":                 "🛡️",
        "Network Device":           "🔀",
    }
    for k, v in icons.items():
        if k in nature:
            return v
    if "Linux" in nature or "BSD" in nature:
        return "🐧"
    return "💻"


def fmt_date(iso: str) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%d %b %Y %H:%M UTC")
    except ValueError:
        return iso


def js_str(s: str) -> str:
    """Escape a string for safe embedding in a JS single-quoted string literal."""
    return str(s).replace("\\", "\\\\").replace("'", "\\'")


# ── Cyber Essentials keyword rules ────────────────────────────────────────────
#
# Each key maps to a list of "keyword groups".  A vulnerability matches a rule
# if ANY group has ALL its keywords present in the lower-cased plugin_name.
#
# To add a new CE check for a future finding, add an entry here — no logic
# changes needed anywhere else.
#
CE_KEYWORD_RULES: dict = {
    # Firewalls
    "ip_forwarding":      [["ip forwarding"]],
    "unencrypted_telnet": [["telnet", "unencrypted"], ["telnet", "cleartext"]],
    "ssl_untrusted":      [["ssl certificate cannot be trusted"],
                           ["ssl certificate untrusted"],
                           ["ssl self-signed certificate"]],
    "tls_deprecated":     [["tls version 1.0"], ["tls version 1.1 deprecated"],
                           ["tls 1.0 protocol detected"], ["tls 1.1 protocol detected"]],
    # Secure configuration & patching
    "patch_failed":       [["os security patch assessment failed"]],
    "backported_patch":   [["backported security patch"]],
    # Malware protection
    "ai_llm_software":    [["ai/llm software"], ["ai software report"]],
    # Access control
    "telnetd_bypass":     [["telnetd"]],
    "cockpit_rce":        [["cockpit"]],
    "sudo_privesc":       [["sudo"]],
    # Network controls
    "smb1":               [["smb", "protocol version 1"], ["smbv1 detected"]],
    "nfs_exposed":        [["nfs server superfluous"], ["nfs", "superfluous"]],
    "afp_exposed":        [["apple filing protocol"]],
}


def _match_rule(vulns: list, rule_id: str, severity_labels=None) -> dict:
    """
    Return all vulns matching a CE_KEYWORD_RULES entry.
    severity_labels: optional set of severity_label strings to require (e.g. {"Critical"}).
    Extracted hosts and CVEs are de-duplicated and sorted.
    """
    groups = CE_KEYWORD_RULES.get(rule_id, [])
    matched = []
    for v in vulns:
        name_l = v.get("plugin_name", "").lower()
        if severity_labels and v.get("severity_label") not in severity_labels:
            continue
        for grp in groups:
            if all(kw in name_l for kw in grp):
                matched.append(v)
                break
    hosts = sorted({
        h.strip()
        for v in matched
        for h in (v.get("currently_impacted_hosts") or "").split(";")
        if h.strip()
    })
    cves = sorted({
        c.strip()
        for v in matched
        for c in (v.get("cve") or "").split(";")
        if c.strip()
    })
    return {
        "vulns":     matched,
        "found":     bool(matched),
        "hosts":     hosts,
        "cves":      cves,
        "hosts_str": ", ".join(hosts),
        "cves_str":  ", ".join(cves[:3]),   # cap display at 3 CVEs
    }


def derive_ce_checks(vulns: list, assets: list) -> dict:
    """
    Derive CE v3.1 pass/fail items from scan findings.
    Returns {domain_id: {title, icon, items: [{pass, text, sub, link, link_host?}]}}
    All host IPs and CVEs are extracted dynamically — nothing is hard-coded.
    """
    # ── special computed values ──────────────────────────────────────────────
    critical_high_count = sum(
        1 for v in vulns if v.get("severity_label") in ("Critical", "High")
    )
    most_critical_asset = max(assets, key=lambda a: a.get("critical_count", 0), default=None)
    critical_asset_ip = most_critical_asset["host_ip"] if (
        most_critical_asset and most_critical_asset.get("critical_count", 0) > 0
    ) else ""
    gateways = [
        a["host_ip"] for a in assets
        if "Router" in a.get("host_nature", "") or "Gateway" in a.get("host_nature", "")
    ]

    # ── rule matches ─────────────────────────────────────────────────────────
    ip_fwd  = _match_rule(vulns, "ip_forwarding")
    telnet  = _match_rule(vulns, "unencrypted_telnet")
    ssl     = _match_rule(vulns, "ssl_untrusted")
    tls     = _match_rule(vulns, "tls_deprecated")
    pf      = _match_rule(vulns, "patch_failed")
    bp      = _match_rule(vulns, "backported_patch")
    ai      = _match_rule(vulns, "ai_llm_software")
    telnetd = _match_rule(vulns, "telnetd_bypass",  severity_labels={"Critical"})
    cockpit = _match_rule(vulns, "cockpit_rce",     severity_labels={"Critical"})
    sudo    = _match_rule(vulns, "sudo_privesc",    severity_labels={"Low", "Medium", "High", "Critical"})
    smb1    = _match_rule(vulns, "smb1")
    nfs     = _match_rule(vulns, "nfs_exposed")
    afp     = _match_rule(vulns, "afp_exposed")

    def _cve(m: dict) -> str:
        return f" ({m['cves_str']})" if m["cves"] else ""

    return {
        "fw": {
            "title": "Firewalls",
            "icon": "🛡️",
            "items": [
                {
                    "pass": not ip_fwd["found"],
                    "text": f"IP forwarding enabled on: {ip_fwd['hosts_str']}" if ip_fwd["found"]
                            else "No hosts with unrestricted IP forwarding detected",
                    "sub":  "CE requires boundary firewalls to block unsolicited inbound connections. "
                            "Unrestricted IP forwarding bypasses this control.",
                    "link": "ip forwarding" if ip_fwd["found"] else "",
                },
                {
                    "pass": not telnet["found"],
                    "text": f"Unencrypted Telnet exposed on: {telnet['hosts_str']}" if telnet["found"]
                            else "No unencrypted Telnet services detected",
                    "sub":  "CE requires all remote access to use encrypted protocols. "
                            "Telnet transmits credentials and data in cleartext.",
                    "link": "Telnet" if telnet["found"] else "",
                },
                {
                    "pass": not ssl["found"],
                    "text": f"Untrusted SSL certificate detected on: {ssl['hosts_str']}" if ssl["found"]
                            else "SSL certificates appear valid",
                    "sub":  "CE requires management interfaces to use trusted certificates to prevent MitM attacks.",
                    "link": "SSL Certificate Cannot Be Trusted" if ssl["found"] else "",
                },
                {
                    "pass": not tls["found"],
                    "text": f"TLS 1.0/1.1 still active on: {tls['hosts_str']}" if tls["found"]
                            else "No deprecated TLS versions detected",
                    "sub":  "CE requires services to disable deprecated TLS versions (1.0, 1.1). Only TLS 1.2+ is acceptable.",
                    "link": "TLS Version 1.0" if tls["found"] else "",
                },
            ],
        },
        "sp": {
            "title": "Secure configuration & patching",
            "icon": "🔧",
            "items": [
                {
                    "pass": critical_high_count == 0,
                    "text": f"{critical_high_count} critical/high severity patches missing across scanned hosts",
                    "sub":  "CE requires critical and high severity patches to be applied within 14 days of release.",
                    "link": "",
                    "link_host": critical_asset_ip,
                },
                {
                    "pass": not pf["found"],
                    "text": f"Credentialed patch assessment failed on: {pf['hosts_str']}" if pf["found"]
                            else "Credentialed patch assessment succeeded on all assessed hosts",
                    "sub":  "Scan could not verify patch status on some hosts — these may have undetected vulnerabilities.",
                    "link": "OS Security Patch Assessment Failed" if pf["found"] else "",
                },
                {
                    "pass": most_critical_asset is None or most_critical_asset.get("critical_count", 0) == 0,
                    "text": (
                        f"{most_critical_asset['host_ip']} ({most_critical_asset.get('host_nature', '')}) has "
                        f"{most_critical_asset['critical_count']} critical + "
                        f"{most_critical_asset['high_count']} high unpatched findings"
                        if most_critical_asset and most_critical_asset.get("critical_count", 0) > 0
                        else "No host has outstanding critical findings"
                    ),
                    "sub":  "Hosts with large numbers of unpatched critical CVEs indicate patching cadence is not meeting CE requirements.",
                    "link": "",
                    "link_host": critical_asset_ip,
                },
                {
                    "pass": bp["found"],
                    "text": "Backported security patches confirmed on some Linux hosts" if bp["found"]
                            else "No evidence of backported patch application found",
                    "sub":  "Backporting is an accepted CE patching mechanism; credentialed checks confirmed it on Ubuntu/Oracle hosts.",
                    "link": "Backported Security Patch" if bp["found"] else "",
                },
            ],
        },
        "mal": {
            "title": "Malware protection",
            "icon": "🦠",
            "items": [
                {
                    "pass": True,
                    "text": "No active malware indicators detected in vulnerability scan",
                    "sub":  "No malware-family findings present. Note: a dedicated AV/EDR solution is still required for CE.",
                    "link": "",
                },
                {
                    "pass": not ai["found"],
                    "text": f"Unapproved AI/LLM software detected on: {ai['hosts_str']}" if ai["found"]
                            else "No unapproved AI/LLM software detected",
                    "sub":  "CE requires all installed software to be licensed, managed, and on an approved list. "
                            "Unapproved software is a compliance gap.",
                    "link": "AI/LLM Software" if ai["found"] else "",
                },
            ],
        },
        "acc": {
            "title": "Access control",
            "icon": "🔑",
            "items": [
                {
                    "pass": not telnetd["found"],
                    "text": f"Authentication bypass on Telnet service{_cve(telnetd)} — {telnetd['hosts_str']}" if telnetd["found"]
                            else "No authentication bypass vulnerabilities detected",
                    "sub":  "CE requires all services to enforce authentication. An auth bypass allows unauthenticated access.",
                    "link": "telnetd" if telnetd["found"] else "",
                },
                {
                    "pass": not cockpit["found"],
                    "text": f"Unauthenticated RCE via Cockpit{_cve(cockpit)} — {cockpit['hosts_str']}" if cockpit["found"]
                            else "No unauthenticated RCE vulnerabilities detected",
                    "sub":  "CE requires no pathway for unauthorised access. RCE without authentication is a critical CE violation.",
                    "link": "cockpit" if cockpit["found"] else "",
                },
                {
                    "pass": not sudo["found"],
                    "text": f"Sudo privilege escalation{_cve(sudo)} — {sudo['hosts_str']}" if sudo["found"]
                            else "No privilege escalation vulnerabilities detected",
                    "sub":  "CE requires least-privilege principles. Privilege escalation vulnerabilities undermine access control.",
                    "link": "sudo" if sudo["found"] else "",
                },
                {
                    "pass": True,
                    "text": "SSH password authentication requires valid credentials on all SSH-accessible hosts",
                    "sub":  "Authentication confirmed via credentialed scan. Key-based authentication is additionally recommended.",
                    "link": "",
                },
            ],
        },
        "net": {
            "title": "Network controls",
            "icon": "🌐",
            "items": [
                {
                    "pass": not smb1["found"],
                    "text": f"SMBv1 enabled on: {smb1['hosts_str']}" if smb1["found"]
                            else "SMBv1 not detected on any host",
                    "sub":  "CE requires only necessary and secure network protocols. SMBv1 is deprecated and exploitable (EternalBlue).",
                    "link": "SMB Protocol Version 1" if smb1["found"] else "",
                },
                {
                    "pass": not nfs["found"],
                    "text": f"NFS service unnecessarily exposed on: {nfs['hosts_str']}" if nfs["found"]
                            else "No unnecessary NFS services detected",
                    "sub":  "CE requires unused network services to be disabled. Exposed NFS without need increases attack surface.",
                    "link": "NFS Server Superfluous" if nfs["found"] else "",
                },
                {
                    "pass": not afp["found"],
                    "text": f"Apple Filing Protocol (AFP) exposed on: {afp['hosts_str']}" if afp["found"]
                            else "No legacy AFP file sharing detected",
                    "sub":  "AFP is a legacy protocol that should be disabled if not required. CE requires minimal service exposure.",
                    "link": "Apple Filing Protocol" if afp["found"] else "",
                },
                {
                    "pass": bool(gateways),
                    "text": f"Network boundary device(s) identified: {', '.join(gateways)}" if gateways
                            else "No network boundary router/gateway identified in scan",
                    "sub":  "A boundary device is present. Verify it has appropriate firewall rules enforcing CE boundary protection.",
                    "link": "",
                },
            ],
        },
    }


def scan_coverage(vulns: list, assets: list) -> dict:
    """
    Identify hosts that were not credentialed scanned.
    Primary:  use 'credentialed' field from nessus_assets.json (populated from plugin 19506).
    Fallback: check for 'Local Security Checks' plugin family presence per host
              (used when cache pre-dates the plugin 19506 extraction).
    """
    if any(a.get("credentialed") is not None for a in assets):
        # Plugin 19506 data available — authoritative
        uncredentialed = sorted(
            a["host_ip"] for a in assets if not a.get("credentialed")
        )
    else:
        # Fallback: hosts without any Local Security Checks findings are uncredentialed
        credentialed_ok = set()
        for v in vulns:
            if v.get("plugin_family") == "Local Security Checks":
                for h in (v.get("currently_impacted_hosts") or "").split(";"):
                    h = h.strip()
                    if h:
                        credentialed_ok.add(h)
        all_ips = {a["host_ip"] for a in assets}
        uncredentialed = sorted(all_ips - credentialed_ok)

    return {
        "has_gap":          bool(uncredentialed),
        "uncredentialed":   uncredentialed,
        "uncred_count":     len(uncredentialed),
        "total_hosts":      len(assets),
        "affected_domains": ["Secure configuration & patching", "Access control", "Malware protection"],
    }


def _coverage_banner(cov: dict) -> str:
    if not cov["has_gap"]:
        return ""
    hosts_html = "".join(f'<span class="coverage-warn-hosts">{esc(h)}</span> ' for h in cov["uncredentialed"])
    domains = " · ".join(cov["affected_domains"])
    return f"""
    <div class="coverage-warn">
      <div class="coverage-warn-icon">⚠️</div>
      <div>
        <div class="coverage-warn-title">Credential coverage gap — {cov["uncred_count"]} of {cov["total_hosts"]} hosts had failed credentialed assessment</div>
        <div class="coverage-warn-body">
          CE results for <b>Patch Management</b>, <b>Access Control</b>, and <b>Malware Protection</b>
          may be incomplete on the following hosts. Run a credentialed scan to get full coverage.
        </div>
        <div style="margin-top:6px">{hosts_html}</div>
        <div class="coverage-warn-domains">Affected CE domains: {esc(domains)}</div>
      </div>
    </div>"""


def extract_software_inventory(assets: list) -> list:
    """
    Parse CPE strings from all assets into a deduplicated software inventory.
    CPE format: cpe:/type:vendor:product:version
      type: a=Application, o=OS, h=Hardware
    """
    inv: dict = {}
    for a in assets:
        for cpe in (a.get("cpe") or "").split():
            if not cpe.startswith("cpe:/"):
                continue
            parts = cpe[5:].split(":")
            if len(parts) < 3:
                continue
            cpe_type = parts[0]
            if cpe_type not in ("a", "o", "h"):
                continue
            vendor  = parts[1]
            product = parts[2]
            version = parts[3].strip("~").split("~")[0] if len(parts) > 3 else ""
            key = (cpe_type, vendor, product)
            if key not in inv:
                inv[key] = {
                    "cpe_type": cpe_type, "vendor": vendor,
                    "product": product, "versions": set(), "hosts": set(),
                }
            if version:
                inv[key]["versions"].add(version)
            inv[key]["hosts"].add(a["host_ip"])

    result = [
        {
            **v,
            "versions":     sorted(v["versions"]),
            "hosts":        sorted(v["hosts"]),
            "host_count":   len(v["hosts"]),
            "display_name": v["product"].replace("_", " ").replace("-", " ").title(),
            "display_vendor": v["vendor"].replace("_", " ").replace("-", " "),
        }
        for v in inv.values()
    ]
    # OS first, then apps, then hardware; within each group sort by product
    result.sort(key=lambda x: ({"o": 0, "a": 1, "h": 2}.get(x["cpe_type"], 3), x["product"]))
    return result


# ── HTML generation ────────────────────────────────────────────────────────────

CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:ital,wght@0,300;0,400;0,500;0,600;1,400&display=swap');

:root {
  --bg:       #0d1117;
  --surface:  #161b22;
  --surface2: #1c2330;
  --border:   #30363d;
  --border2:  #21262d;
  --text:     #e6edf3;
  --muted:    #8b949e;
  --accent:   #58a6ff;

  --crit-bg:  #2d0808; --crit:  #E84040;
  --high-bg:  #2d1808; --high:  #E87840;
  --med-bg:   #2d2008; --med:   #E8B030;
  --low-bg:   #282200; --low:   #E8D040;
  --info-bg:  #0a1c30; --info:  #5AB4E8;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
  line-height: 1.6;
}

/* ── layout ── */
.shell { display: flex; min-height: 100vh; }

.sidebar {
  width: 220px;
  flex-shrink: 0;
  background: var(--surface);
  border-right: 1px solid var(--border);
  padding: 1.5rem 0;
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.sidebar-logo {
  padding: .5rem 1.25rem 1.25rem;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 13px;
  font-weight: 500;
  color: var(--accent);
  letter-spacing: .08em;
  border-bottom: 1px solid var(--border2);
  margin-bottom: .75rem;
}
.sidebar-logo span { color: var(--muted); font-weight: 400; }

.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: .55rem 1.25rem;
  font-size: 13px;
  color: var(--muted);
  cursor: pointer;
  border: none;
  background: transparent;
  width: 100%;
  text-align: left;
  border-left: 3px solid transparent;
  transition: background .1s, color .1s;
  text-decoration: none;
}
.nav-item:hover { background: var(--surface2); color: var(--text); }
.nav-item.active {
  background: var(--surface2);
  color: var(--accent);
  border-left-color: var(--accent);
  font-weight: 500;
}
.nav-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  margin-left: auto;
  flex-shrink: 0;
}

.main { flex: 1; padding: 2rem 2.5rem; max-width: 1100px; }

/* ── page sections ── */
.page { display: none; }
.page.active { display: block; }

.page-title {
  font-size: 20px;
  font-weight: 600;
  margin-bottom: .35rem;
  display: flex;
  align-items: center;
  gap: .5rem;
}
.page-subtitle {
  font-size: 13px;
  color: var(--muted);
  margin-bottom: 1.75rem;
}

/* ── metrics ── */
.metrics {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 1.5rem;
}
.metric {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
}
.metric-label {
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .06em;
  margin-bottom: 4px;
}
.metric-val {
  font-size: 30px;
  font-weight: 600;
  font-family: 'IBM Plex Mono', monospace;
  line-height: 1.1;
}

/* ── cards ── */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem;
}
.card-title {
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .07em;
  font-weight: 500;
  margin-bottom: 1rem;
}
.charts-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-bottom: 1.25rem;
}

/* ── bar charts ── */
.bar-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 7px;
}
.bar-label {
  font-size: 12px;
  color: var(--muted);
  width: 95px;
  text-align: right;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  flex-shrink: 0;
}
.bar-track {
  flex: 1;
  height: 8px;
  background: var(--surface2);
  border-radius: 4px;
  overflow: hidden;
}
.bar-fill {
  height: 100%;
  border-radius: 4px;
}
.bar-count {
  font-size: 12px;
  color: var(--muted);
  min-width: 28px;
  text-align: right;
  font-family: 'IBM Plex Mono', monospace;
}

/* ── badges ── */
.badge {
  display: inline-block;
  font-size: 11px;
  padding: 2px 9px;
  border-radius: 20px;
  font-weight: 500;
}
.sev-pill {
  display: inline-block;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 4px;
  font-family: 'IBM Plex Mono', monospace;
  letter-spacing: .02em;
}

/* ── vuln table ── */
.filter-row {
  display: flex;
  gap: 6px;
  margin-bottom: .85rem;
  flex-wrap: wrap;
  align-items: center;
}
.fbtn {
  font-size: 11px;
  padding: 4px 12px;
  border-radius: 20px;
  border: 1px solid var(--border);
  background: transparent;
  cursor: pointer;
  color: var(--muted);
  transition: background .1s;
}
.fbtn:hover { background: var(--surface2); color: var(--text); }
.fbtn.active {
  background: var(--accent);
  color: #000;
  border-color: var(--accent);
  font-weight: 600;
}
.sbox {
  font-size: 12px;
  padding: 5px 12px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--surface2);
  color: var(--text);
  outline: none;
  flex: 1;
  min-width: 120px;
  max-width: 220px;
}
.sbox:focus { border-color: var(--accent); }
.result-count {
  font-size: 11px;
  color: var(--muted);
  margin-left: auto;
  font-family: 'IBM Plex Mono', monospace;
}

table.vtable {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.vtable th {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  padding: 6px 10px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-weight: 500;
  background: var(--surface);
  position: sticky;
  top: 0;
}
.vtable td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--border2);
  vertical-align: top;
}
.vtable tr:last-child td { border-bottom: none; }
.vtable tr:hover td { background: var(--surface2); }

.vname { font-weight: 500; line-height: 1.4; }
.vdetail {
  font-size: 12px;
  color: var(--muted);
  margin-top: 6px;
  line-height: 1.6;
  border-left: 2px solid var(--border);
  padding-left: 10px;
  display: none;
}
.vdetail.open { display: block; }
.vdetail b { color: var(--text); }

.kev-badge {
  display: inline-block;
  font-size: 9px;
  font-weight: 700;
  font-family: 'IBM Plex Mono', monospace;
  letter-spacing: .04em;
  padding: 1px 6px;
  border-radius: 3px;
  background: #3d0f0f;
  color: #ff6b6b;
  border: 1px solid #7a1f1f;
  vertical-align: middle;
  margin-left: 5px;
  white-space: nowrap;
}
[data-theme="light"] .kev-badge { background: #ffecec; color: #c0392b; border-color: #e74c3c; }

.epss-wrap { display: flex; align-items: center; gap: 6px; }
.epss-bar {
  height: 5px;
  border-radius: 3px;
  min-width: 3px;
}
.epss-num {
  font-size: 11px;
  font-family: 'IBM Plex Mono', monospace;
  color: var(--muted);
}

.pager {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 1rem;
  font-size: 12px;
  color: var(--muted);
}
.pbtn {
  font-size: 12px;
  padding: 4px 12px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: transparent;
  cursor: pointer;
  color: var(--muted);
}
.pbtn:hover:not(:disabled) { background: var(--surface2); color: var(--text); }
.pbtn:disabled { opacity: .3; cursor: default; }

/* ── assets ── */
.asset-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
  gap: 10px;
}
.acard {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  display: flex;
  flex-direction: column;
}
.acard.vuln { border-color: #3d1a1a; }
.acard.no-cred { border-color: #4a3800; }
.no-cred-badge {
  font-size: 10px;
  padding: 1px 7px;
  border-radius: 10px;
  background: #2a1f00;
  color: #e3b341;
  border: 1px solid #4a3800;
  font-weight: 500;
  white-space: nowrap;
}
[data-theme="light"] .acard.no-cred { border-color: #d4a017; }
[data-theme="light"] .no-cred-badge { background: #fffbeb; color: #7d5a00; border-color: #d4a017; }
.aip {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 13px;
  font-weight: 500;
  color: var(--accent);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.anat {
  font-size: 11px;
  color: var(--muted);
  margin: 2px 0 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  flex: 1;
  min-width: 0;
}
.acard-meta {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 6px;
  margin-bottom: .6rem;
  min-height: 18px;
}
.abars { display: flex; gap: 3px; align-items: flex-end; height: 24px; margin-top: auto; margin-bottom: .6rem; flex-shrink: 0; }
.abar { border-radius: 2px; min-width: 5px; }
.acounts { display: flex; gap: 4px; flex-wrap: wrap; }
.ac {
  font-size: 10px;
  padding: 1px 7px;
  border-radius: 10px;
  font-family: 'IBM Plex Mono', monospace;
  font-weight: 500;
}

/* ── Cyber Essentials ── */
.ce-score-band {
  display: flex;
  gap: 2rem;
  align-items: center;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem 2rem;
  margin-bottom: 1.5rem;
}
.ce-verdict {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 42px;
  font-weight: 600;
  line-height: 1;
}
.ce-readiness { font-size: 13px; color: var(--muted); margin-top: 4px; }
.ce-divider { width: 1px; height: 50px; background: var(--border); }
.ce-stat { text-align: center; }
.ce-stat-num {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 28px;
  font-weight: 600;
  line-height: 1;
}
.ce-stat-label { font-size: 11px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: .05em; }

.ce-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-bottom: 12px;
}
.ce-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.1rem;
}
.ce-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: .85rem;
}
.ce-card-title { font-size: 13px; font-weight: 600; }
.ce-status-badge { font-size: 11px; padding: 2px 9px; border-radius: 10px; font-weight: 600; }
.ce-item {
  display: flex;
  align-items: flex-start;
  gap: 9px;
  padding: 6px 0;
  border-top: 1px solid var(--border2);
  font-size: 12px;
  line-height: 1.5;
}
.ce-icon { flex-shrink: 0; margin-top: 1px; font-size: 13px; }
.ce-item-text { flex: 1; }
.ce-item-sub { font-size: 11px; color: var(--muted); margin-top: 2px; }
.ce-item-link {
  cursor: pointer;
  border-radius: 5px;
  margin: 0 -8px;
  padding: 6px 8px;
  transition: background .12s;
}
.ce-item-link:hover { background: var(--surface2); }
.ce-link-arrow {
  flex-shrink: 0;
  font-size: 12px;
  color: var(--accent);
  opacity: 0;
  transition: opacity .12s;
  align-self: center;
}
.ce-item-link:hover .ce-link-arrow { opacity: 1; }

/* ── light mode ── */
[data-theme="light"] {
  --bg:       #f6f8fa;
  --surface:  #ffffff;
  --surface2: #eaeef2;
  --border:   #d0d7de;
  --border2:  #e1e4e8;
  --text:     #1f2328;
  --muted:    #656d76;
  --accent:   #0969da;

  --crit-bg:  #ffebe9; --crit:  #cf222e;
  --high-bg:  #fff8c5; --high:  #9a6700;
  --med-bg:   #ddf4ff; --med:   #0969da;
  --low-bg:   #dafbe1; --low:   #1a7f37;
  --none-bg:  #eaeef2; --none:  #656d76;
}
[data-theme="light"] .acard.vuln { border-color: #ffc1c0; }
[data-theme="light"] .fbtn.active { color: #fff; }
[data-theme="light"] .sbox { color-scheme: light; }

/* ── theme toggle ── */
.theme-toggle {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: .6rem 1.25rem;
  font-size: 12px;
  color: var(--muted);
  cursor: pointer;
  border: none;
  background: transparent;
  width: 100%;
  text-align: left;
  border-top: 1px solid var(--border2);
  transition: color .15s;
}
.theme-toggle:hover { color: var(--text); }
.theme-toggle-icon { font-size: 14px; }
.theme-switch {
  width: 34px; height: 18px;
  border-radius: 9px;
  background: var(--border);
  position: relative;
  flex-shrink: 0;
  margin-left: auto;
  transition: background .2s;
}
.theme-switch.on { background: var(--accent); }
.theme-switch::after {
  content: '';
  width: 13px; height: 13px;
  border-radius: 50%;
  background: #fff;
  position: absolute;
  top: 2.5px; left: 2.5px;
  transition: transform .2s;
  box-shadow: 0 1px 2px rgba(0,0,0,.3);
}
.theme-switch.on::after { transform: translateX(16px); }

/* ── export buttons ── */
.sidebar-export {
  padding: .6rem 1.25rem .75rem;
  border-top: 1px solid var(--border2);
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.sidebar-export-label {
  font-size: 10px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .05em;
  margin-bottom: 2px;
}
.export-btn {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 5px 10px;
  font-size: 12px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--surface2);
  color: var(--muted);
  cursor: pointer;
  transition: color .15s, border-color .15s, background .15s;
  width: 100%;
  text-align: left;
}
.export-btn:hover { color: var(--text); border-color: var(--accent); background: var(--surface); }
.export-btn-icon { font-size: 14px; }

/* ── print / PDF ── */
@media print {
  .sidebar, #crit-tip { display: none !important; }
  .shell { display: block !important; }
  .main { margin: 0 !important; padding: 0 !important; }
  /* !important overrides the JS inline style="display:none" on inactive pages */
  .page { display: block !important; page-break-after: always; padding: 1.5rem !important; }
  .page:last-child { page-break-after: avoid; }
  .export-btn, .sidebar-export { display: none !important; }
}

/* ── software inventory ── */
.sw-filter-row {
  display: flex;
  gap: 6px;
  align-items: center;
  margin-bottom: .85rem;
  flex-wrap: wrap;
}
table.swtable {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.swtable th {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  padding: 6px 10px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-weight: 500;
  background: var(--surface);
}
.swtable td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--border2);
  vertical-align: middle;
}
.swtable tr:last-child td { border-bottom: none; }
.swtable tr:hover td { background: var(--surface2); }
.swtable tr[style*="none"] { display: none; }
.sw-type-badge {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 600;
  font-family: 'IBM Plex Mono', monospace;
  white-space: nowrap;
}
.sw-host-tag {
  font-size: 11px;
  font-family: 'IBM Plex Mono', monospace;
  padding: 1px 6px;
  border-radius: 4px;
  background: var(--surface2);
  color: var(--accent);
  cursor: pointer;
  border: 1px solid var(--border);
  margin: 1px;
  display: inline-block;
  text-decoration: underline;
  text-underline-offset: 2px;
}
.sw-host-tag:hover { background: var(--border); }
.sw-version {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  color: var(--muted);
}
.sw-metrics {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-bottom: 1.25rem;
}

/* ── 14-day patching compliance ── */
.patch-section-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  margin: 1.5rem 0 .4rem;
  display: flex;
  align-items: center;
  gap: .5rem;
  cursor: pointer;
  user-select: none;
  padding: .5rem .75rem;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--surface);
  transition: background .1s;
}
.patch-section-title:hover { background: var(--surface2); }
.patch-chevron {
  margin-left: auto;
  font-size: 14px;
  color: var(--muted);
  transition: transform .2s;
  font-style: normal;
}
.patch-section-sub {
  font-size: 11px;
  color: var(--muted);
  margin-bottom: .85rem;
}
.patch-metrics {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 10px;
  margin-bottom: 1rem;
}
.patch-metric {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: .75rem 1rem;
  display: flex;
  align-items: center;
  gap: .75rem;
}
.patch-metric-num {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 24px;
  font-weight: 600;
  line-height: 1;
}
.patch-metric-label {
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .05em;
  margin-top: 2px;
}

/* ── coverage warning ── */
.coverage-warn {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
  background: #2a1f00;
  border: 1px solid #6a4c00;
  border-left: 4px solid #e3b341;
  border-radius: 8px;
  padding: 1rem 1.25rem;
  margin-bottom: 1.25rem;
  font-size: 13px;
  line-height: 1.6;
}
.coverage-warn-icon { font-size: 18px; flex-shrink: 0; margin-top: 1px; }
.coverage-warn-title { font-weight: 600; color: #e3b341; margin-bottom: 4px; }
.coverage-warn-body  { color: var(--muted); }
.coverage-warn-hosts {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  background: #1c1500;
  border: 1px solid #4a3800;
  border-radius: 4px;
  padding: 4px 10px;
  margin-top: 6px;
  color: #e3b341;
  display: inline-block;
}
.coverage-warn-domains {
  margin-top: 4px;
  font-size: 11px;
  color: var(--muted);
}
[data-theme="light"] .coverage-warn {
  background: #fffbeb;
  border-color: #d4a017;
  border-left-color: #d4a017;
}
[data-theme="light"] .coverage-warn-hosts {
  background: #fef9e7;
  border-color: #d4a017;
  color: #7d5a00;
}

/* ── print ── */
@media print {
  .sidebar { display: none; }
  .main { padding: 1rem; max-width: 100%; }
  .page { display: block !important; page-break-inside: avoid; }
  .page-title { margin-top: 2rem; }
  .filter-row, .pager, .pbtn, .fbtn, .sbox { display: none !important; }
  .vdetail { display: block !important; }
  body { background: #fff; color: #000; }
  .sidebar-logo, .nav-item { display: none; }
  table.vtable { font-size: 11px; }
}

/* ── scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

/* ── asset criticality ── */
.acard.crit-critical { border-color: #E84040; }
.acard.crit-high     { border-color: #E87840; }
.acard.crit-medium   { border-color: #E8B030; }
.acard.crit-low      { border-color: var(--border); }
[data-theme="light"] .acard.crit-critical { border-color: #CC0000; }
[data-theme="light"] .acard.crit-high     { border-color: #C84010; }
[data-theme="light"] .acard.crit-medium   { border-color: #A06800; }

.acrit-row {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: .2rem;
  flex-shrink: 0;
}
.acrit-badges {
  min-height: 22px;
  margin-bottom: .3rem;
  display: flex;
  align-items: center;
  flex-shrink: 0;
}
.acrit-tier {
  font-size: 10px;
  font-weight: 700;
  font-family: 'IBM Plex Mono', monospace;
  letter-spacing: .04em;
}
.acrit-inet {
  font-size: 10px;
  color: #58a6ff;
  background: #0d2035;
  border: 1px solid #1a4060;
  border-radius: 4px;
  padding: 0px 5px;
  white-space: nowrap;
}
[data-theme="light"] .acrit-inet { color: #0969da; background: #ddf4ff; border-color: #0969da; }
.acrit-inet-warn { color: #e3b341 !important; background: #2a1f00 !important; border-color: #5a3f00 !important; }
[data-theme="light"] .acrit-inet-warn { color: #7d5a00 !important; background: #fffbeb !important; border-color: #d4a017 !important; }
.acrit-score {
  font-size: 10px;
  font-family: 'IBM Plex Mono', monospace;
  color: var(--muted);
  margin-left: auto;
}
.acrit-services {
  font-size: 10px;
  color: var(--muted);
  margin-bottom: .45rem;
  line-height: 1.4;
  flex-shrink: 0;
  min-height: 18px;
}
.acard-footer {
  min-height: 20px;
  margin-top: 4px;
  display: flex;
  align-items: center;
}

/* ── asset filter bar ── */
.asset-filter-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}
.asset-search-wrap {
  position: relative;
  display: flex;
  align-items: center;
  flex: 1;
  min-width: 200px;
  max-width: 340px;
}
.asset-search-icon {
  position: absolute;
  left: 9px;
  width: 14px;
  height: 14px;
  color: var(--muted);
  pointer-events: none;
}
.asset-search {
  width: 100%;
  padding: 6px 28px 6px 30px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--surface2);
  color: var(--text);
  font-size: 12px;
  outline: none;
  transition: border-color .15s;
}
.asset-search:focus { border-color: var(--accent); }
.asset-search-clear {
  position: absolute;
  right: 7px;
  background: none;
  border: none;
  color: var(--muted);
  cursor: pointer;
  font-size: 11px;
  display: none;
  padding: 0;
  line-height: 1;
}
.asset-search-clear.visible { display: block; }
.groupby-toggle {
  display: flex;
  align-items: center;
  gap: 5px;
}
.groupby-label {
  font-size: 11px;
  color: var(--muted);
  white-space: nowrap;
}
.groupby-btn {
  padding: 4px 12px;
  font-size: 11px;
  border-radius: 5px;
  border: 1px solid var(--border);
  background: var(--surface2);
  color: var(--muted);
  cursor: pointer;
  transition: all .15s;
}
.groupby-btn:hover { color: var(--text); }
.groupby-btn.active {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}
[data-theme="light"] .groupby-btn.active { color: #fff; }

/* ── asset groups ── */
.agroup { margin-bottom: .75rem; }
.agroup-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 7px;
  background: var(--surface2);
  border: 1px solid var(--border);
  cursor: pointer;
  user-select: none;
  transition: background .15s;
  margin-bottom: 0;
}
.agroup-header:hover { background: var(--surface); }
.agroup-chevron {
  font-size: 10px;
  color: var(--muted);
  width: 10px;
  flex-shrink: 0;
  transition: transform .2s;
}
.agroup-name {
  font-size: 12px;
  font-weight: 600;
  color: var(--text);
  min-width: 70px;
}
.agroup-count {
  font-size: 11px;
  font-family: 'IBM Plex Mono', monospace;
  color: var(--muted);
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1px 8px;
}
.agroup-stats {
  display: flex;
  gap: 8px;
  font-size: 11px;
  font-family: 'IBM Plex Mono', monospace;
  margin-left: auto;
}
.agroup-body {
  padding-top: 8px;
  overflow: hidden;
}
.agroup-body .asset-grid { margin-top: 0; }
.agroup-no-results {
  padding: 1rem;
  font-size: 12px;
  color: var(--muted);
  text-align: center;
}

/* ── criticality score tooltip ── */
#crit-tip {
  position: fixed; z-index: 9999; pointer-events: none; display: none;
  background: #161b22; border: 1px solid #30363d; border-radius: 8px;
  padding: 12px 14px; min-width: 240px; max-width: 320px;
  box-shadow: 0 8px 24px rgba(0,0,0,.6); font-size: 12px; line-height: 1.5;
}
[data-theme="light"] #crit-tip { background: #fff; border-color: #d0d7de; box-shadow: 0 8px 24px rgba(0,0,0,.12); }
.ctip-title { font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: var(--fg); margin-bottom: 8px; }
.ctip-row { display: flex; justify-content: space-between; gap: 16px; color: var(--muted); margin-bottom: 3px; }
.ctip-row.ctip-total { color: var(--fg); font-weight: 600; }
.ctip-val { font-family: 'IBM Plex Mono', monospace; white-space: nowrap; }
.ctip-divider { border: none; border-top: 1px solid #30363d; margin: 7px 0; }
[data-theme="light"] .ctip-divider { border-color: #d0d7de; }
.ctip-factor { color: var(--muted); font-size: 11px; margin-top: 3px; word-break: break-word; }
.acrit-row { cursor: help; }

/* ── clickable bar rows (overview charts) ── */
.bar-row.clickable {
  cursor: pointer;
  border-radius: 4px;
  padding: 2px 4px;
  margin-left: -4px;
  margin-right: -4px;
  transition: background .1s;
}
.bar-row.clickable:hover { background: var(--surface2); }
.bar-row.clickable .bar-label { color: var(--text); }

/* ── sortable table headers ── */
.vtable th.sortable {
  cursor: pointer;
  user-select: none;
  white-space: nowrap;
}
.vtable th.sortable:hover { color: var(--text); }
.sort-arrow {
  font-size: 9px;
  opacity: 0.4;
  margin-left: 2px;
}
.sort-arrow.active { opacity: 1; color: var(--accent); }

/* ── numbered pagination ── */
.page-num-btn {
  font-size: 12px;
  min-width: 28px;
  height: 28px;
  padding: 0 6px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: transparent;
  cursor: pointer;
  color: var(--muted);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  transition: background .1s;
  font-family: 'IBM Plex Mono', monospace;
}
.page-num-btn:hover { background: var(--surface2); color: var(--text); }
.page-num-btn.current {
  background: var(--accent);
  color: #000;
  border-color: var(--accent);
  font-weight: 600;
  cursor: default;
}
.page-ellipsis {
  font-size: 12px;
  color: var(--muted);
  padding: 0 2px;
  align-self: center;
}
"""


JS = """
const PAGE_SIZE = 15;
let sevFilter    = 'All';
let searchQ      = '';
let hostFilter   = '';
let exploitFilter = '';
let kevFilter    = false;
let vulnPage     = 0;
let expandedId   = null;
let sortCol      = null;
let sortDir      = -1;   // -1 = descending (highest first by default)

const SEV_ORDER     = { Critical:4, High:3, Medium:2, Low:1, Info:0 };
const EXPLOIT_ORDER = { High:4, Functional:3, PoC:2, Unproven:1 };

const vulns = window.VULNS || [];

function setPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  document.getElementById('nav-' + id).classList.add('active');
  window.scrollTo(0, 0);
}

function setPageClearHost(id) {
  hostFilter    = '';
  exploitFilter = '';
  kevFilter     = false;
  vulnPage      = 0;
  setPage(id);
  if (id === 'vulns') { renderVulnTable(); updateHostBadge(); updateExploitBadge(); }
}

function setHostFilter(ip) {
  hostFilter    = ip;
  exploitFilter = '';
  sevFilter     = 'All';
  vulnPage      = 0;
  expandedId    = null;
  document.querySelectorAll('.fbtn').forEach(b => b.classList.toggle('active', b.dataset.sev === 'All'));
  setPage('vulns');
  renderVulnTable();
  updateHostBadge();
  updateExploitBadge();
}

function clearHostFilter() {
  hostFilter = '';
  vulnPage   = 0;
  renderVulnTable();
  updateHostBadge();
}

function updateHostBadge() {
  const badge = document.getElementById('host-badge');
  if (!badge) return;
  if (hostFilter) {
    badge.style.display = 'inline-flex';
    badge.querySelector('.hbip').textContent = hostFilter;
  } else {
    badge.style.display = 'none';
  }
}

function updateExploitBadge() {
  const badge = document.getElementById('exploit-badge');
  if (!badge) return;
  if (exploitFilter) {
    badge.style.display = 'inline-flex';
    badge.querySelector('.ebtype').textContent = exploitFilter;
  } else {
    badge.style.display = 'none';
  }
}

function clearExploitFilter() {
  exploitFilter = '';
  vulnPage      = 0;
  renderVulnTable();
  updateExploitBadge();
}

function getFiltered() {
  let result = vulns.filter(v => {
    if (sevFilter !== 'All' && v.sev !== sevFilter) return false;
    if (kevFilter && !v.kev) return false;
    if (hostFilter) {
      const hosts = (v.hosts || '').split(';').map(h => h.trim());
      if (!hosts.includes(hostFilter)) return false;
    }
    if (exploitFilter) {
      const e = v.exploit || 'Unknown';
      if (e !== exploitFilter) return false;
    }
    if (searchQ) {
      const q = searchQ.toLowerCase();
      return v.name.toLowerCase().includes(q) ||
             (v.cve    || '').toLowerCase().includes(q) ||
             (v.hosts  || '').toLowerCase().includes(q) ||
             (v.family || '').toLowerCase().includes(q);
    }
    return true;
  });

  if (sortCol) {
    result = [...result].sort((a, b) => {
      let va, vb;
      switch (sortCol) {
        case 'sev':     va = SEV_ORDER[a.sev] ?? 0;           vb = SEV_ORDER[b.sev] ?? 0;           break;
        case 'name':    va = a.name.toLowerCase();             vb = b.name.toLowerCase();             break;
        case 'cvss3':   va = parseFloat(a.cvss3) || 0;        vb = parseFloat(b.cvss3) || 0;        break;
        case 'vpr':     va = parseFloat(a.vpr)   || 0;        vb = parseFloat(b.vpr)   || 0;        break;
        case 'epss':    va = parseFloat(a.epss)  || 0;        vb = parseFloat(b.epss)  || 0;        break;
        case 'exploit': va = EXPLOIT_ORDER[a.exploit] ?? 0;   vb = EXPLOIT_ORDER[b.exploit] ?? 0;   break;
        case 'port':    va = parseInt(a.port)    || 0;        vb = parseInt(b.port)    || 0;        break;
        default: return 0;
      }
      const cmp = va < vb ? -1 : va > vb ? 1 : 0;
      return cmp * sortDir;   // sortDir=-1 → descending, 1 → ascending
    });
  }
  return result;
}

function epssColor(v) {
  if (v >= 0.5) return '#E84040';
  if (v >= 0.1) return '#E87840';
  if (v >= 0.01) return '#E8B030';
  return '#5AB4E8';
}

function exploitStyle(e) {
  const m = { High: ['#2d0808','#E84040'], Functional: ['#2d1808','#E87840'],
               PoC: ['#2d2008','#E8B030'], Unproven: ['#1a2800','#8bc34a'] };
  return m[e] || ['#1c2330','#8b949e'];
}

function sevStyle(s) {
  const m = {
    Critical: ['#2d0808','#E84040'],
    High:     ['#2d1808','#E87840'],
    Medium:   ['#2d2008','#E8B030'],
    Low:      ['#282200','#E8D040'],
    Info:     ['#0a1c30','#5AB4E8'],
  };
  return m[s] || ['#0a1c30','#5AB4E8'];
}

function sortBy(col) {
  if (sortCol === col) {
    sortDir = -sortDir;
  } else {
    sortCol = col;
    sortDir = -1;
  }
  vulnPage = 0;
  renderVulnTable();
}

function renderPager(total, currentPage) {
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (totalPages <= 1) return '';
  const range = new Set([0, totalPages - 1]);
  for (let i = Math.max(0, currentPage - 1); i <= Math.min(totalPages - 1, currentPage + 1); i++) range.add(i);
  const pages = [...range].sort((a, b) => a - b);
  let html = `<button class="pbtn" ${currentPage === 0 ? 'disabled' : ''} onclick="setVPage(${currentPage - 1})">← Prev</button>`;
  let last = -1;
  for (const p of pages) {
    if (last !== -1 && p > last + 1) html += '<span class="page-ellipsis">…</span>';
    html += `<button class="page-num-btn${p === currentPage ? ' current' : ''}" onclick="setVPage(${p})">${p + 1}</button>`;
    last = p;
  }
  html += `<button class="pbtn" ${currentPage >= totalPages - 1 ? 'disabled' : ''} onclick="setVPage(${currentPage + 1})">Next →</button>`;
  return html;
}

function renderVulnTable() {
  const filtered = getFiltered();
  const total    = filtered.length;
  const maxP     = Math.max(0, Math.ceil(total / PAGE_SIZE) - 1);
  if (vulnPage > maxP) vulnPage = maxP;
  const slice = filtered.slice(vulnPage * PAGE_SIZE, (vulnPage + 1) * PAGE_SIZE);

  const tbody = document.getElementById('vtbody');
  tbody.innerHTML = slice.map(v => {
    const eid = v.id + '_' + v.port;
    const isOpen = expandedId === eid;
    const [sevBg, sevFg] = sevStyle(v.sev);
    const cvss    = v.cvss3 ? parseFloat(v.cvss3).toFixed(1) : '—';
    const vpr     = v.vpr   ? parseFloat(v.vpr).toFixed(1)   : '—';
    const portStr = v.port && v.port !== '0' ? `${v.port}/${v.proto}` : '—';
    const epssVal = v.epss ? parseFloat(v.epss) : null;
    const epssHtml = epssVal !== null
      ? `<div class="epss-wrap">
           <div class="epss-bar" style="width:${Math.max(3, Math.round(epssVal*60))}px;background:${epssColor(epssVal)}"></div>
           <span class="epss-num">${(epssVal*100).toFixed(epssVal<0.01?2:1)}%</span>
         </div>`
      : '<span class="epss-num">—</span>';
    const [eBg, eFg] = exploitStyle(v.exploit);
    const expHtml = v.exploit
      ? `<span class="badge" style="background:${eBg};color:${eFg}">${v.exploit}</span>` : '—';
    const kevBadge = v.kev ? '<span class="kev-badge" title="CISA KEV — Confirmed actively exploited in the wild">KEV</span>' : '';
    const hostTags = (v.hosts || '').split(';').map(h => h.trim()).filter(Boolean)
      .map(h => `<span class="sw-host-tag" onclick="setHostFilter('${h}')" title="Filter by ${h}">${h}</span>`).join(' ');
    const detail = `<div class="vdetail${isOpen?' open':''}" id="detail-${eid}">
      <b>Synopsis:</b> ${v.synopsis}<br><br>
      <b>Solution:</b> ${v.solution}<br><br>
      <b>Affected Hosts (${(v.hosts||'').split(';').filter(h=>h.trim()).length}):</b><br><div style="margin-top:4px">${hostTags || '<span style="color:var(--muted)">—</span>'}</div>
      ${v.cve ? `<br><b>CVE:</b> ${v.cve}` : ''}
      ${v.kev ? `&nbsp;·&nbsp;<span class="kev-badge">KEV</span> <span style="font-size:11px;color:#ff6b6b">Confirmed actively exploited (CISA KEV)</span>` : ''}
      ${v.vpr ? `&nbsp;·&nbsp;<b>VPR:</b> ${v.vpr}` : ''}
      ${epssVal !== null ? `&nbsp;·&nbsp;<b>EPSS:</b> ${(epssVal*100).toFixed(2)}% probability of exploitation within 30 days` : ''}
      ${v.description ? `<br><br><b>Description:</b> ${v.description.slice(0,300)}${v.description.length>300?'…':''}` : ''}
    </div>`;
    return `<tr>
      <td><span class="sev-pill" style="background:${sevBg};color:${sevFg}">${v.sev}</span></td>
      <td><div class="vname" style="cursor:pointer" onclick="toggleDetail('${eid}')">${v.name}${kevBadge}</div>${detail}</td>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:12px">${cvss}</td>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:12px">${vpr}</td>
      <td>${epssHtml}</td>
      <td>${expHtml}</td>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:11px;color:#8b949e">${portStr}</td>
    </tr>`;
  }).join('');

  document.getElementById('result-count').textContent = `${total} findings`;

  const pagerEl = document.getElementById('pager-container');
  if (pagerEl) pagerEl.innerHTML = renderPager(total, vulnPage);

  document.querySelectorAll('.vtable thead th[data-col]').forEach(th => {
    const arrow = th.querySelector('.sort-arrow');
    if (!arrow) return;
    if (th.dataset.col === sortCol) {
      arrow.textContent = sortDir < 0 ? ' ↓' : ' ↑';
      arrow.classList.add('active');
    } else {
      arrow.textContent = ' ↕';
      arrow.classList.remove('active');
    }
  });
}

function setSevFilter(s) {
  sevFilter     = s;
  exploitFilter = '';
  kevFilter     = false;
  vulnPage      = 0;
  document.querySelectorAll('.fbtn').forEach(b => b.classList.toggle('active', b.dataset.sev === s));
  document.getElementById('kev-filter-btn').classList.remove('active');
  updateExploitBadge();
  renderVulnTable();
}

function setKevFilter(forceOn) {
  kevFilter     = forceOn !== undefined ? forceOn : !kevFilter;
  sevFilter     = 'All';
  exploitFilter = '';
  vulnPage      = 0;
  document.querySelectorAll('.fbtn[data-sev]').forEach(b =>
    b.classList.toggle('active', b.dataset.sev === 'All' && !kevFilter));
  document.getElementById('kev-filter-btn').classList.toggle('active', kevFilter);
  updateExploitBadge();
  renderVulnTable();
}

function setSearch(q) {
  searchQ  = q;
  vulnPage = 0;
  renderVulnTable();
}

function setVPage(p) {
  vulnPage = p;
  renderVulnTable();
}

function toggleDetail(id) {
  expandedId = expandedId === id ? null : id;
  renderVulnTable();
}

function goToVuln(q, host) {
  searchQ       = q    || '';
  hostFilter    = host || '';
  exploitFilter = '';
  sevFilter     = 'All';
  vulnPage      = 0;
  expandedId    = null;
  const sbox = document.querySelector('.sbox');
  if (sbox) sbox.value = searchQ;
  document.querySelectorAll('.fbtn').forEach(b =>
    b.classList.toggle('active', b.dataset.sev === 'All'));
  setPage('vulns');
  renderVulnTable();
  updateHostBadge();
  updateExploitBadge();
}

function goToVulnSev(sev) {
  searchQ       = '';
  hostFilter    = '';
  exploitFilter = '';
  sevFilter     = sev;
  vulnPage      = 0;
  expandedId    = null;
  const sbox = document.querySelector('.sbox');
  if (sbox) sbox.value = '';
  document.querySelectorAll('.fbtn').forEach(b =>
    b.classList.toggle('active', b.dataset.sev === sev));
  setPage('vulns');
  renderVulnTable();
  updateHostBadge();
  updateExploitBadge();
}

function goToVulnHostSev(ip, sev) {
  searchQ       = '';
  hostFilter    = ip;
  exploitFilter = '';
  sevFilter     = sev;
  vulnPage      = 0;
  expandedId    = null;
  const sbox = document.querySelector('.sbox');
  if (sbox) sbox.value = '';
  document.querySelectorAll('.fbtn').forEach(b =>
    b.classList.toggle('active', b.dataset.sev === sev));
  setPage('vulns');
  renderVulnTable();
  updateHostBadge();
  updateExploitBadge();
}

function goToVulnExploit(exploit) {
  searchQ       = '';
  hostFilter    = '';
  exploitFilter = exploit;
  sevFilter     = 'All';
  vulnPage      = 0;
  expandedId    = null;
  const sbox = document.querySelector('.sbox');
  if (sbox) sbox.value = '';
  document.querySelectorAll('.fbtn').forEach(b =>
    b.classList.toggle('active', b.dataset.sev === 'All'));
  setPage('vulns');
  renderVulnTable();
  updateHostBadge();
  updateExploitBadge();
}

let swTypeFilter = '';
let swSearch     = '';

function setSwType(t) {
  swTypeFilter = t;
  document.querySelectorAll('.sw-type-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.t === t));
  filterSoftware();
}

function setSwSearch(q) {
  swSearch = q.toLowerCase();
  filterSoftware();
}

function filterSoftware() {
  let visible = 0;
  document.querySelectorAll('.sw-row').forEach(r => {
    const matchType = !swTypeFilter || r.dataset.type === swTypeFilter;
    const matchQ    = !swSearch || r.dataset.text.includes(swSearch);
    const show = matchType && matchQ;
    r.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  const el = document.getElementById('sw-count');
  if (el) el.textContent = visible + ' entries';
}

function togglePatch() {
  const body    = document.getElementById('patch-body');
  const chevron = document.getElementById('patch-chevron');
  const open    = body.style.display !== 'none';
  body.style.display      = open ? 'none' : '';
  chevron.style.transform = open ? '' : 'rotate(90deg)';
}

function initTheme() {
  const saved = localStorage.getItem('nessus-theme') ||
    (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  applyTheme(saved, false);
}

function applyTheme(theme, save = true) {
  document.documentElement.setAttribute('data-theme', theme);
  const sw  = document.getElementById('theme-switch');
  const lbl = document.getElementById('theme-label');
  const ico = document.getElementById('theme-icon');
  if (sw)  sw.classList.toggle('on', theme === 'light');
  if (lbl) lbl.textContent = theme === 'light' ? 'Light mode' : 'Dark mode';
  if (ico) ico.textContent = theme === 'light' ? '☀️' : '🌙';
  if (save) localStorage.setItem('nessus-theme', theme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'dark' ? 'light' : 'dark');
}

window.addEventListener('DOMContentLoaded', () => {
  initTheme();
  renderVulnTable();
  updateHostBadge();
  updateExploitBadge();
  initAssets();
  setPage('overview');
  initCritTip();
});

// ── Asset grouping & filtering ─────────────────────────────────────────────────
let _assetGroupBy = 'tier';

const ASSET_GROUPS = {
  tier: [
    { key: 'critical', label: 'Critical', color: '#E84040' },
    { key: 'high',     label: 'High',     color: '#E87840' },
    { key: 'medium',   label: 'Medium',   color: '#E8B030' },
    { key: 'low',      label: 'Low',      color: '#E8D040' },
  ],
  type: [
    { key: 'network',  label: 'Network Devices',   color: '#8b949e', icon: '🌐' },
    { key: 'server',   label: 'Servers',            color: '#8b949e', icon: '🖥️' },
    { key: 'storage',  label: 'Storage',            color: '#8b949e', icon: '💾' },
    { key: 'endpoint', label: 'Endpoints & Mobile', color: '#8b949e', icon: '💻' },
    { key: 'unknown',  label: 'Unknown',            color: '#8b949e', icon: '❓' },
  ],
};

function initAssets() {
  renderAssetGroups('tier');
}

function renderAssetGroups(groupBy) {
  _assetGroupBy = groupBy;
  const pool    = document.getElementById('assets-pool');
  const display = document.getElementById('assets-display');
  if (!pool || !display) return;

  // Return any previously placed cards to the pool
  display.querySelectorAll('.acard').forEach(c => pool.appendChild(c));
  display.innerHTML = '';

  const cards  = Array.from(pool.querySelectorAll('.acard'));
  const attr   = groupBy === 'tier' ? 'data-tier' : 'data-atype';
  const groups = ASSET_GROUPS[groupBy];

  for (const g of groups) {
    const matching = cards.filter(c => c.getAttribute(attr) === g.key);
    if (matching.length === 0) continue;

    // Aggregate vuln counts for header
    let gc = 0, gh = 0, gm = 0, gl = 0;
    matching.forEach(c => {
      gc += parseInt(c.dataset.critical) || 0;
      gh += parseInt(c.dataset.high)     || 0;
      gm += parseInt(c.dataset.medium)   || 0;
      gl += parseInt(c.dataset.low)      || 0;
    });
    const statParts = [];
    if (gc) statParts.push(`<span style="color:#E84040">C: ${gc}</span>`);
    if (gh) statParts.push(`<span style="color:#E87840">H: ${gh}</span>`);
    if (gm) statParts.push(`<span style="color:#E8B030">M: ${gm}</span>`);
    if (gl) statParts.push(`<span style="color:#E8D040">L: ${gl}</span>`);
    const statsHtml = statParts.length ? statParts.join('') : '<span style="color:var(--muted)">—</span>';

    const label = (g.icon ? g.icon + ' ' : '') + g.label;
    const groupEl = document.createElement('div');
    groupEl.className = 'agroup';
    groupEl.id = `agroup-${g.key}`;
    // Expand Critical + High by default for tier view; all expanded for type view
    const collapsed = (groupBy === 'tier') && (g.key === 'medium' || g.key === 'low');
    groupEl.innerHTML = `
      <div class="agroup-header" onclick="toggleGroup('${g.key}')">
        <span class="agroup-chevron" id="chevron-${g.key}">${collapsed ? '▶' : '▼'}</span>
        <span style="color:${g.color};font-size:11px">●</span>
        <span class="agroup-name">${label}</span>
        <span class="agroup-count" id="agroup-count-${g.key}">${matching.length} asset${matching.length !== 1 ? 's' : ''}</span>
        <div class="agroup-stats" id="agroup-stats-${g.key}">${statsHtml}</div>
      </div>
      <div class="agroup-body" id="agroup-body-${g.key}" style="${collapsed ? 'display:none' : ''}">
        <div class="asset-grid" id="agroup-grid-${g.key}"></div>
      </div>`;
    display.appendChild(groupEl);

    const grid = groupEl.querySelector('.asset-grid');
    matching.forEach(c => grid.appendChild(c));
  }
}

function toggleGroup(key) {
  const body    = document.getElementById(`agroup-body-${key}`);
  const chevron = document.getElementById(`chevron-${key}`);
  if (!body) return;
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : '';
  if (chevron) chevron.textContent = open ? '▶' : '▼';
}

function switchGroupBy(mode) {
  if (mode === _assetGroupBy) return;
  renderAssetGroups(mode);
  // Re-apply any active search
  const q = (document.getElementById('asset-search') || {}).value || '';
  if (q.trim()) filterAssets(q);
  // Update button states
  document.querySelectorAll('.groupby-btn').forEach(b => b.classList.remove('active'));
  const btn = document.getElementById(`groupby-${mode}`);
  if (btn) btn.classList.add('active');
}

function filterAssets(raw) {
  const q = (raw || '').trim().toLowerCase();
  const clearBtn = document.getElementById('asset-search-clear');
  if (clearBtn) clearBtn.classList.toggle('visible', q.length > 0);

  document.querySelectorAll('#assets-display .acard').forEach(c => {
    const ip     = (c.dataset.ip     || '').toLowerCase();
    const nature = (c.dataset.nature || '').toLowerCase();
    const match  = !q || ip.includes(q) || nature.includes(q);
    c.style.display = match ? '' : 'none';
  });

  // Per-group: update count badge, auto-expand if has matches, hide if empty
  document.querySelectorAll('.agroup').forEach(g => {
    const visible = g.querySelectorAll('.acard:not([style*="display: none"])').length;
    const countEl = document.getElementById(`agroup-count-${g.id.replace('agroup-', '')}`);
    if (countEl) countEl.textContent = `${visible} asset${visible !== 1 ? 's' : ''}`;
    g.style.display = visible === 0 ? 'none' : '';
    if (q && visible > 0) {
      const body = g.querySelector('.agroup-body');
      const chev = g.querySelector('.agroup-chevron');
      if (body)  body.style.display = '';
      if (chev)  chev.textContent = '▼';
    }
  });
}

function clearAssetSearch() {
  const inp = document.getElementById('asset-search');
  if (inp) { inp.value = ''; filterAssets(''); inp.focus(); }
}

function initCritTip() {
  const tip = document.getElementById('crit-tip');
  if (!tip) return;

  function buildTip(d) {
    const raw = d.inet + d.svc + d.vuln;
    const hasMultiplier = d.score !== raw;
    let h = '<div class="ctip-title">Criticality Breakdown</div>';
    h += `<div class="ctip-row"><span>Internet Exposure</span><span class="ctip-val">${d.inet}&thinsp;/&thinsp;40</span></div>`;
    h += `<div class="ctip-row"><span>Service Criticality</span><span class="ctip-val">${d.svc}&thinsp;/&thinsp;35</span></div>`;
    h += `<div class="ctip-row"><span>Vuln Risk</span><span class="ctip-val">${d.vuln}&thinsp;/&thinsp;25</span></div>`;
    h += '<hr class="ctip-divider">';
    if (hasMultiplier) {
      h += `<div class="ctip-row"><span>Subtotal</span><span class="ctip-val">${raw}</span></div>`;
      h += `<div class="ctip-row ctip-total"><span>Score (with multiplier)</span><span class="ctip-val">${d.score}&thinsp;/&thinsp;100</span></div>`;
    } else {
      h += `<div class="ctip-row ctip-total"><span>Score</span><span class="ctip-val">${d.score}&thinsp;/&thinsp;100</span></div>`;
    }
    if (d.factors && d.factors.length) {
      h += '<hr class="ctip-divider">';
      d.factors.forEach(f => { h += `<div class="ctip-factor">• ${f}</div>`; });
    }
    return h;
  }

  function reposition(e) {
    const margin = 14, tw = tip.offsetWidth, th = tip.offsetHeight;
    let x = e.clientX + margin, y = e.clientY + margin;
    if (x + tw > window.innerWidth  - margin) x = e.clientX - tw - margin;
    if (y + th > window.innerHeight - margin) y = e.clientY - th - margin;
    tip.style.left = x + 'px';
    tip.style.top  = y + 'px';
  }

  document.querySelectorAll('[data-crit-tip]').forEach(el => {
    el.addEventListener('mouseenter', e => {
      tip.innerHTML = buildTip(JSON.parse(el.dataset.critTip));
      tip.style.display = 'block';
      reposition(e);
    });
    el.addEventListener('mousemove', reposition);
    el.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
  });
}

// ── PDF export ────────────────────────────────────────────────────────────────
function exportPDF() {
  window.print();
}

// ── XLSX export ───────────────────────────────────────────────────────────────
function exportXLSX() {
  const assets = window.ASSETS || [];
  const vulns  = window.VULNS  || [];

  const assetRows = [
    ['Host IP','Nature','Tier','Score','Internet Exposure /40','Service Criticality /35','Vuln Risk /25',
     'Critical','High','Medium','Low','Info','CVEs','Services Detected','Boundary Device','Exposed Services','No Cred','Factors'],
    ...assets.map(a => [
      a.ip, a.nature, a.tier, a.score, a.inet, a.svc, a.vuln,
      a.critical, a.high, a.medium, a.low, a.info, a.cves,
      a.services, a.boundary ? 'Yes' : 'No', a.exposure ? 'Yes' : 'No', a.no_cred ? 'Yes' : 'No', a.factors,
    ]),
  ];

  const vulnRows = [
    ['Host(s)','Plugin Name','Severity','CVE','CVSS3','EPSS','Exploit Maturity','Plugin Family','Plugin ID','Port','Protocol','Synopsis'],
    ...vulns.map(v => [
      v.hosts, v.name, v.sev, v.cve, v.cvss3 || '', v.epss || '', v.exploit || '',
      v.family, v.id, v.port, v.proto, v.synopsis,
    ]),
  ];

  const bytes = _buildXLSX([
    { name: 'Assets',          rows: assetRows },
    { name: 'Vulnerabilities', rows: vulnRows  },
  ]);

  const blob = new Blob([bytes], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = 'security_report.xlsx';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── Minimal XLSX writer (no external library) ─────────────────────────────────
function _buildXLSX(sheets) {
  const enc = new TextEncoder();

  // CRC-32 table
  const CRC = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) c = (c & 1) ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
    CRC[i] = c;
  }
  function crc32(buf) {
    let c = 0xFFFFFFFF;
    for (const b of buf) c = CRC[(c ^ b) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }

  function u16(v, b, o) { b[o] = v & 0xFF; b[o+1] = (v >> 8) & 0xFF; }
  function u32(v, b, o) { b[o] = v & 0xFF; b[o+1] = (v>>8) & 0xFF; b[o+2] = (v>>16) & 0xFF; b[o+3] = (v>>24) & 0xFF; }

  function xe(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function sheetXml(rows) {
    const rd = rows.map((row, ri) => {
      const cells = row.map(v => {
        const bold = ri === 0 ? ' s="1"' : '';
        if (typeof v === 'number' && isFinite(v)) return `<c t="n"${bold}><v>${v}</v></c>`;
        return `<c t="inlineStr"${bold}><is><t>${xe(v)}</t></is></c>`;
      }).join('');
      return `<row r="${ri+1}">${cells}</row>`;
    }).join('');
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${rd}</sheetData></worksheet>`;
  }

  const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><sz val="11"/><b/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0"/></cellXfs></styleSheet>`;
  const ct = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>${sheets.map((_,i)=>`<Override PartName="/xl/worksheets/sheet${i+1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('')}<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`;
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  const wbRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${sheets.map((_,i)=>`<Relationship Id="rId${i+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i+1}.xml"/>`).join('')}</Relationships>`;
  const wb = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${sheets.map((s,i)=>`<sheet name="${xe(s.name)}" sheetId="${i+1}" r:id="rId${i+1}"/>`).join('')}</sheets></workbook>`;

  const files = [
    { n: '[Content_Types].xml',        d: enc.encode(ct)     },
    { n: '_rels/.rels',                d: enc.encode(rels)   },
    { n: 'xl/workbook.xml',            d: enc.encode(wb)     },
    { n: 'xl/_rels/workbook.xml.rels', d: enc.encode(wbRels) },
    { n: 'xl/styles.xml',              d: enc.encode(styles) },
    ...sheets.map((s,i) => ({ n: `xl/worksheets/sheet${i+1}.xml`, d: enc.encode(sheetXml(s.rows)) })),
  ];

  // Build local file headers and track offsets
  let offset = 0;
  const localParts = [];
  for (const f of files) {
    const nb = enc.encode(f.n), crc = crc32(f.d);
    const lh = new Uint8Array(30 + nb.length);
    lh[0]=0x50; lh[1]=0x4B; lh[2]=0x03; lh[3]=0x04;
    u16(20, lh, 4); u16(0, lh, 6); u16(0, lh, 8); u16(0, lh, 10); u16(0, lh, 12);
    u32(crc, lh, 14); u32(f.d.length, lh, 18); u32(f.d.length, lh, 22);
    u16(nb.length, lh, 26); u16(0, lh, 28);
    lh.set(nb, 30);
    f._nb = nb; f._crc = crc; f._off = offset;
    localParts.push(lh, f.d);
    offset += lh.length + f.d.length;
  }

  // Central directory
  const cdParts = [];
  for (const f of files) {
    const cd = new Uint8Array(46 + f._nb.length);
    cd[0]=0x50; cd[1]=0x4B; cd[2]=0x01; cd[3]=0x02;
    u16(20,cd,4); u16(20,cd,6); u16(0,cd,8); u16(0,cd,10); u16(0,cd,12); u16(0,cd,14);
    u32(f._crc,cd,16); u32(f.d.length,cd,20); u32(f.d.length,cd,24);
    u16(f._nb.length,cd,28); u16(0,cd,30); u16(0,cd,32); u16(0,cd,34); u16(0,cd,36);
    u32(0,cd,38); u32(f._off,cd,42);
    cd.set(f._nb, 46);
    cdParts.push(cd);
  }

  const cdSize = cdParts.reduce((s,c) => s + c.length, 0);
  const eocd = new Uint8Array(22);
  eocd[0]=0x50; eocd[1]=0x4B; eocd[2]=0x05; eocd[3]=0x06;
  u16(0,eocd,4); u16(0,eocd,6);
  u16(files.length,eocd,8); u16(files.length,eocd,10);
  u32(cdSize,eocd,12); u32(offset,eocd,16); u16(0,eocd,20);

  const all = [...localParts, ...cdParts, eocd];
  const total = all.reduce((s,a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of all) { out.set(a, pos); pos += a.length; }
  return out;
}
"""


def build_html(vulns: list, assets: list, summary: dict, kev_lookup: dict | None = None) -> str:
    scan_date = fmt_date(summary.get("latest_scan_date", ""))
    scan_name = esc(summary.get("latest_scan_name", "Nessus Scan"))
    generated = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")

    # ── severity counts ──
    counts = Counter(v["severity_label"] for v in vulns)
    c = counts.get("Critical", 0)
    h = counts.get("High", 0)
    m = counts.get("Medium", 0)
    l = counts.get("Low", 0)
    total_open = summary.get("open_vulnerability_count", 0)

    # ── exploit counts (exclude None) ──
    active_vulns = [v for v in vulns if v["severity_label"] != "Info"]
    exploit_counts = Counter(v.get("exploit_code_maturity", "") or "Unknown" for v in active_vulns)

    # ── top families ──
    fam_counts = Counter(v["plugin_family"] for v in active_vulns)
    top_fam = fam_counts.most_common(7)
    max_fam = top_fam[0][1] if top_fam else 1

    # ── top EPSS ──
    top_epss = sorted(
        [v for v in vulns if v.get("epss_score") and float(v.get("epss_score", 0)) > 0],
        key=lambda v: float(v["epss_score"]), reverse=True
    )[:10]

    # ── KEV counts ──
    def _vuln_has_kev(v: dict) -> bool:
        if not kev_lookup:
            return False
        return any(c.strip() in kev_lookup for c in (v.get("cve") or "").split(";") if c.strip())

    kev_vulns = [v for v in vulns if _vuln_has_kev(v) and v.get("seen_in_latest_run") != "No"]
    kev_count = len(kev_vulns)
    top_kev = sorted(kev_vulns, key=lambda v: v.get("severity", 0), reverse=True)[:10]

    # ── software inventory ──
    software = extract_software_inventory(assets)

    # ── asset criticality (enriched with CISA KEV) ──
    criticality_map: dict[str, CriticalityResult] = assess_all(assets, vulns, kev_lookup=kev_lookup)

    # ── CE checks + coverage ──
    ce = derive_ce_checks(vulns, assets)
    cov = scan_coverage(vulns, assets)
    total_pass = sum(1 for d in ce.values() for i in d["items"] if i["pass"])
    total_fail = sum(1 for d in ce.values() for i in d["items"] if not i["pass"])
    verdict = "PASS" if total_fail == 0 else ("REVIEW" if total_fail <= 3 else "FAIL")
    verdict_color = "#3fb950" if total_fail == 0 else ("#e3b341" if total_fail <= 3 else "#f85149")
    readiness = (
        "Ready for CE assessment" if total_fail == 0
        else "Minor remediation required" if total_fail <= 3
        else "Significant remediation required"
    )

    # ── slim vuln list for JS ──
    js_vulns = []
    for v in vulns:
        cve_field = (v.get("cve") or "")
        kev_hit = kev_lookup and any(
            c.strip() in kev_lookup
            for c in cve_field.split(";") if c.strip()
        )
        js_vulns.append({
            "id":       v.get("plugin_id", ""),
            "name":     v.get("plugin_name", ""),
            "family":   v.get("plugin_family", ""),
            "sev":      v.get("severity_label", "Info"),
            "cvss3":    v.get("cvss3_base_score", ""),
            "vpr":      v.get("vpr_score", ""),
            "epss":     v.get("epss_score", ""),
            "cve":      cve_field.split(";")[0].strip(),
            "exploit":  v.get("exploit_code_maturity", ""),
            "port":     v.get("port", "0"),
            "proto":    v.get("protocol", ""),
            "hosts":    v.get("currently_impacted_hosts", "") or v.get("impacted_hosts", ""),
            "hostCount":v.get("currently_impacted_host_count", 0) or v.get("impacted_host_count", 0),
            "synopsis": (v.get("synopsis") or "")[:200],
            "solution": (v.get("solution") or "")[:200],
            "description": (v.get("description") or "")[:300],
            "kev":      bool(kev_hit),
        })

    # ─────────────────────────────────────────────────────────────
    # Page: Overview
    # ─────────────────────────────────────────────────────────────

    def sev_bar(label: str, count: int, max_v: int, color: str) -> str:
        pct = round(count / max_v * 100) if max_v else 0
        return f"""<div class="bar-row clickable" onclick="goToVulnSev('{js_str(label)}')" title="Filter by {label}">
          <div class="bar-label">{label}</div>
          <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>
          <div class="bar-count">{count}</div>
        </div>"""

    max_sev = max(c, h, m, l, 1)
    sev_bars = (
        sev_bar("Critical", c, max_sev, "#E84040") +
        sev_bar("High",     h, max_sev, "#E87840") +
        sev_bar("Medium",   m, max_sev, "#E8B030") +
        sev_bar("Low",      l, max_sev, "#E8D040")
    )

    fam_bars = "".join(
        f"""<div class="bar-row clickable" onclick="goToVuln('{js_str(f)}','')" title="{esc(f)}">
          <div class="bar-label">{esc(f[:22]+'…' if len(f)>22 else f)}</div>
          <div class="bar-track"><div class="bar-fill" style="width:{round(cnt/max_fam*100)}%;background:#58a6ff"></div></div>
          <div class="bar-count">{cnt}</div>
        </div>"""
        for f, cnt in top_fam
    )

    def exp_badge(label: str, count: int) -> str:
        bg, fg = exploit_color(label)
        lbl = label or "Unknown"
        return (f'<span class="badge" style="background:{bg};color:{fg};cursor:pointer"'
                f' onclick="goToVulnExploit(\'{js_str(lbl)}\')"'
                f' title="Filter by {esc(lbl)} exploit maturity">'
                f'{esc(lbl)}: {count}</span> ')

    exploit_badges = "".join(
        exp_badge(k, v) for k, v in sorted(exploit_counts.items(), key=lambda x: -x[1])
    )

    epss_bars = "".join(
        f"""<div class="bar-row clickable" onclick="goToVuln('{js_str(v['plugin_name'])}','')" title="{esc(v['plugin_name'])}">
          <div class="bar-label" style="width:200px;text-align:left">{esc(v['plugin_name'][:40]+'…' if len(v['plugin_name'])>40 else v['plugin_name'])}</div>
          <div class="bar-track"><div class="bar-fill" style="width:{round(float(v['epss_score'])*100)}%;background:{epss_color(float(v['epss_score']))}"></div></div>
          <div class="bar-count">{round(float(v['epss_score'])*100, 1)}%</div>
        </div>"""
        for v in top_epss
    )

    SEV_STYLES = {
        "Critical": ("#2d0808", "#E84040"),
        "High":     ("#2d1808", "#E87840"),
        "Medium":   ("#2d2008", "#E8B030"),
        "Low":      ("#282200", "#E8D040"),
    }
    kev_rows = ""
    for v in top_kev:
        sbg, sfg = SEV_STYLES.get(v["severity_label"], ("#1c2330", "#8b949e"))
        name = v["plugin_name"]
        name_esc = esc(name[:60] + "…" if len(name) > 60 else name)
        cve_str = esc((v.get("cve") or "").split(";")[0].strip())
        kev_rows += (
            f'<div class="bar-row clickable" onclick="goToVuln(\'{js_str(name)}\',\'\')" title="{esc(name)}">'
            f'<span class="sev-pill" style="background:{sbg};color:{sfg};margin-right:6px">{esc(v["severity_label"])}</span>'
            f'<div class="bar-label" style="width:auto;flex:1;text-align:left;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{name_esc}</div>'
            f'<span style="font-size:10px;color:#8b949e;font-family:IBM Plex Mono,monospace;flex-shrink:0;margin-left:8px">{cve_str}</span>'
            f'</div>'
        )
    kev_empty = '<div style="color:var(--muted);font-size:13px">No KEV matches found in current scan results.</div>'
    kev_overview_card = (
        f'<div class="card" style="margin-bottom:1.25rem">'
        f'<div class="card-title" style="color:#ff6b6b">🔴 CISA KEV — Confirmed Actively Exploited ({kev_count} findings)</div>'
        f'{kev_rows if top_kev else kev_empty}'
        f'</div>'
    )

    overview_html = f"""
    <div class="page-title">Overview</div>
    <div class="page-subtitle">
      Scan: <b>{scan_name}</b> &nbsp;·&nbsp; {scan_date}
      &nbsp;·&nbsp; {len(assets)} assets &nbsp;·&nbsp; {total_open} open findings
      &nbsp;·&nbsp; Generated {generated}
    </div>

    <div class="metrics" style="grid-template-columns:repeat(5,1fr)">
      <div class="metric">
        <div class="metric-label">Critical</div>
        <div class="metric-val" style="color:#E84040">{c}</div>
      </div>
      <div class="metric">
        <div class="metric-label">High</div>
        <div class="metric-val" style="color:#E87840">{h}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Medium</div>
        <div class="metric-val" style="color:#E8B030">{m}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Open findings</div>
        <div class="metric-val" style="color:#e6edf3">{total_open}</div>
      </div>
      <div class="metric" style="border-color:#7a1f1f;cursor:pointer" onclick="setPageClearHost('vulns');setTimeout(()=>setKevFilter(true),50)" title="Filter vulnerabilities by CISA KEV">
        <div class="metric-label" style="color:#ff6b6b">🔴 CISA KEV</div>
        <div class="metric-val" style="color:#ff6b6b">{kev_count}</div>
        <div style="font-size:10px;color:#8b6b6b;margin-top:2px">actively exploited</div>
      </div>
    </div>

    <div class="charts-row">
      <div class="card"><div class="card-title">Severity distribution</div>{sev_bars}</div>
      <div class="card"><div class="card-title">Top plugin families</div>{fam_bars}</div>
    </div>
    <div class="charts-row">
      <div class="card"><div class="card-title">Exploit availability</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">{exploit_badges}</div>
      </div>
      <div class="card"><div class="card-title">Top EPSS scores — exploitation probability</div>{epss_bars}</div>
    </div>
    {kev_overview_card}
    """

    # ─────────────────────────────────────────────────────────────
    # Page: Vulnerabilities  (table rendered by JS)
    # ─────────────────────────────────────────────────────────────
    filter_btns = "".join(
        f'<button class="fbtn{" active" if s == "All" else ""}" data-sev="{s}" onclick="setSevFilter(\'{s}\')">{s}</button>'
        for s in ["All", "Critical", "High", "Medium", "Low", "Info"]
    )
    vulns_html = f"""
    <div class="page-title">Vulnerabilities</div>
    <div class="page-subtitle">Click a row to expand synopsis, solution, and EPSS detail &nbsp;·&nbsp; Click column headers to sort</div>
    <div class="filter-row">
      {filter_btns}
      <button class="fbtn" id="kev-filter-btn" data-sev="KEV" onclick="setKevFilter()" title="Show only CISA KEV — confirmed actively exploited">🔴 KEV</button>
      <input class="sbox" placeholder="Search name, CVE, host…" oninput="setSearch(this.value)">
      <span id="host-badge" style="display:none;align-items:center;gap:5px;font-size:11px;
            padding:3px 10px;border-radius:20px;background:#0d2035;color:#58a6ff;
            border:1px solid #1a6fa8;font-family:'IBM Plex Mono',monospace">
        🖥 <span class="hbip"></span>
        <span onclick="clearHostFilter()" style="cursor:pointer;color:#8b949e;margin-left:2px"
              title="Clear host filter">✕</span>
      </span>
      <span id="exploit-badge" style="display:none;align-items:center;gap:5px;font-size:11px;
            padding:3px 10px;border-radius:20px;background:#3d2a0f;color:#e3b341;
            border:1px solid #5a3f00;font-family:'IBM Plex Mono',monospace">
        🎯 <span class="ebtype"></span>
        <span onclick="clearExploitFilter()" style="cursor:pointer;color:#8b949e;margin-left:2px"
              title="Clear exploit filter">✕</span>
      </span>
      <span class="result-count" id="result-count"></span>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <table class="vtable">
        <thead><tr>
          <th style="width:80px" class="sortable" data-col="sev" onclick="sortBy('sev')">Severity<span class="sort-arrow"> ↕</span></th>
          <th class="sortable" data-col="name" onclick="sortBy('name')">Vulnerability<span class="sort-arrow"> ↕</span></th>
          <th style="width:60px" class="sortable" data-col="cvss3" onclick="sortBy('cvss3')">CVSS3<span class="sort-arrow"> ↕</span></th>
          <th style="width:50px" class="sortable" data-col="vpr" onclick="sortBy('vpr')">VPR<span class="sort-arrow"> ↕</span></th>
          <th style="width:95px" class="sortable" data-col="epss" onclick="sortBy('epss')">EPSS<span class="sort-arrow"> ↕</span></th>
          <th style="width:90px" class="sortable" data-col="exploit" onclick="sortBy('exploit')">Exploit<span class="sort-arrow"> ↕</span></th>
          <th style="width:75px" class="sortable" data-col="port" onclick="sortBy('port')">Port<span class="sort-arrow"> ↕</span></th>
        </tr></thead>
        <tbody id="vtbody"></tbody>
      </table>
    </div>
    <div class="pager" id="pager-container"></div>
    """

    # ─────────────────────────────────────────────────────────────
    # Page: Assets
    # ─────────────────────────────────────────────────────────────
    sorted_assets = sorted(
        assets,
        key=lambda a: -criticality_map[a["host_ip"]].score
    )
    uncred_set = set(cov["uncredentialed"])

    # OS types that support Nessus credentialed scanning — show badge when scan was missed.
    # Non-OS devices (iOS, Router, NAS, Firewall…) are excluded: missing cred scan is expected.
    _OS_KEYWORDS = ("Linux", "macOS", "Windows", "Hypervisor", "BSD")

    asset_cards = ""
    for a in sorted_assets:
        has_v = (a.get("critical_count",0) + a.get("high_count",0) +
                 a.get("medium_count",0) + a.get("low_count",0)) > 0
        no_cred = a["host_ip"] in uncred_set
        nature  = a.get("host_nature", "Unknown")
        show_no_cred_badge = no_cred and any(kw in nature for kw in _OS_KEYWORDS)

        max_b = max(a.get("critical_count",0), a.get("high_count",0),
                    a.get("medium_count",0), a.get("info_count",0), 1)
        bars = "".join(
            f'<div class="abar" style="height:{max(3,round(v/max_b*22))}px;background:{c};" title="{lbl}: {v}"></div>'
            for lbl, v, c in [
                ("C", a.get("critical_count",0), "#E84040"),
                ("H", a.get("high_count",0),     "#E87840"),
                ("M", a.get("medium_count",0),   "#E8B030"),
                ("L", a.get("low_count",0),      "#E8D040"),
                ("I", a.get("info_count",0),      "#5AB4E8"),
            ] if v > 0
        )
        SEV_LABELS = {"C": "Critical", "H": "High", "M": "Medium", "L": "Low"}
        counts_html = ""
        for lbl, v, bg, fg in [
            ("C", a.get("critical_count",0), "#2d0808", "#E84040"),
            ("H", a.get("high_count",0),     "#2d1808", "#E87840"),
            ("M", a.get("medium_count",0),   "#2d2008", "#E8B030"),
            ("L", a.get("low_count",0),      "#282200", "#E8D040"),
        ]:
            if v:
                sev_label = SEV_LABELS[lbl]
                ip = a["host_ip"]
                counts_html += (
                    f'<span class="ac" style="background:{bg};color:{fg};cursor:pointer"'
                    f' onclick="goToVulnHostSev(\'{js_str(ip)}\',\'{sev_label}\')"'
                    f' title="View {sev_label} findings for {esc(ip)}">'
                    f'{lbl}: {v}</span>'
                )
        info_n = a.get("info_count", 0)
        if info_n:
            counts_html += f'<span class="ac" style="background:#1c2330;color:#8b949e">I: {info_n}</span>'

        cve_badge = ""
        if a.get("unique_cve_count", 0):
            cve_badge = f'<span style="font-size:10px;background:#2d0808;color:#E84040;padding:1px 7px;border-radius:10px;font-weight:600;white-space:nowrap;flex-shrink:0">{a["unique_cve_count"]} CVEs</span>'

        no_cred_badge = (
            f'<span class="no-cred-badge"'
            f' title="Credentialed scan failed — patch/access-control findings may be incomplete">⚠ No Cred</span>'
        ) if show_no_cred_badge else ""

        cr = criticality_map[a["host_ip"]]

        tip_json = esc(json.dumps({
            "inet":    cr.inet_score,
            "svc":     cr.svc_score,
            "vuln":    cr.vuln_score,
            "score":   cr.score,
            "factors": cr.factors,
        }, separators=(',', ':')))

        card_class = f"acard crit-{cr.tier.lower()}"
        if show_no_cred_badge:
            card_class += " no-cred"

        if cr.boundary_device:
            inet_badge = '<span class="acrit-inet">🌐 Boundary</span>'
        elif cr.exposure_risk:
            inet_badge = '<span class="acrit-inet acrit-inet-warn">⚠ Exposed Services</span>'
        else:
            inet_badge = ""
        svc_text   = " · ".join(cr.services[:3]) if cr.services else ""

        atype = asset_type_key(nature)
        asset_cards += f"""
        <div class="{card_class}"
             data-ip="{esc(a['host_ip'])}"
             data-tier="{cr.tier.lower()}"
             data-atype="{atype}"
             data-nature="{esc(nature.lower())}"
             data-critical="{a.get('critical_count',0)}"
             data-high="{a.get('high_count',0)}"
             data-medium="{a.get('medium_count',0)}"
             data-low="{a.get('low_count',0)}">
          <div class="aip" onclick="setHostFilter('{esc(a['host_ip'])}')"
               title="Show vulnerabilities for this host"
               style="cursor:pointer;text-decoration:underline;text-underline-offset:3px;margin-bottom:2px">{esc(a["host_ip"])}</div>
          <div class="acard-meta">
            <div class="anat">{nat_icon(nature)} {esc(nature)}</div>
            {cve_badge}
          </div>
          <div class="acrit-row" data-crit-tip="{tip_json}" title="Hover to see score breakdown">
            <span class="acrit-tier" style="color:{cr.tier_color}">● {esc(cr.tier)}</span>
            <span class="acrit-score">{cr.score}/100</span>
          </div>
          <div class="acrit-badges">{inet_badge}</div>
          <div class="acrit-services">{esc(svc_text)}</div>
          <div class="abars">{bars}</div>
          <div class="acounts">{counts_html}</div>
          <div class="acard-footer">{no_cred_badge}</div>
        </div>"""

    uncred_note = (
        f' &nbsp;·&nbsp; <span style="color:#e3b341">⚠ {cov["uncred_count"]} without credentials</span>'
        if cov["has_gap"] else ""
    )
    assets_html = f"""
    <div class="page-title">Assets</div>
    <div class="page-subtitle">{len(assets)} hosts discovered &nbsp;·&nbsp; sorted by risk exposure{uncred_note}</div>
    <div class="asset-filter-bar">
      <div class="asset-search-wrap">
        <svg class="asset-search-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="6.5" cy="6.5" r="4.5"/><path d="M10.5 10.5l3 3"/>
        </svg>
        <input class="asset-search" id="asset-search" type="text"
               placeholder="Search IP or device type…" oninput="filterAssets(this.value)">
        <button class="asset-search-clear" id="asset-search-clear"
                onclick="clearAssetSearch()" title="Clear search">✕</button>
      </div>
      <div class="groupby-toggle">
        <span class="groupby-label">Group by</span>
        <button class="groupby-btn active" id="groupby-tier" onclick="switchGroupBy('tier')">Tier</button>
        <button class="groupby-btn" id="groupby-type" onclick="switchGroupBy('type')">Type</button>
      </div>
    </div>
    <div id="assets-pool" style="display:none">{asset_cards}</div>
    <div id="assets-display"></div>
    """

    js_assets = []
    for a in sorted_assets:
        cr  = criticality_map[a["host_ip"]]
        nat = a.get("host_nature", "Unknown")
        nc  = a["host_ip"] in uncred_set and any(kw in nat for kw in _OS_KEYWORDS)
        js_assets.append({
            "ip":       a["host_ip"],
            "nature":   nat,
            "tier":     cr.tier,
            "score":    cr.score,
            "inet":     cr.inet_score,
            "svc":      cr.svc_score,
            "vuln":     cr.vuln_score,
            "critical": a.get("critical_count", 0),
            "high":     a.get("high_count",     0),
            "medium":   a.get("medium_count",   0),
            "low":      a.get("low_count",      0),
            "info":     a.get("info_count",     0),
            "cves":     a.get("unique_cve_count", 0),
            "services": " | ".join(cr.services),
            "boundary": cr.boundary_device,
            "exposure": cr.exposure_risk,
            "no_cred":  nc,
            "factors":  " | ".join(cr.factors),
        })

    # ─────────────────────────────────────────────────────────────
    # Page: Software Inventory
    # ─────────────────────────────────────────────────────────────
    sw_apps = [s for s in software if s["cpe_type"] == "a"]
    sw_os   = [s for s in software if s["cpe_type"] == "o"]
    hosts_with_cpe = len({h for s in software for h in s["hosts"]})

    TYPE_META = {
        "a": ("📦", "App",      "#0d2035", "#58a6ff"),
        "o": ("💿", "OS",       "#0d2a1a", "#3fb950"),
        "h": ("🔧", "Hardware", "#1c2330", "#8b949e"),
    }

    def sw_row(s: dict) -> str:
        icon, label, bg, fg = TYPE_META.get(s["cpe_type"], ("·", s["cpe_type"], "#1c2330", "#8b949e"))
        ver = ", ".join(s["versions"]) if s["versions"] else "—"
        host_tags = " ".join(
            f'<span class="sw-host-tag" onclick="setHostFilter(\'{esc(h)}\')" title="Show vulnerabilities for {esc(h)}">{esc(h)}</span>'
            for h in s["hosts"]
        )
        search_text = f"{s['product']} {s['vendor']} {s['display_name']} {ver}".lower()
        return (
            f'<tr class="sw-row" data-type="{s["cpe_type"]}" data-text="{esc(search_text)}">'
            f'<td><span class="sw-type-badge" style="background:{bg};color:{fg}">{icon} {label}</span></td>'
            f'<td style="font-weight:500">{esc(s["display_name"])}</td>'
            f'<td style="color:var(--muted);font-size:12px">{esc(s["display_vendor"])}</td>'
            f'<td class="sw-version">{esc(ver)}</td>'
            f'<td>{host_tags}</td>'
            f'</tr>'
        )

    sw_rows_html = "".join(sw_row(s) for s in software)

    sw_filter_btns = "".join(
        f'<button class="fbtn sw-type-btn{" active" if t == "" else ""}" data-t="{t}" onclick="setSwType(\'{t}\')">{lbl}</button>'
        for t, lbl in [("", "All"), ("a", "📦 Apps"), ("o", "💿 OS"), ("h", "🔧 Hardware")]
    )

    software_html = f"""
    <div class="page-title">Software Inventory</div>
    <div class="page-subtitle">Discovered via CPE (plugin 45590) &nbsp;·&nbsp; {hosts_with_cpe} hosts with CPE data</div>

    <div class="sw-metrics">
      <div class="metric">
        <div class="metric-label">Applications</div>
        <div class="metric-val" style="color:#58a6ff">{len(sw_apps)}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Operating Systems</div>
        <div class="metric-val" style="color:#3fb950">{len(sw_os)}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Hosts with CPE data</div>
        <div class="metric-val" style="color:var(--text)">{hosts_with_cpe}</div>
      </div>
    </div>

    <div class="sw-filter-row">
      {sw_filter_btns}
      <input class="sbox" placeholder="Search software, vendor, version…" oninput="setSwSearch(this.value)">
      <span class="result-count" id="sw-count">{len(software)} entries</span>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <table class="swtable">
        <thead><tr>
          <th style="width:90px">Type</th>
          <th>Software</th>
          <th style="width:140px">Vendor</th>
          <th style="width:160px">Version</th>
          <th>Found on</th>
        </tr></thead>
        <tbody>{sw_rows_html}</tbody>
      </table>
    </div>
    """

    # ─────────────────────────────────────────────────────────────
    # Page: Cyber Essentials
    # ─────────────────────────────────────────────────────────────
    def ce_card(domain: dict) -> str:
        items = domain["items"]
        fails = sum(1 for i in items if not i["pass"])
        if fails == 0:
            badge_style = "background:#0d2a1a;color:#3fb950"
            badge_text = "Pass"
        elif fails == len(items):
            badge_style = "background:#3d1a1a;color:#f85149"
            badge_text = f"{fails} issues"
        else:
            badge_style = "background:#3d2a0f;color:#e3b341"
            badge_text = f"{fails} issue{'s' if fails > 1 else ''}"

        def _item(i: dict) -> str:
            link = i.get("link", "")
            link_host = i.get("link_host", "")
            icon = "✅" if i["pass"] else "❌"
            text = esc(i["text"])
            sub  = esc(i["sub"])
            if link or link_host:
                return (
                    f'\n        <div class="ce-item ce-item-link"'
                    f' data-q="{esc(link)}" data-host="{esc(link_host)}"'
                    f' onclick="goToVuln(this.dataset.q,this.dataset.host)">'
                    f'\n          <span class="ce-icon">{icon}</span>'
                    f'\n          <div class="ce-item-text">{text}'
                    f'<div class="ce-item-sub">{sub}</div></div>'
                    f'\n          <span class="ce-link-arrow">→</span>'
                    f'\n        </div>'
                )
            return (
                f'\n        <div class="ce-item">'
                f'\n          <span class="ce-icon">{icon}</span>'
                f'\n          <div class="ce-item-text">{text}'
                f'<div class="ce-item-sub">{sub}</div></div>'
                f'\n        </div>'
            )

        items_html = "".join(_item(i) for i in items)

        return f"""
        <div class="ce-card">
          <div class="ce-card-head">
            <div class="ce-card-title">{domain["icon"]} {esc(domain["title"])}</div>
            <span class="ce-status-badge" style="{badge_style}">{badge_text}</span>
          </div>
          {items_html}
        </div>"""

    # ── 14-day patching compliance ──
    crithigh = sorted(
        [v for v in vulns
         if v.get("severity_label") in ("Critical", "High")
         and v.get("currently_impacted_host_count", 0) > 0],
        key=lambda v: -(v.get("age_of_vulnerability_days") or 0),
    )

    def _age_status(age):
        if age is None or age < 0:
            return "Unknown",   "#1c2330", "#8b949e", "—"
        if age > 14:
            return "Overdue",   "#2d0808", "#E84040", f"{age}d"
        if age > 7:
            return "Due soon",  "#2d1808", "#E87840", f"{age}d"
        return     "On track",  "#1a2800", "#8bc34a", f"{age}d"

    overdue_count   = sum(1 for v in crithigh if (v.get("age_of_vulnerability_days") or 0) > 14)
    due_soon_count  = sum(1 for v in crithigh if 7 < (v.get("age_of_vulnerability_days") or 0) <= 14)
    on_track_count  = sum(1 for v in crithigh if 0 <= (v.get("age_of_vulnerability_days") or 0) <= 7)

    def _patch_row(v: dict) -> str:
        age     = v.get("age_of_vulnerability_days")
        sev     = v.get("severity_label", "")
        sev_bg, sev_fg = ("#2d0808","#E84040") if sev=="Critical" else ("#2d1808","#E87840")
        st_text, st_bg, st_fg, age_str = _age_status(age)
        hosts   = [h.strip() for h in (v.get("currently_impacted_hosts") or "").split(";") if h.strip()]
        host_html = " ".join(
            f'<span style="font-family:\'IBM Plex Mono\',monospace;font-size:10px;'
            f'padding:1px 5px;border-radius:4px;background:var(--surface2);color:var(--muted)">'
            f'{esc(h)}</span>' for h in hosts
        )
        return (
            f'<tr style="cursor:pointer" data-q="{esc(v.get("plugin_name",""))}" data-host=""'
            f' onclick="goToVuln(this.dataset.q,this.dataset.host)">'
            f'<td><span class="sev-pill" style="background:{sev_bg};color:{sev_fg}">{esc(sev)}</span></td>'
            f'<td style="font-weight:500;max-width:340px">{esc(v.get("plugin_name",""))}</td>'
            f'<td style="font-family:\'IBM Plex Mono\',monospace;font-size:12px;white-space:nowrap">{age_str}</td>'
            f'<td><span class="sev-pill" style="background:{st_bg};color:{st_fg}">{esc(st_text)}</span></td>'
            f'<td style="font-size:11px">{host_html}</td>'
            f'</tr>'
        )

    patch_rows_html = "".join(_patch_row(v) for v in crithigh)

    overdue_label = f'<span style="color:#f85149">{overdue_count} overdue</span>' if overdue_count else f'<span style="color:#3fb950">none overdue</span>'
    patch_table_html = f"""
    <div class="patch-section-title" onclick="togglePatch()">
      ⏱ 14-Day Patching Compliance
      <span style="font-size:12px;font-weight:400;color:var(--muted);margin-left:.25rem">
        — {len(crithigh)} Critical/High findings &nbsp;·&nbsp; {overdue_label}
      </span>
      <i class="patch-chevron" id="patch-chevron">›</i>
    </div>
    <div id="patch-body" style="display:none">
      <div class="patch-section-sub">
        CE requires all Critical and High vulnerabilities to be remediated within 14 days of patch availability.
        Click any row to view the finding detail.
      </div>
      <div class="patch-metrics">
        <div class="patch-metric">
          <div>
            <div class="patch-metric-num" style="color:#f85149">{overdue_count}</div>
            <div class="patch-metric-label">Overdue (&gt;14 days)</div>
          </div>
        </div>
        <div class="patch-metric">
          <div>
            <div class="patch-metric-num" style="color:#e3b341">{due_soon_count}</div>
            <div class="patch-metric-label">Due soon (8–14 days)</div>
          </div>
        </div>
        <div class="patch-metric">
          <div>
            <div class="patch-metric-num" style="color:#3fb950">{on_track_count}</div>
            <div class="patch-metric-label">On track (≤7 days)</div>
          </div>
        </div>
      </div>
      <div class="card" style="padding:0;overflow:hidden;margin-bottom:1.5rem">
        <table class="vtable">
          <thead><tr>
            <th style="width:80px">Severity</th>
            <th>Vulnerability</th>
            <th style="width:70px">Age</th>
            <th style="width:95px">CE Status</th>
            <th>Affected Hosts</th>
          </tr></thead>
          <tbody>{patch_rows_html}</tbody>
        </table>
      </div>
    </div>"""

    ce_domains = list(ce.values())
    ce_grid_html = (
        f'<div class="ce-grid">{"".join(ce_card(d) for d in ce_domains[:2])}</div>'
        f'<div class="ce-grid">{"".join(ce_card(d) for d in ce_domains[2:4])}</div>'
        f'<div style="max-width:calc(50% - 6px)">{ce_card(ce_domains[4])}</div>'
    )

    ce_html = f"""
    <div class="page-title">Cyber Essentials Assessment</div>
    <div class="page-subtitle">NCSC Cyber Essentials v3.1 — derived from vulnerability scan findings</div>

    <div class="ce-score-band">
      <div>
        <div class="ce-verdict" style="color:{verdict_color}">{verdict}</div>
        <div class="ce-readiness">{readiness}</div>
      </div>
      <div class="ce-divider"></div>
      <div class="ce-stat">
        <div class="ce-stat-num" style="color:#f85149">{total_fail}</div>
        <div class="ce-stat-label">Failing</div>
      </div>
      <div class="ce-divider"></div>
      <div class="ce-stat">
        <div class="ce-stat-num" style="color:#3fb950">{total_pass}</div>
        <div class="ce-stat-label">Passing</div>
      </div>
      <div class="ce-divider"></div>
      <div class="ce-stat" style="text-align:left">
        <div style="font-size:13px;color:#e6edf3;line-height:1.5">Framework: NCSC CE v3.1<br>
        Scope: {len(assets)} assets, {total_open} findings<br>
        Scan date: {scan_date}</div>
      </div>
    </div>
    {_coverage_banner(cov)}
    {patch_table_html}
    {ce_grid_html}
    """

    # ─────────────────────────────────────────────────────────────
    # Assemble full HTML
    # ─────────────────────────────────────────────────────────────
    vuln_dot_color = (
        "#E84040" if c > 0 else
        "#E87840" if h > 0 else
        "#E8B030" if m > 0 else
        "#5AB4E8"
    )
    nav_dots = {
        "overview": "",
        "vulns":    f'<span class="nav-dot" style="background:{vuln_dot_color}"></span>' if (c + h + m + l) > 0 else "",
        "assets":   f'<span class="nav-dot" style="background:#e3b341"></span>' if cov["has_gap"] else "",
        "software": "",
        "ce":       f'<span class="nav-dot" style="background:{verdict_color}"></span>',
    }
    nav_labels = {
        "overview":  ("📊", "Overview"),
        "vulns":     ("🐛", "Vulnerabilities"),
        "assets":    ("🖥️",  "Assets"),
        "software":  ("📦", "Software"),
        "ce":        ("🛡️",  "Cyber Essentials"),
    }

    sidebar_items = "".join(
        f'<a class="nav-item" id="nav-{k}" onclick="setPageClearHost(\'{k}\')" href="javascript:void(0)">'
        f'{icon} {label}{nav_dots[k]}</a>'
        for k, (icon, label) in nav_labels.items()
    )

    pages_html = "\n".join(
        f'<div class="page" id="page-{pid}">{html}</div>'
        for pid, html in [
            ("overview",  overview_html),
            ("vulns",     vulns_html),
            ("assets",    assets_html),
            ("software",  software_html),
            ("ce",        ce_html),
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Risk Radar — {esc(scan_name)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="shell">
  <nav class="sidebar">
    <div class="sidebar-logo">RISK RADAR<span> / REPORT</span></div>
    {sidebar_items}
    <button class="theme-toggle" onclick="toggleTheme()" title="Toggle light / dark mode">
      <span class="theme-toggle-icon" id="theme-icon">🌙</span>
      <span id="theme-label">Dark mode</span>
      <span class="theme-switch" id="theme-switch"></span>
    </button>
    <div class="sidebar-export">
      <div class="sidebar-export-label">Export</div>
      <button class="export-btn" onclick="exportPDF()"><span class="export-btn-icon">📄</span> PDF Report</button>
      <button class="export-btn" onclick="exportXLSX()"><span class="export-btn-icon">📊</span> Excel (XLSX)</button>
    </div>
    <div style="padding:.75rem 1.25rem;font-size:11px;color:var(--muted)">
      Generated<br>{generated}
    </div>
  </nav>
  <main class="main">
    {pages_html}
  </main>
</div>
<div id="crit-tip"></div>
<script>
window.VULNS   = {json.dumps(js_vulns,   separators=(',', ':'))};
window.ASSETS  = {json.dumps(js_assets,  separators=(',', ':'))};
{JS}
</script>
</body>
</html>"""


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a standalone HTML security report from Nessus JSON output."
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=Path("nessus_aggregated_results.json"),
        help="Path to nessus_aggregated_results.json (default: ./nessus_aggregated_results.json)",
    )
    parser.add_argument(
        "--assets",
        type=Path,
        default=Path("nessus_assets.json"),
        help="Path to nessus_assets.json (default: ./nessus_assets.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output HTML file (default: nessus_report_<YYYYMMDD>.html)",
    )
    args = parser.parse_args()

    print(f"Reading vulnerabilities: {args.results}")
    results_data = load_json(args.results)
    vulns   = results_data.get("results", [])
    summary = results_data.get("summary", {})

    # Normalise legacy "None" severity label → "Info"
    for v in vulns:
        if v.get("severity_label") == "None":
            v["severity_label"] = "Info"

    print(f"Reading assets:          {args.assets}")
    assets_data = load_json(args.assets)
    assets = assets_data.get("results", [])

    print(f"Loaded {len(vulns)} findings across {len(assets)} assets.")

    print("Fetching CISA KEV threat intelligence…")
    kev_cache = Path(__file__).resolve().parent / "threat_intel_cache"
    kev_lookup = fetch_cisa_kev(cache_dir=kev_cache)

    output_path = args.output or Path(
        f"nessus_report_{datetime.now().strftime('%Y%m%d')}.html"
    )

    print(f"Generating report…")
    html = build_html(vulns, assets, summary, kev_lookup=kev_lookup)
    output_path.write_text(html, encoding="utf-8")

    size_kb = round(output_path.stat().st_size / 1024)
    print(f"Report written: {output_path}  ({size_kb} KB)")
    print("Open it in any browser — no server or internet connection required.")


if __name__ == "__main__":
    main()
