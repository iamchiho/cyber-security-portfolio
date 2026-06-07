---
title: "Sample Report"
sidebar_position: 6
---

# Sample Report

The report below was generated from a real Nessus scan of a home lab environment running 28 hosts across multiple OS types and device roles.

It demonstrates the full output of the AI Vulnerability Prioritization pipeline — including asset criticality scoring, CISA KEV enrichment, Cyber Essentials assessment, and software inventory.

<div style={{textAlign: 'center', margin: '2rem 0'}}>
  <a
    href="/cyber-security-portfolio/reports/nessus_report_latest.html"
    target="_blank"
    rel="noopener noreferrer"
    style={{
      display: 'inline-block',
      padding: '14px 32px',
      background: '#238636',
      color: '#ffffff',
      borderRadius: '8px',
      fontWeight: '600',
      fontSize: '16px',
      textDecoration: 'none',
      border: '1px solid #2ea043',
    }}
  >
    🔍 View Sample Report
  </a>
  <div style={{marginTop: '10px', fontSize: '13px', color: '#8b949e'}}>
    Opens in a new tab · No login required · Fully interactive
  </div>
</div>

---

## What's Inside

| Section | Description |
|---|---|
| **Overview** | Severity breakdown, top plugin families, exploit availability, EPSS distribution, and CISA KEV findings |
| **Vulnerabilities** | Searchable and filterable table with KEV badges, CVSS3, VPR, EPSS, and exploit maturity |
| **Assets** | Criticality-scored asset cards (0–100) grouped by device type with exposure and service signals |
| **Software Inventory** | CPE-derived software and version list across all hosts |
| **Cyber Essentials** | Automated CE v3.1 pass/fail assessment across all 5 domains |

## Scan Environment

| Detail | Value |
|---|---|
| Scanner | Nessus Essentials |
| Hosts scanned | 28 |
| Total findings | 459 |
| Scan type | Credentialed + uncredentialed |
| CISA KEV data | Fetched at report generation time |
