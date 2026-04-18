# Cyber Security Portfolio

This repository contains my cybersecurity portfolio website and the supporting project work behind it. It showcases hands-on security workflows across vulnerability management, exposure analysis, threat detection, and security-focused automation.

## What This Repository Covers

- vulnerability management and exposure analysis
- risk-based prioritization and remediation workflows
- Microsoft Sentinel threat detection engineering
- KQL-based detection logic for identity-focused use cases
- OpenVAS data export and parsing
- Python-based security tooling
- AI-assisted security analysis concepts
- project documentation for portfolio presentation

## Featured Projects

### AI Vulnerability Prioritization (In Progress)

This project focuses on transforming raw vulnerability scan results into structured, contextual, and actionable security insights.

Key areas include:

- exporting OpenVAS reports and asset data
- parsing XML scan outputs with Python
- correlating host and operating system asset context
- preparing data for prioritization and AI-assisted analysis
- supporting better remediation decisions with enriched context

Project documentation:

```text
website/docs/projects/ai-vuln-prioritization/
```

Supporting code:

```text
projects/ai-vuln-prioritization/
```

### SIEM Threat Detection

This project demonstrates an end-to-end threat detection and response workflow using Microsoft Sentinel, focused on identity-based attack scenarios in Entra ID.

Key areas include:

- building a working SIEM lab in Microsoft Sentinel
- collecting and analyzing Entra ID sign-in and audit logs
- creating custom analytics rules with KQL
- simulating attack scenarios such as password spraying and impossible travel
- generating alerts and incidents for investigation
- integrating playbooks for automated response

Project documentation:

```text
website/docs/projects/siem-threat-detection/
```

Current detection use cases:

- password spraying
- impossible travel
- privilege escalation in progress

## Repository Structure

```text
.
├── README.md
├── deploy.sh
├── projects/
│   └── ai-vuln-prioritization/
│       └── src/
└── website/
    ├── README.md
    ├── docs/
    │   └── projects/
    │       ├── ai-vuln-prioritization/
    │       └── siem-threat-detection/
    ├── src/
    ├── static/
    ├── docusaurus.config.js
    └── package.json
```

## Website

The portfolio site is built with Docusaurus and published to GitHub Pages.

Live site:

```text
https://iamchiho.github.io/cyber-security-portfolio/
```

Run locally:

```bash
cd website
npm install
npm start
```

Build the site:

```bash
cd website
npm run build
```

## Deployment

Use the root deployment helper:

```bash
./deploy.sh "Update portfolio"
```

This handles staging, committing, pushing, building, and deploying the site to GitHub Pages.

## Purpose

This portfolio is intended to demonstrate:

- practical hands-on security work
- clear technical communication
- structured project thinking
- detection engineering and security operations workflows
- the ability to connect technical findings with business-focused prioritization

## Notes

- Website-specific guidance is in `website/README.md`
- Some project scripts use local `.env` files for test and export workflows
- Sensitive credentials should never be committed
