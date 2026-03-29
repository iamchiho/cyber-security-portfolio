# Cyber Security Portfolio

This repository contains my cybersecurity portfolio website and the supporting project work behind it. It showcases hands-on security workflows across vulnerability management, exposure analysis, and security-focused automation.

## What This Repository Covers

- vulnerability management and exposure analysis
- risk-based prioritization and remediation workflows
- OpenVAS data export and parsing
- Python-based security tooling
- AI-assisted security analysis concepts
- project documentation for portfolio presentation

## Current Featured Project

### AI Vulnerability Prioritization

This project focuses on transforming raw vulnerability scan results into structured, contextual, and actionable security insights.

Key areas include:

- exporting OpenVAS reports and asset data
- parsing XML scan outputs with Python
- correlating host and operating system asset context
- preparing data for prioritization and AI-assisted analysis
- supporting better remediation decisions with enriched context

Project location:

```text
projects/ai-vuln-prioritization/
```

## Repository Structure

```text
.
├── README.md
├── projects/
│   └── ai-vuln-prioritization/
│       └── src/
│           └── test/
└── website/
    ├── docs/
    ├── src/
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
- the ability to connect technical findings with business-focused prioritization

## Notes

- Website-specific guidance is in `website/README.md`
- Some project scripts use local `.env` files for test and export workflows
- Sensitive credentials should never be committed
