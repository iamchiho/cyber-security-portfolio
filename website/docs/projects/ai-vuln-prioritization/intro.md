---
title: "Introduction"
sidebar_position: 1
---

# Welcome to AI Vulnerability Prioritization

This project enhances vulnerability management by combining Nessus scan results with AI-driven risk prioritization. Enterprise vulnerability scans often produce hundreds of findings, making it difficult for security teams to identify what truly matters.

To address this, the project ingests Nessus scan reports, enriches findings with asset criticality context, and uses an LLM to produce actionable, prioritized remediation guidance.

---

# Project Objective

The goal is to bridge the gap between raw vulnerability detection and risk-based decision-making — transforming Nessus HTML reports into structured, AI-analyzed outputs that help teams focus on the highest-impact issues first.

---

# Tools Leveraged

**Nessus (Tenable)**

Nessus is an industry-leading vulnerability scanner developed by Tenable. It is widely used in enterprise environments to identify security weaknesses across systems, networks, and applications, including:

- Outdated and unpatched software
- Misconfigurations and insecure defaults
- Weak authentication settings
- Known CVEs and exposed services

Nessus produces detailed scan reports in HTML format. In this project, Nessus serves as the primary data source for identifying security findings across target environments.


**Python**

Python is the automation and integration layer that connects Nessus scan output to AI analysis.

Within this project, Python is responsible for:
- Parsing and extracting vulnerability findings from Nessus HTML reports
- Aggregating results from multiple scan reports
- Enriching findings with asset criticality and contextual information
- Calculating weighted risk scores based on CVSS and business impact
- Preparing structured data for AI-driven analysis
- Generating final prioritized reports


**Claude (Anthropic)**

Claude is the Large Language Model (LLM) developed by Anthropic, used for intelligent risk analysis in this project.

The LLM is applied to:
- Analyze vulnerability context beyond raw CVSS scores
- Generate composite risk assessments based on asset criticality
- Produce human-readable remediation summaries
- Recommend prioritized remediation actions

By combining structured Nessus scan data with Claude's contextual reasoning, the project delivers more intelligent, business-aware risk prioritization beyond traditional static scoring models.

---

## How to Use This Project

- Browse the **docs** to understand the workflow and design decisions.
- Follow the **guides** to see how Nessus reports are processed and analyzed.
- Check the examples to understand how vulnerabilities are scored and prioritized.

---

