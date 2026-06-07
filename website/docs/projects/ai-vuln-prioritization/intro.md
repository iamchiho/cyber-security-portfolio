---
title: "Introduction"
sidebar_position: 1
---

# Welcome to AI Vulnerability Prioritization

This project enhances vulnerability management by combining Nessus scan results with AI-driven risk prioritization. Enterprise vulnerability scans often produce hundreds of findings, making it difficult for security teams to identify what truly matters.

To address this, the project ingests Nessus scan reports, enriches findings with asset criticality context, live threat intelligence, and uses an LLM to produce actionable, prioritized remediation guidance.

---

# The Problem

Vulnerability scanners like Nessus are excellent at discovering security weaknesses — but the raw output has several significant gaps when it comes to real-world decision-making:

**1. Technical findings without business context**

A raw Nessus report lists hundreds of CVEs with CVSS scores, but CVSS measures theoretical severity — not actual business risk. A Critical CVE on a development laptop and a Critical CVE on a production database server are treated identically, even though the business impact is worlds apart. Security teams need risk scores that account for **what the asset does**, **how exposed it is**, and **how likely the vulnerability is to be exploited**.

**2. No indication of active exploitation**

CVSS scores are static — they do not tell you whether a vulnerability is being actively exploited in the wild right now. Without threat intelligence enrichment, teams have no way to distinguish theoretical risk from confirmed, active threats targeting their environment.

**3. No regulatory alignment**

Raw scan results are not mapped to compliance frameworks. A security manager preparing for a **Cyber Essentials** assessment cannot directly use a Nessus report to understand their pass/fail posture — they must manually cross-reference hundreds of findings against framework requirements. This is time-consuming and error-prone.

**4. Volume without prioritisation**

A typical enterprise scan produces 300–500+ findings. Without automated prioritisation, remediation effort is often misallocated — teams patch low-risk issues first simply because they appear at the top of a sorted list, while critical, actively-exploited vulnerabilities wait.

---

# Project Objective

The goal is to bridge the gap between raw vulnerability detection and risk-based decision-making — by enriching Nessus scan data with asset criticality scoring, live threat intelligence (CISA KEV), and AI-driven analysis to produce reports that answer the question security teams actually need answered:

> **"What do we fix first, and why does it matter to the business?"**

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

