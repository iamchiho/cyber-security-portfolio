---
title: "Running Scan"
sidebar_position: 3
---

# Running a Scan in Nessus

## 1. Login to the Web UI

Open your browser and navigate to:

```
https://<your-server-ip>:8834
```

Login with your administrator account created during installation.

## 2. Create a New Scan

On the left panel, click **My Scans**, then click **New Scan**.

![Add New Scan](/img/ai-vuln-prioritization/step1-add-new-scan.png)

## 3. Select Scan Template

Choose **Basic Network Scan** — this is suitable for general vulnerability discovery across hosts and network ranges.

![Select Basic Network Scan](/img/ai-vuln-prioritization/step2-add-new-basic-network-scan.png)

## 4. Configure Scan Settings

Fill in the scan details:

- **Name** — give the scan a descriptive name (e.g. `Lab Network Scan`)
- **Targets** — enter an IP address or CIDR range (e.g. `192.168.1.0/24`)

![Configure Scan Settings](/img/ai-vuln-prioritization/step3-configure-basic-network-scan-settings.png)

## 5. Add Credentials (Optional)

Adding credentials allows Nessus to perform authenticated scans, which produce more thorough results by checking installed software versions and local configurations.

Under the **Credentials** tab, add SSH or Windows credentials if available.

![Add Credentials](/img/ai-vuln-prioritization/step4-add-credential-optional.png)

## 6. Launch the Scan

Click **Save**, then click the **Launch** button (▶) next to your scan to start it.

Scan duration depends on the number of targets and network speed. You can monitor progress from the **My Scans** page.

## 7. View Scan Results

Once the scan completes, click on the scan name to view the results.

**Summary** — overall vulnerability count by severity:

![Scan Results Summary](/img/ai-vuln-prioritization/step5-scan-results-summary.png)

**Hosts** — breakdown of findings per host:

![Scan Results Hosts Summary](/img/ai-vuln-prioritization/step5-scan-results-hosts-summary.png)

**Vulnerabilities** — full list of discovered vulnerabilities with severity and details:

![Scan Results Vulnerability Summary](/img/ai-vuln-prioritization/step5-scan-results-vuln-summary.png)

## 8. Export the Scan Report

To use the scan results for AI-based prioritization, export the report in **HTML** format:

1. Click **Report** (top right of the scan results page)
2. Select **HTML** as the format
3. Click **Export**

The exported HTML report will be used as input for the Python processing pipeline in the next step.
