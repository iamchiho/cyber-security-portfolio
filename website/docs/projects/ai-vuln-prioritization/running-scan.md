---
title: "Running Scan"
sidebar_position: 3
---

# Running Scan

## 1. Login the Web UI

Login to the OpenVAS Web UI by

```
https://<your-server-ip>:9392
```

Login to by your admin account password you should see following screen.

![OpenVAS Dashboard](/img/ai-vuln-prioritization/openvas_dashboard.png)

## 2. Create scan target

After that we need to define the host or a network range to be scanned.

On manu bar, select **Configuration**, **Target**, click ![OpenVAS Dashboard](/img/ai-vuln-prioritization/create_new_scan_task.png)

![OpenVAS Dashboard](/img/ai-vuln-prioritization/create_new_target.png)

Under **Hosts**, you may put an IP address of a single host or a CIDR (e.g. 192.168.0.0/24)

## 3. Create a Scan

On the menu bar, select **Scans → Tasks**, then click **New Task**.

![Create Scan Task](/img/ai-vuln-prioritization/create_scan_task.png)

Click **Save**. You will see the new scan task.

![Task List](/img/ai-vuln-prioritization/show_task_list.png)

Click **Start** to begin the scan.

## 4. View Scan Results

After the scan completes, go to **Results** on the left panel.

![Scan Results](/img/ai-vuln-prioritization/show_results.png)
