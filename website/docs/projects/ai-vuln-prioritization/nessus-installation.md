---
title: "Nessus Installation"
sidebar_position: 2
---

# Installation

# Nessus Installation Guide (Tenable Nessus Essentials)

This document provides a complete step-by-step guide to installing Nessus on Ubuntu Linux using Tenable Nessus Essentials — a free tier that supports scanning up to 16 IP addresses.

---

## 1. System Requirements

Before installation, ensure your system meets the following requirements:

- Ubuntu 20.04 or 22.04 (Recommended)
- Minimum 4 GB RAM (8 GB Recommended)
- At least 30 GB free disk space
- Root or sudo privileges
- Stable internet connection (required for plugin updates)

---

## 2. Register for a Free Activation Code

Nessus Essentials requires a free activation code from Tenable.

1. Go to the [Tenable Nessus Essentials registration page](https://www.tenable.com/products/nessus/nessus-essentials)
2. Fill in your name and email address
3. Tenable will email you an activation code — save it for later

---

## 3. Download Nessus

Download the latest Nessus `.deb` package for Ubuntu from the [Tenable Downloads page](https://www.tenable.com/downloads/nessus).

Select the package matching your OS, for example:

```
Nessus-10.x.x-ubuntu1604_amd64.deb
```

Or download directly via terminal (replace the filename with the latest version):

```bash
curl -O https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/<id>/get
```

---

## 4. Install Nessus

Install the downloaded `.deb` package:

```bash
sudo dpkg -i Nessus-*.deb
```

---

## 5. Start the Nessus Service

Start and enable the Nessus daemon:

```bash
sudo systemctl start nessusd
sudo systemctl enable nessusd
```

Verify the service is running:

```bash
sudo systemctl status nessusd
```

You should see `active (running)` in the output.

---

## 6. Access the Web Interface

Open your browser and navigate to:

```
https://localhost:8834
```

Or if accessing from another machine:

```
https://<your-server-ip>:8834
```

You may see a security warning due to a self-signed SSL certificate. Proceed to continue.

---

## 7. Initial Setup

Follow the on-screen setup wizard:

1. Select **Nessus Essentials**
2. Enter the **activation code** received from Tenable
3. Create an **administrator username and password**
4. Wait for Nessus to download and compile plugins

:::info
Plugin compilation may take **15–30 minutes** depending on your internet speed and hardware.
:::

---

## 8. Verify Installation

Once plugins are compiled, you will be redirected to the Nessus dashboard.

Confirm the installation is working by checking:

- The dashboard loads without errors
- Plugin feed shows an up-to-date compilation timestamp under **Settings → Software Update**

---

## 9. Restart Services (If Needed)

If Nessus becomes unresponsive:

```bash
sudo systemctl restart nessusd
```

---

## 10. Troubleshooting Common Issues

### Cannot Access Web Interface

Check that the service is running:

```bash
sudo systemctl status nessusd
```

Check service logs:

```bash
sudo journalctl -u nessusd
```

### Plugin Compilation Stuck

Restart the service and allow additional time:

```bash
sudo systemctl restart nessusd
```

### Port 8834 Already in Use

Check what is using the port:

```bash
sudo lsof -i :8834
```

---

# Installation Complete

You now have a fully functional Nessus Essentials installation.

## Next Steps

- Create target hosts and scan policies
- Run vulnerability scans against your target environment
- Export scan reports in HTML format for AI-based prioritization
