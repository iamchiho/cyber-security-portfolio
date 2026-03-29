---
title: "Openvas Installation"
sidebar_position: 2
---

# Installation

# OpenVAS Installation Guide (Greenbone Community Edition)

This document provides a complete step-by-step guide to installing OpenVAS using the Greenbone Community Edition (GVM) on Ubuntu Linux.

OpenVAS is part of the Greenbone Vulnerability Management (GVM) framework and provides comprehensive vulnerability scanning capabilities.

---

## 1. System Requirements

Before installation, ensure your system meets the following requirements:

- Ubuntu 20.04 or 22.04 (Recommended)
- Minimum 4 GB RAM (8 GB Recommended)
- At least 20 GB free disk space
- Root or sudo privileges
- Stable internet connection (required for vulnerability feed updates)

---

## 2. Update the System

Update package lists and upgrade installed packages:

```bash
sudo apt update
sudo apt upgrade -y
```

---

## 3. Install OpenVAS (GVM)

Install Greenbone Vulnerability Manager:

```bash
sudo apt install gvm -y
```

This will install:

- OpenVAS Scanner
- Greenbone Security Assistant (Web Interface)
- PostgreSQL Database
- Required dependencies

---

## 4. Initialize and Configure OpenVAS

Run the initial setup:

```bash
sudo gvm-setup
```

This process will:

- Configure PostgreSQL database
- Download vulnerability feeds
- Generate SSL certificates
- Configure scanner services
- Create an administrator account

⚠️ Feed synchronization may take 30–60 minutes depending on your internet speed.

At the end of the setup process, the system will display:

- Administrator username  
- Generated password  

Save these credentials securely.

---

## 5. Verify Installation

After setup completes, verify that everything is configured properly:

```bash
sudo gvm-check-setup
```

If successful, you should see:

```
It seems like your GVM installation is OK.
```

If errors appear, follow the instructions shown in the output.

---

## 6. Start OpenVAS Services

If services are not running automatically, start them:

```bash
sudo gvm-start
```

To check service status:

```bash
sudo systemctl status gvmd
sudo systemctl status ospd-openvas
```

---

## 7. Access the Web Interface

Open your browser and navigate to:

```
https://<your-server-ip>:9392
```

Example:

```
https://192.168.1.100:9392
```

You may see a security warning due to a self-signed SSL certificate. Proceed to continue.

Login using the administrator credentials generated during setup.

---

## 8. Reset Administrator Password (Optional)

If you need to reset the admin password:

```bash
sudo runuser -u _gvm -- gvmd --user=admin --new-password=NewPasswordHere
```

---

## 9. Manual Feed Synchronization (If Required)

If vulnerability feeds fail to sync during setup:

```bash
sudo greenbone-feed-sync
```

After syncing, restart services:

```bash
sudo systemctl restart gvmd
sudo systemctl restart ospd-openvas
```

---

## 10. Restart Services (If Needed)

If OpenVAS services become unresponsive:

```bash
sudo gvm-stop
sudo gvm-start
```

---

## 11. Troubleshooting Common Issues

### Feed Update Errors

Check system time:

```bash
timedatectl
```

Restart services:

```bash
sudo gvm-stop
sudo gvm-start
```

### Services Not Starting

Check service logs:

```bash
journalctl -u gvmd
journalctl -u ospd-openvas
```

---

# Installation Complete

You now have a fully functional OpenVAS (Greenbone Community Edition) installation.

## Next Steps

- Create target hosts
- Configure scan tasks
- Run vulnerability scans
- Export scan reports for analysis and AI-based prioritization