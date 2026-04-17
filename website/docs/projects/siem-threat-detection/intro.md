---
title: "Introduction"
sidebar_position: 1
---

# 🔐 Microsoft Sentinel Threat Detection Lab

## 📌 Overview

This project demonstrates how to build an **end-to-end threat detection and response workflow** using Microsoft Sentinel, with a focus on **identity-based attack scenarios**.

Instead of enabling all available detections, this lab follows a **use-case driven approach**, simulating realistic attack behaviour and implementing targeted detection logic using KQL.

---

## 🧠 Key Objectives

- Build a working SIEM lab using Microsoft Sentinel  
- Simulate real-world identity-based attack scenarios  
- Develop custom detection logic using KQL  
- Implement automated response using playbooks (SOAR)  
- Optimize data ingestion to reduce unnecessary cost  

---

## 🏗️ Architecture

Entra ID (Users & Logs)  
↓  
Data Connectors (Sign-in / Audit Logs)  
↓  
Microsoft Sentinel  
↓  
Analytics Rules (Detection)  
↓  
Incidents & Investigation  
↓  
Playbooks (SOAR Automation)  

---

## 🔌 Data Sources

- Entra ID Sign-in Logs  
- Entra ID Audit Logs  

---

## 🚨 Detection Use Cases

### 🥇 1. Password Spray Attack

**Description:**  
Simulates multiple failed login attempts across different user accounts using a single password.

**Detection Logic:**  
- Multiple failed logins from the same IP  
- Multiple user accounts targeted within a short time window  

**MITRE ATT&CK:**  
- T1110.003 – Password Spraying  

**Response:**  
- Alert and incident generation in Microsoft Sentinel  
- Automated notification via playbook  

---

### 🌍 2. Impossible Travel Detection

**Description:**  
Detects suspicious login activity where the same user account signs in from geographically distant locations within a short time period.

**Detection Logic:**  
- Successful logins from the same user  
- Multiple geographic locations  
- Short time window between login events  

**MITRE ATT&CK:**  
- T1078 – Valid Accounts  

**Response:**  
- Alert and incident generation  
- Investigation of user activity and login sources  
- Optional response actions (MFA enforcement, password reset, IP blocking)  

---

### 🥈 3. Privilege Escalation *(In Progress)*

**Description:**  
Monitors role assignments and privilege elevation events within Entra ID.

**Detection Focus:**  
- Addition of users to privileged roles  
- Administrative activity in Audit Logs  

---

## 🔎 Threat Hunting Approach

Hypothesis → Query → Evidence → Detection Rule  

---

## ⚙️ Automation (SOAR)

- Triggered automatically when incidents are created  
- Sends notifications (Email / Teams)  
- Can be extended to perform response actions (e.g., block IP, create tickets)  

---

## 💰 Cost Optimization

- Enable only required data connectors  
- Generate minimal logs for testing  
- Remove unused resources after lab completion  

---

## 🧪 Key Learnings

- Built a Microsoft Sentinel environment from scratch, including workspace setup, data connectors, and analytics rules  
- Detection quality is more important than log volume  
- Identity-based logs provide high detection value  
- Behavioural detection is effective for identifying compromise  
- Proper threshold tuning reduces false positives  
- Hunting queries can be operationalised into detection rules  
- Automation improves response efficiency 

---

## 💡 Key Takeaway

Focus on **high-signal data and meaningful detection logic**, rather than enabling all available detections.

---

## 🚀 Future Improvements

- Complete Privilege Escalation detection  
- Integrate Microsoft Defender signals  
- Explore UEBA / Fusion detections  
- Implement automated containment actions  

---

## 📎 Technologies Used

- Microsoft Sentinel  
- Microsoft Entra ID  
- KQL (Kusto Query Language)  
- Azure Logic Apps  

---

## 🧑‍💻 Author

Hands-on cybersecurity lab project demonstrating practical detection engineering and SIEM design skills.