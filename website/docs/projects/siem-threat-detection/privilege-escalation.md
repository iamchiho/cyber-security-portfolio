---
title: "🔑 Use Case 3: Privilege Escalation Detection"
sidebar_position: 3
---

# 🔑 Use Case 3: Privilege Escalation Detection

## 🔐 Overview

This use case detects suspicious privilege escalation activity in Microsoft Entra ID, where a user is assigned to a privileged role.

Such behaviour may indicate unauthorized administrative access or potential account compromise.

![OpenVAS Dashboard](/img/siem-threat-detection/03-privilege-escalation-flow.png)

---

## 🎯 Objective

Identify high-risk administrative actions by monitoring:

- Permanent role assignments  
- Unusual or unauthorized privilege elevation events  

---

## 🧠 Detection Flow (Step-by-Step)

### Step 1: Privileged role assignment occurs
An administrative action is performed where a user is assigned to a privileged role (e.g., Global Administrator).

![OpenVAS Dashboard](/img/siem-threat-detection/03-assign-user-admin-role.png)

---

### Step 2: Logs generated in Entra ID
The role assignment activity is recorded in Entra ID Audit Logs.

![OpenVAS Dashboard](/img/siem-threat-detection/03-audit-log.png)

---

### Step 3: Logs ingested into Microsoft Sentinel
Audit Logs are collected via data connectors and ingested into Microsoft Sentinel.

![OpenVAS Dashboard](/img/siem-threat-detection/03-audit-log-sentinel.png)

---

### Step 4: Analytics rule evaluates the activity
A KQL-based analytics rule detects role assignment events.

---

### Step 5: Alert is generated
Sentinel generates an alert when a privileged role assignment is detected.

---

### Step 6: Incident is created
The alert is grouped into an incident for investigation.

---

### Step 7: Investigation
The analyst reviews:
- Initiator  
- Target user  
- Assigned role  

---

### Step 8: Response actions
- Verify legitimacy of role assignment  
- Remove unauthorized access  
- Review audit logs  
- Apply least privilege principle  

---

## 🔍 KQL Query

```sql
AuditLogs
| where OperationName contains "Add member to role"
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].userPrincipalName)
| extend Role = tostring(TargetResources[0].displayName)
| project TimeGenerated,
          OperationName,
          Initiator,
          Target,
          Role,
          Result
| order by TimeGenerated desc
```

---

## 🧩 Entity Mapping

- Account → InitiatedBy.user.userPrincipalName  
- Target Account → TargetResources.userPrincipalName  

---

## 🧭 MITRE ATT&CK Mapping

- Technique: T1098 – Account Manipulation  
- Tactic: Persistence / Privilege Escalation  

---

## 🧪 Simulation Method

1. Go to Microsoft Entra ID  
2. Assign a user to a privileged role (e.g., Global Administrator)  
3. Observe the generated Audit Logs  

---

## 🚨 Alert Description

This alert is triggered when a user is assigned to a privileged role, indicating potential privilege escalation.

---

## ⚠️ False Positives

This detection may generate false positives in legitimate scenarios:

- Authorized administrative role assignments  
- Routine access changes by IT administrators  

### Reduce False Positives

- Filter known admin accounts  
- Monitor only high-risk roles  
- Apply approval workflows  

---

## 🚀 Future Enhancement: Privileged Identity Management (PIM)

This detection can be enhanced by integrating Microsoft Entra ID Privileged Identity Management (PIM), which introduces:

- Just-in-Time (JIT) access  
- Role activation instead of permanent assignment  
- Approval workflows  
- Time-bound privilege elevation  

Future detection improvements may include:

- Monitoring PIM activation events (e.g., "Activate eligible role")  
- Correlating approval status with role activation  
- Detecting abnormal activation timing (e.g., outside business hours)  

---

## 📌 Summary

1. Detects privileged role assignments using Entra ID Audit Logs  
2. Identifies administrative actions that may indicate privilege escalation  
3. Uses KQL to monitor role assignment events  
4. Maps both initiator and target entities for investigation  
5. Aligns with MITRE ATT&CK T1098 (Account Manipulation)  
6. Can be extended to support PIM-based detection in future  
