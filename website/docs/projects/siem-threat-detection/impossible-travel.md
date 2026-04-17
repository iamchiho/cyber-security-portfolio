---
title: "Impossible Travel"
sidebar_position: 3
---

## 🔐 Overview

This use case detects suspicious login activity where the same user account signs in from geographically distant locations within a short time period.

![OpenVAS Dashboard](/img/siem-threat-detection/02-impossible-travel-flow.png)

---

## 🧠 Detection Flow (Step-by-Step)

### Step 1: User logs in from two different locations
The same user account signs in from one location (e.g., UK), and shortly after signs in again from a different geographic location (e.g., Turkey).

In this lab, this behaviour is simulated using a VPN.

---

### Step 2: Logs are generated in Entra ID and ingested into Sentinel
Both login events are recorded in Entra ID Sign-in Logs with different location data and ingested into Microsoft Sentinel.

**Login log in Entra ID**
![OpenVAS Dashboard](/img/siem-threat-detection/02-login-log-entra.png)

**Login log in Sentinel**
![OpenVAS Dashboard](/img/siem-threat-detection/02-login-log-sentinel.png)

---

### Step 3: Analytics rule evaluates the activity
A KQL analytics rule analyses login events and compares the locations and timestamps for each user.

**MITRE ATT&CK Mapping**
- Technique: T1078 – Valid Accounts  
- Tactic: Initial Access / Persistence  

This detection aligns with the use of valid credentials by an attacker after compromise.

Impossible travel scenarios often indicate that an attacker is using legitimate user credentials from different geographic locations within a short period of time.

![OpenVAS Dashboard](/img/siem-threat-detection/02-mitre-attack-valid-account.png)

**KQL Query**

```sql
SigninLogs
| where ResultType == 0
| project UserPrincipalName, Location, IPAddress, TimeGenerated
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend prevLocation = prev(Location),
         prevIP = prev(IPAddress),
         prevTime = prev(TimeGenerated)
| where Location != prevLocation
| where datetime_diff("minute", TimeGenerated, prevTime) < 60
```

**Entity mapping**

The detection maps the user account and source IP address as entities in Microsoft Sentinel.

- Account → UserPrincipalName  
- IP → IPAddress  

The account entity is used as the primary investigation pivot, while the IP entity provides additional context about the login source.

![OpenVAS Dashboard](/img/siem-threat-detection/02-entity-mapping.png)

---

### Step 4: Alert is generated
If the same user is observed logging in from different locations within a short time window, Sentinel generates an alert.

---

### Step 5: Incident is created
The alert is grouped into an incident to provide context for investigation.

---

### Step 6: Investigation
The analyst reviews the incident and examines:
- Login locations  
- Time difference between logins  
- User account activity  

**Incident is created**
![OpenVAS Dashboard](/img/siem-threat-detection/02-incident-list.png)

**View Incident details**
![OpenVAS Dashboard](/img/siem-threat-detection/02-incident-details.png)

---

### Step 7: Response actions
- Verify the activity with the user  
- Reset the password if compromise is suspected  
- Enforce MFA  
- Block suspicious IP addresses if required  

---

### 📌 Summary

1. Detects impossible travel behaviour using Entra ID sign-in logs.  
2. Correlates successful logins from different geographic locations.  
3. Identifies abnormal login patterns within a short time window.  
4. Uses KQL analytics for behavioural detection.  
5. Enriches alerts with entity mapping (Account and IP).  
6. Maps to MITRE ATT&CK T1078 (Valid Accounts).  
7. Enables efficient investigation and response.