---
title: "🔑 Use Case 1: Password Spraying"
sidebar_position: 2
---

In this use case, I will simulate a password spraying attack and show how MS Sentinel dealing with this attack.

## Password Spray Use Case Flow

![OpenVAS Dashboard](/img/siem-threat-detection/01-password-spraying-flow.png)

### Step 1: Attacker initiates the attack
The attacker starts a password spray attack by using a single common password against multiple user accounts instead of trying many passwords against one account.

**Goal:**  
Avoid account lockout while increasing the chance of finding a weak password.

For this, I created 3 dummy users in Entra ID (User 1, 2, 3 respectively).

![OpenVAS Dashboard](/img/siem-threat-detection/01-dummy-users.png)

I tried to simulate a password spraying attacking by logging in to those user accounts with same passwords.

---

### Step 2: Multiple failed sign-in attempts are generated
Several failed login attempts are triggered from the same IP address across different Entra ID user accounts.

**What this creates:**  
- Failed sign-in events  
- Repeated authentication failures from one source  
- A suspicious identity-based pattern

---

### Step 3: Entra ID logs are collected by Microsoft Sentinel
The failed sign-in activity is recorded in Entra ID sign-in logs and ingested into Microsoft Sentinel through the configured data connector.

**Relevant data source:**  
- Entra ID Sign-in Logs

**Why this matters:**  
Sentinel now has the raw telemetry needed to detect the attack pattern.

Logs for failed logon activities can be found either in Entra ID and Sentinel

**Entra ID**
![OpenVAS Dashboard](/img/siem-threat-detection/01-entra-failed-logon-logs.png)

**Sentinel**
![OpenVAS Dashboard](/img/siem-threat-detection/01-sentinel-failed-logon-logs.png)

---

### Step 4: Analytics rule evaluates the activity
A custom analytics rule in Sentinel runs on a schedule and checks for suspicious behaviour, such as:
- Multiple failed logins
- Same source IP
- Multiple targeted user accounts
- Short time window

**Example detection logic:**  
Identify repeated failed authentication attempts from the same IP across multiple users within a few minutes.

```sql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count(), Users = dcount(UserPrincipalName)
    by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 5 and Users > 2
```

**Map to MITRE ATT&CK Framework (T1110.003)**

In Analytic Rule settings, I map the rule to MITRE ATT&CK technique.

![OpenVAS Dashboard](/img/siem-threat-detection/01-map-to-mitre-attack-T1110.png)

This detection use case is mapped to the MITRE ATT&CK technique **T1110.003 – Password Spraying** under the **Credential Access** tactic.

Password spraying is a common attack method where an attacker attempts a single password across multiple user accounts to avoid account lockout policies.

This detection identifies the attack by correlating multiple failed authentication attempts from a single source IP across multiple accounts within a short time window.

By focusing on behavioural patterns rather than individual login failures, the rule effectively detects password spray activity and supports early-stage attack detection.

**Entity Mapping**

The detection rule maps the 'IPAddress' field from Entra ID sign-in logs to the **IP entity** in Microsoft Sentinel.

![OpenVAS Dashboard](/img/siem-threat-detection/01-ip-mapping.png)

- Entity Type: IP  
- Identifier: Address  
- Field: IPAddress  

This allows Sentinel to treat the source IP as a structured entity rather than plain text.

**Note: Why IP Mapping Matters**

Password spray attacks are typically characterized by:

- A single source IP  
- Multiple failed login attempts  
- Multiple targeted user accounts  

By mapping the source IP as an entity, the detection enables:

- Faster investigation using IP as a pivot  
- Correlation with other alerts involving the same IP  
- Visualization in the investigation graph  
- Integration with automated response (e.g., blocking IP)  

---

### Step 5: Sentinel generates an alert
When the rule conditions are met, Sentinel creates an alert to indicate suspicious password spray activity.

**Alert purpose:**  
Highlight the suspicious behaviour as a potential attack signal.

![OpenVAS Dashboard](/img/siem-threat-detection/01-alert-settings.png)

---

### Step 6: Sentinel groups the alert into an incident
If incident creation is enabled in the rule, Sentinel creates an incident for investigation.

**Why this matters:**  
An incident provides better context than a single alert and makes investigation easier.

---

### Step 7: Investigation begins
The analyst reviews the incident in Sentinel and examines:
- Source IP address
- Number of failed attempts
- Targeted user accounts
- Time range of the activity

**Objective:**  
Confirm whether the pattern matches a password spray attack.

**Incident is created**
![OpenVAS Dashboard](/img/siem-threat-detection/01-incident-list.png)

**View incident details**
![OpenVAS Dashboard](/img/siem-threat-detection/01-incident-investigation.png)

---

### Step 8: Playbook triggers automated response
If a playbook is attached to the analytics rule or incident, Sentinel can automatically respond.

**Possible actions:**  
- Send email notification
- Send Teams alert
- Create a ticket
- Trigger additional investigation steps
- Block the source IP in a connected security tool

---

### Step 9: Analyst performs follow-up actions
After reviewing the incident, the analyst can decide whether to:
- Escalate the incident
- Block the attacking IP
- Monitor for successful logins
- Reset affected accounts if compromise is suspected

---

## Key Detection Idea

A password spray attack is not identified by one failed login.  
It is identified by a **pattern**:

- Same IP address  
- Multiple failed attempts  
- Multiple user accounts  
- Short time window

---

## Summary

This use case shows how Microsoft Sentinel can detect and respond to password spray activity by:

1. Collecting sign-in logs from Entra ID  
2. Identifying suspicious failed login patterns  
3. Generating alerts and incidents  
4. Supporting investigation  
5. Triggering automated response through playbooks

