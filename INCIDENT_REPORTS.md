# SOC L1 Incident Investigation Reports

> Evidence-led lab portfolio based on supplied Wazuh screenshots. These screenshots do not prove a real compromise; conclusions are bounded by the visible fields.

## Environment and evidence handling

- Wazuh Threat Hunting; agent `Windows-Laptop-2`, ID `003`.
- Cases cover authentication failures/success, process execution, account creation, and audit-log clearing.
- UI timestamps appear in local time; visible Windows `systemTime` values are UTC and should be validated against raw records.
- Partial screenshots omit important fields. Missing facts are recorded as gaps, not invented.

## Classification definitions

- **True Positive:** detection correctly identifies the behavior it was designed to detect, supported by evidence.
- **False Positive:** evidence shows the detected condition was not present.
- **Benign Positive:** activity occurred and is verified as authorized/legitimate.
- **Inconclusive:** evidence is insufficient to decide.

---

## Incident 01 — Repeated Authentication Failures

**Incident ID:** `SOC-LAB-001`  
**Severity:** Low–Medium, provisional  
**Confidence:** High that three failures are shown; low on cause  
**Classification:** **Inconclusive (provisional)**

### Executive summary

Wazuh shows three hits for “Logon Failure - Unknown user or bad password” on Windows-Laptop-2 at 04:32:31.896, 04:32:34.130 and 04:32:36.154 on 22 Oct 2026. Rule ID 60122, level 5.

### Evidence observed

- Three authentication-failure rows are visible; rule ID 60122 and level 5.
- The view is filtered to agent ID 003.

### Investigation and analysis

- Three failures in about 4.3 seconds may result from a typo, stale credentials, an unknown username, a script, or password guessing.
- The screenshot does not show account, source IP, status/substatus or logon type. Three failures alone do not prove brute force or compromise.

### MITRE ATT&CK

No technique confirmed. T1110.001 (Password Guessing) is only a hypothesis if broader evidence supports it.

### Impact

No impact confirmed.

### Recommended actions

1. Open raw events and capture target account, source IP, logon type, status/substatus and timestamp.
2. Search a bounded time window for frequency by source and target account.
3. Check whether a successful login follows and compare account/source/context.
4. Confirm whether the events were intentionally generated in the lab.

### Limitations

Only summary rows are visible; raw payload and source/account fields are missing.

### Escalation decision

Escalate if failures persist, target privileged accounts, span many accounts, originate from an unauthorized source, or are followed by suspicious success.

---

## Incident 02 — Successful Logon; Correlation Pending

**Incident ID:** `SOC-LAB-002`  
**Severity:** Low–Medium, provisional  
**Confidence:** High that two success-rule hits are shown; low that they correlate to Incident 01  
**Classification:** **Inconclusive (provisional)**

### Executive summary

A separate screenshot shows two “Windows Workstation Logon Success” hits at 04:32:38.529 on 22 Oct 2026, rule ID 60118, level 3. Screenshots alone do not prove these successes are related to the failures.

### Evidence observed

- Two success-rule rows are visible for Windows-Laptop-2.
- Both rows display the same timestamp; underlying documents need inspection.

### Investigation and analysis

- Correlate using account, source IP, logon type, logon ID and raw Windows event fields, not time proximity alone.
- Two hits may be duplicate/related records or separate records; do not count them as two distinct logons without checking.
- No evidence shown establishes unauthorized access.

### MITRE ATT&CK

No technique confirmed; do not assert brute force or initial access without context.

### Impact

No impact confirmed.

### Recommended actions

1. Inspect Event ID and fields such as TargetUserName, IpAddress, LogonType, LogonId and AuthenticationPackageName.
2. Compare these fields with the failed events.
3. Validate account owner, approved VPN/source and whether the login was expected.
4. Review subsequent process, privilege and network activity.

### Limitations

Raw 4624 fields are not visible; same-sequence correlation is unproven.

### Escalation decision

Escalate if the login is confirmed unauthorized or followed by suspicious activity; otherwise document the authorized lab login.

---

## Incident 03 — Process Execution: ipconfig.exe

**Incident ID:** `SOC-LAB-003`  
**Severity:** Informational–Low, provisional  
**Confidence:** High that process and parent paths are visible; low regarding intent  
**Classification:** **Inconclusive (provisional)**

### Executive summary

Two document-detail screenshots show C:\Windows\System32\ipconfig.exe. One has cmd.exe as parent; another has PowerShell as parent. The visible subject username is Ansh2.

### Evidence observed

- New process path: C:\Windows\System32\ipconfig.exe.
- Parent process shown in one record: C:\Windows\System32\cmd.exe.
- Parent process shown in another record: PowerShell.
- Subject username shown: Ansh2.

### Investigation and analysis

- ipconfig.exe is a normal Windows utility. cmd.exe or PowerShell as its parent is not inherently suspicious.
- The screenshots do not show the full command line, initiating context or follow-on activity.
- The two parent-process examples should not be treated as one chain without timestamps and identifiers.

### MITRE ATT&CK

T1016 (System Network Configuration Discovery) may fit if adversarial discovery is supported by context; normal ipconfig use alone is insufficient.

### Impact

No impact confirmed.

### Recommended actions

1. Inspect raw Event ID 4688, command line if enabled, parent process, subject user/logon ID and timestamp.
2. Confirm whether execution matches the lab action.
3. Check PowerShell Operational logs and adjacent telemetry if context is suspicious.
4. Document a benign explanation only if validated.

### Limitations

Command line and reason for execution are not visible.

### Escalation decision

Do not escalate solely because ipconfig.exe ran; escalate if surrounding evidence supports unauthorized discovery or other suspicious activity.

---

## Incident 04 — User Account Created

**Incident ID:** `SOC-LAB-004`  
**Severity:** Medium, provisional; privilege and authorization matter  
**Confidence:** High that account-created message is visible; low on authorization  
**Classification:** **Inconclusive (provisional)**

### Executive summary

A Wazuh detail shows “A user account was created,” account name Ansh2, provider Microsoft-Windows-Security-Auditing, and AUDIT_SUCCESS. The full event ID and actor/target fields are not fully visible.

### Evidence observed

- Message says “A user account was created.”
- Visible account name: Ansh2.
- Provider: Microsoft-Windows-Security-Auditing; severity AUDIT_SUCCESS.
- Visible systemTime: 2026-10-21T23:12:10.5633843Z, approximately 22 Oct 2026 04:42:10 IST.

### Investigation and analysis

- Account creation may be normal lab setup or unauthorized persistence; context decides.
- AUDIT_SUCCESS means the action was recorded as successful, not that it was approved.
- Actor identity, group membership, authorization and subsequent use are not established.

### MITRE ATT&CK

No technique confirmed. T1098 (Account Manipulation) requires supporting adversary context.

### Impact

Potential unauthorized account creation; no compromise or privilege impact confirmed.

### Recommended actions

1. Verify the full Event ID (often 4720 for account creation), subject/actor, target account and logon ID.
2. Confirm whether this was an authorized lab action.
3. Review group membership changes, account enablement and subsequent logons.
4. If unauthorized, preserve evidence and escalate.

### Limitations

Full event ID, actor, privileges and approval context are not visible.

### Escalation decision

Escalate promptly if the account was unapproved, privileged or used suspiciously; otherwise document the authorized test.

---

## Incident 05 — Security Audit Log Cleared

**Incident ID:** `SOC-LAB-005`  
**Severity:** Medium–High, provisional  
**Confidence:** High that log-cleared message and rule hits are visible; low on intent  
**Classification:** **Inconclusive (provisional)**

### Executive summary

Wazuh shows two “The audit log was cleared” hits, rule ID 63103, level 5. A detail panel shows account Ansh2 and systemTime 2026-10-21T23:14:38.0883367Z (about 22 Oct 2026 04:44:38 IST).

### Evidence observed

- Two result rows show rule ID 63103, level 5.
- Message: “The audit log was cleared.”
- Visible account context includes Ansh2; provider shown is Microsoft-Windows-Eventlog.

### Investigation and analysis

- Clearing logs can reduce forensic visibility and is security-relevant, but can also be an intentional lab/admin action.
- Windows Security Event ID 1102 is commonly associated with the Security audit log being cleared; verify the raw event ID.
- Two hits may be duplicate/related records; inspect document IDs before claiming two separate clear operations.

### MITRE ATT&CK

T1070.001 (Clear Windows Event Logs) may be relevant if adversarial defense evasion is supported; do not infer malicious intent from a lab event alone.

### Impact

Potential loss of audit evidence; no further impact confirmed.

### Recommended actions

1. Preserve current telemetry; do not clear more logs.
2. Verify raw event ID, subject, logon ID, timestamp and whether hits are distinct.
3. Check whether the event came from an intentional lab/admin action.
4. Correlate with process creation, logon, PowerShell and account activity; document any visibility gap.

### Limitations

The initiating process and motive are not shown; raw records are needed.

### Escalation decision

Escalate promptly if unexpected, especially alongside suspicious account creation or other anomalies. If intentional lab activity, document it.

---

## Cross-case assessment

- These screenshots do not establish a single attack chain by themselves.
- Correlate failures and successes by account, source IP, logon type, logon ID and raw event data—not timestamp proximity alone.
- `ipconfig.exe` is a normal Windows utility; its presence alone does not prove malicious activity.
- Account creation and audit-log clearing require authorization/context validation.
- No confirmed compromise or business impact is demonstrated by the supplied screenshots.

## Evidence index

- `evidence/05-auth-failures.png` — Authentication Failures
- `evidence/06-auth-success.png` — Authentication Success
- `evidence/07-log-cleared-results.png` — Audit Log Cleared
- `evidence/09-process-details-powershell.png` — PowerShell Parent Process
- `evidence/10-process-details-cmd.png` — CMD Parent Process
- `evidence/11-account-created-details.png` — Account Created
- `evidence/14-event-summary.png` — Process Event Summary

## Public sharing checklist

- Review every screenshot for identifiers you do not want public.
- Never publish credentials, tokens, private keys or sensitive organizational data.
- Be prepared to explain evidence gaps and provisional classifications in interviews.
