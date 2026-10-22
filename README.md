# SOC L1 Incident Investigation Portfolio — Windows + Wazuh

**Purpose:** A public-safe, evidence-led portfolio demonstrating entry-level SOC alert triage and incident reporting using Windows Security/Event Log telemetry forwarded to Wazuh.

> **Important:** These reports are based on screenshots supplied from a personal lab. The screenshots show selected events and Wazuh rule summaries, not complete raw event exports. Findings are therefore limited to what is visible. No real compromise is claimed. Event relationships must be validated against full event records before making a definitive incident determination.

## Lab environment (as observed)

- SIEM: Wazuh Dashboard / Threat Hunting
- Endpoint agent name shown: `Windows-Laptop-2`
- Agent ID shown: `003`
- Agent IP visible in one screenshot: private RFC1918 address (redacted in this public copy)
- Relevant Windows telemetry: authentication failures/success, process creation, account creation, and audit-log-cleared events

## Cases included

1. **Repeated authentication failures** — three visible Wazuh hits for “Logon Failure - Unknown user or bad password” (rule ID `60122`, level 5), within a short interval.
2. **Successful logon** — two visible hits for “Windows Workstation Logon Success” (rule ID `60118`, level 3). The screenshot does not establish that these are the same authentication flow as the failures.
3. **Process execution context** — `ipconfig.exe` is shown with `cmd.exe` as parent in one event and PowerShell as parent in another. `ipconfig.exe` is a normal Windows utility; its presence alone is not malicious.
4. **Account creation** — Windows event message says “A user account was created”; the visible details include account name `Ansh2`. Verify the Windows Event ID and actor/target fields from the full event before concluding whether the creation was authorized.
5. **Security audit log cleared** — event message says “The audit log was cleared”; Wazuh shows rule ID `63103`, level 5, with two hits. This deserves review because clearing logs can remove forensic context, but a test/admin action is also possible.

## Classification approach

- **Inconclusive** is used when screenshots do not provide enough context to establish malicious or authorized activity.
- Do not label a case **True Positive** solely because a detection fired.
- Do not label a case **False Positive** unless evidence shows the detection condition was not present.
- **Benign Positive** requires evidence that the activity occurred and was authorized/legitimate.

## Limitations

- Screenshots are partial and do not provide all raw XML/JSON fields.
- Source IP, logon type, status/substatus, logon ID, actor/target account, process command line, and event IDs are not consistently visible.
- Timezone conversions and event-to-event correlation should be confirmed using raw records. Wazuh table timestamps are displayed in local UI time; Windows `systemTime` values shown in details are UTC.
- Screenshots do not prove a breach, malware execution, or successful attacker access.
- Local identifiers have been redacted in selected screenshots for public sharing. Review every artifact before publishing.

## Suggested next steps

1. Export raw JSON for each relevant event and record `timestamp`, `agent.name`, `data.win.system.eventID`, `data.win.eventdata.*`, and `rule.id`.
2. Correlate events using host, account, logon ID, source IP, and a bounded time window—not timestamp proximity alone.
3. Confirm whether the account creation and audit-log clearing were expected lab actions.
4. Add a detection/query section with the exact Wazuh DQL/KQL query used, time range, and event count.
5. Update classifications only when the evidence supports them.

## Evidence index

- `evidence/05-auth-failures.png`
- `evidence/06-auth-success.png`
- `evidence/07-log-cleared-results.png`
- `evidence/09-process-details-powershell.png`
- `evidence/10-process-details-cmd.png`
- `evidence/11-account-created-details.png`
- `evidence/14-event-summary.png`

## Disclaimer

This is an educational lab portfolio. It is not a claim of a real-world security incident, professional SOC employment, or confirmed compromise. All investigation conclusions are bounded by the evidence supplied.
