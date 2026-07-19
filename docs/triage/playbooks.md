# Analyst triage playbooks

These playbooks preserve the useful incident-response material from the retired endpoint planning repository and align it with the executable detections in this project. They are investigation guides, not automatic containment authorization.

## Suspicious PowerShell command features

**Trigger:** `ENDPOINT-PS-001` matches encoded-command or remote-content features in a Sysmon process-creation event.

**Questions**

- Which user and parent process launched PowerShell?
- Is the complete command known, signed, and expected for that host?
- What does decoded content do when inspected without execution?
- Did the process create files, tasks, accounts, DNS queries, or outbound connections?
- Does the same command or hash appear on other hosts?

**Preserve:** Sysmon Events 1 and 3, PowerShell script-block logs where available, parent/child process data, file hashes, network metadata, and the complete original command.

**Decision:** do not isolate a host solely because PowerShell used encoding. Escalate when the decoded behavior, source, process ancestry, or correlated activity supports malicious execution.

## Unusual LSASS process access

**Trigger:** `ENDPOINT-LSASS-001` matches high-access process activity against LSASS from outside the initial system/Defender path exclusions.

**Questions**

- Is the source binary a known security, authentication, debugging, or forensic tool?
- What are its path, signer, hash, parent process, and user context?
- Did suspicious execution occur immediately before the access?
- Are there subsequent logon, ticket, remote-service, or credential anomalies?

**Preserve:** Sysmon Events 1 and 10, authentication logs, source binary metadata, relevant memory/forensic evidence, and a host timeline.

**Decision:** treat unexplained LSASS access as high priority, but verify the source before declaring credential dumping. If evidence supports compromise, isolate through the approved response process and rotate potentially exposed credentials.

## Cloud IAM privilege expansion

**Trigger:** `AWS-IAM-001` matches a permission-changing CloudTrail API call.

**Questions**

- Who initiated the action, from which session and source?
- Was the change produced by an approved deployment or ticket?
- Which effective permissions were added, and to which principal?
- Can the new permission path create credentials, pass roles, alter logging, or assume broader roles?
- What enumeration or resource access occurred before and after the change?

**Decision:** record the observed API success or failure separately from intended containment. A failed rollback must become a failure state, never a success message.

## AWS root account activity

**Trigger:** `AWS-ROOT-001` observes an AWS API call attributed to the root identity.

**Questions**

- Was there a documented, time-bounded break-glass reason?
- Was MFA used, and is the source network and user agent expected?
- Which other API calls occurred in the session?
- Were credentials, contact settings, policies, trails, or billing controls changed?

**Decision:** escalate unexplained root activity immediately. Preserve the CloudTrail sequence before changing credentials or sessions according to the incident plan.
