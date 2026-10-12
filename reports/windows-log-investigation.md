# Windows Security Log Investigation

## 1. Objective
Examine Windows authentication events and understand how
successful and failed logons are recorded.

## 2. Environment
- Host operating system: Windows
- Analysis environment: Kali Linux in Oracle VirtualBox
- Log source: Windows Event Viewer
- Log category: Windows Logs > Security

## 3. Events Examined
- Event ID 4624: Successful logon
- Event ID 4625: Failed logon

## 4. Methodology
1. Opened Windows Event Viewer.
2. Examined the Security event log.
3. Filtered for event IDs 4624 and 4625.
4. Opened event details and reviewed available fields.
5. Avoided including identifying information in this report.

## 5. Findings
- Both successful and failed logon events were present.
- A successful logon event was examined.
- The numeric logon type still needs to be verified.
- A failure reason was not available in the fields examined.
- No conclusion about malicious activity can be made from
  these observations alone.

## 6. Security Assessment
Successful and failed logons are normal Windows security
events. Repeated failures, unusual logon types, unexpected
accounts, or suspicious source addresses may warrant further
investigation when supported by additional evidence.

The presence of both event types does not establish that
an account was compromised.

## 7. Recommended Follow-up
- Record the numeric logon type from event 4624.
- Inspect the status and substatus fields of event 4625.
- Compare event timestamps and relevant account context.
- Correlate suspicious activity with other available logs.
- Escalate only when additional evidence supports concern.

## 8. Limitations
- Exact event counts and timestamps have not been documented.
- The logon type has not yet been verified.
- The failure reason was not available in the fields examined.
- No confirmed security incident was established.

## 9. Conclusion
This exercise demonstrated how to locate and examine Windows
authentication events. Further contextual analysis is needed
before determining whether any activity is suspicious.
