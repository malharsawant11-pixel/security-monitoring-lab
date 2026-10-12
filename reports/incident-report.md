# Incident Investigation Report

## 1. Summary
A controlled test dataset was analyzed for repeated failed
authentication events. The detection script flagged a source
after it reached the configured threshold of three failures.

## 2. Scope
This investigation used synthetic CSV records in a local
Kali Linux lab. No real security incident was investigated.

## 3. Evidence
- Source IP: 192.0.2.10
- Failed authentication events: 3
- Detection threshold: 3
- Result: Alert generated

The IP address is reserved for documentation and is not evidence
of a real attacker.

## 4. Assessment
The sample data met the configured alert threshold.
This alone does not establish malicious activity or prove
that an account was compromised.

## 5. Recommended Follow-up
- Review relevant authentication logs and timestamps.
- Check the account and source context.
- Correlate events with endpoint and network telemetry.
- Escalate only if additional evidence supports suspicion.

## 6. Limitations
The prototype processes CSV files and counts event ID 4625.
It does not monitor a live endpoint or correlate events over
a time window.

## 7. Conclusion
The lab demonstrated threshold-based authentication log
analysis, automated testing, and structured incident reporting.
