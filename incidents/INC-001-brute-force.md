# INC-001 — Potential Brute-Force Activity

## 1. Incident Summary
- **Incident ID:** INC-001
- **Title:** Potential Brute-Force Login Activity
- **Severity:** Medium (provisional)
- **Status:** Investigating
- **Detection Type:** Authentication Anomaly
- **Environment:** Synthetic training lab

## 2. Executive Summary
Repeated failed authentication attempts were observed from a single source IP address against multiple usernames. The activity met the lab detection threshold of five failed attempts within five minutes.

This pattern may indicate brute-force activity or automated credential guessing. The finding is based on synthetic training data and does not represent a real security incident.

## 3. Evidence
- **Source IP:** 203.0.113.50
- **Failed Attempts:** 5
- **Targeted Usernames:** admin, root, mike
- **Time Window:** 2026-10-15 10:00:00–10:00:20 UTC
- **Related Event:** A successful login for `mike` followed the failed attempts in the sample data.

## 4. Analysis
The repeated failures and use of multiple usernames are consistent with a possible credential-guessing pattern.

The subsequent successful login deserves further investigation. However, the available sample data does not establish whether the login was legitimate or unauthorized.

## 5. Recommended Response
1. Review authentication records around the alert time.
2. Verify whether the successful login was expected by the account owner.
3. Check for other suspicious activity associated with the source IP.
4. Review MFA status and relevant account protection controls.
5. If unauthorized access is confirmed, follow the organization's account containment and credential-reset procedures.

## 6. MITRE ATT&CK Mapping
- **T1110 — Brute Force:** Potential technique; requires further validation.

## 7. Limitations
- All events are synthetic and intended for training.
- No real endpoint, identity provider, or SIEM telemetry was collected.
- The severity is provisional and should be reassessed if this were a real incident.

## 8. Conclusion
The detection successfully identified a repeated authentication-failure pattern in the training dataset. Further validation would be required before classifying the activity as a confirmed security incident.
