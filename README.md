# Enterprise SOC Lab

A hands-on Security Operations Center (SOC) training project focused on authentication log analysis, brute-force detection, KQL, and incident response.

## Project Objectives

- Analyze authentication events using Python.
- Detect repeated failed login attempts within a defined time window.
- Practice writing KQL detection queries for Microsoft Sentinel.
- Document findings in a structured incident report.
- Develop practical SOC investigation and documentation skills.

## Lab Environment

- OS: Ubuntu 24.04 LTS
- Python: 3.12
- Data: Synthetic authentication logs
- Query language: Kusto Query Language (KQL)

## Repository Structure

```text
enterprise-soc-lab/
├── data/
│   └── authentication.log
├── detections/
│   ├── 01-brute-force-login.kql
│   └── analyze_auth_logs.py
├── incidents/
│   └── INC-001-brute-force.md
├── kql/
│   └── 01-kql-basics.kql
├── notes/
│   └── day-01.md
└── README.md
```

## Detection: Potential Brute-Force Activity

The Python script analyzes authentication logs and identifies source IP addresses with at least five failed login attempts within a rolling five-minute window.

### Run the detection

Requirements: Python 3.10 or newer. No third-party Python packages are required.

```bash
python3 detections/analyze_auth_logs.py
```

### Sample result

```text
=== Brute-Force Detection ===

ALERT: Potential brute-force activity
Source IP: 203.0.113.50
Failed attempts in 5 minutes: 5
Targeted users: admin, mike, root
Window: 2026-10-15T10:00:00+00:00 to 2026-10-15T10:00:20+00:00

Total IP alerts: 1
```

The result above was produced using the lab's synthetic dataset.

## KQL Detection

The file `detections/01-brute-force-login.kql` contains a detection query designed for Microsoft Sentinel authentication data.

It uses the `SigninLogs` table to aggregate failed sign-in attempts by source IP and five-minute time window.

**Note:** This query requires a Microsoft Sentinel workspace containing the expected sign-in data. It has not been validated against a live Sentinel workspace in this lab.

The exercises in `kql/01-kql-basics.kql` use sample data to practice KQL filtering, projection, aggregation, and sorting.

## Incident Response

The report `incidents/INC-001-brute-force.md` documents the simulated alert, evidence, analysis, recommended investigation steps, and potential MITRE ATT&CK mapping.

The activity is classified as potential brute-force behavior, not a confirmed security incident.

## Limitations

- All authentication events are synthetic and intended for training.
- The Python detector analyzes failed logins; it does not independently determine whether a subsequent successful login was unauthorized.
- The KQL detection has not been tested against a live Microsoft Sentinel workspace.
- Alert thresholds are configurable training values, not universal indicators of malicious activity.

## Future Improvements

- Add automated unit tests for the Python detector.
- Improve alert output and include successful logins in the investigation timeline.
- Add additional detection scenarios.
- Capture and document test results.
- Validate KQL queries against an appropriately configured SIEM environment.

## Disclaimer

This project is for educational and portfolio purposes only. It does not represent monitoring of a real organization or production environment.
