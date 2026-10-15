
# Enterprise SOC Lab

A hands-on Security Operations Center (SOC) training project focused on authentication log analysis, brute-force detection, KQL, automated testing, and incident response.

## Objectives

- Analyze authentication logs using Python.
- Detect repeated failed logins within a rolling time window.
- Write KQL detection queries for Microsoft Sentinel.
- Test detection logic with automated unit tests.
- Document findings using an incident report.

## Environment

- OS: Ubuntu 24.04 LTS
- Python: 3.12
- Data: Synthetic authentication logs
- Query language: Kusto Query Language (KQL)
- Dependencies: Python standard library

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
├── tests/
│   └── test_analyze_auth_logs.py
├── .gitignore
└── README.md
```

## Detection Scenario: Brute-Force Login Attempts

The Python detector identifies source IP addresses with at least five failed authentication attempts within a rolling five-minute window.

### Run the detector

From the repository root:

```bash
python3 detections/analyze_auth_logs.py
```

### Run automated tests

```bash
python3 -m unittest discover -s tests -v
```

### Test coverage

The current test suite validates:

1. Five failures trigger an alert.
2. Four failures do not trigger an alert.
3. Failed attempts from different IPs are not combined.
4. Failures outside the same five-minute window do not trigger an alert.

**Latest test result:** 4 tests passed.

## KQL Detection

`detections/01-brute-force-login.kql` contains a detection query designed for Microsoft Sentinel sign-in telemetry.

The query uses the `SigninLogs` table to aggregate failed sign-ins by IP address and five-minute time window.

**Validation status:** The query has not been validated against a live Microsoft Sentinel workspace. It requires a suitable workspace with the expected table and fields.

The file `kql/01-kql-basics.kql` contains exercises for filtering, projection, aggregation, and sorting using sample data.

## Incident Report

`incidents/INC-001-brute-force.md` documents the simulated alert, supporting evidence, analysis, recommended investigation steps, and potential MITRE ATT&CK mapping.

The activity is classified as potential brute-force behavior, not a confirmed security incident.

## Limitations

- All authentication events are synthetic and intended for training.
- The sample IP addresses are reserved for documentation and examples.
- The Python detector focuses on failed logins and does not independently determine whether a subsequent successful login was unauthorized.
- The Sentinel KQL query has not been tested against live security telemetry.
- The detection threshold is a configurable training value, not a universal indicator of malicious activity.

## Future Improvements

- Add tests for malformed log entries and missing fields.
- Improve investigation timelines by correlating failed and successful logins.
- Add additional detection scenarios.
- Validate detections against a suitable SIEM dataset.
- Capture reproducible evidence of test results.

## Disclaimer

This project is for educational and portfolio purposes only. It does not monitor a real organization or production environment.
