
import csv
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "detections"
    / "analyze_auth_logs.py"
)


def run_detector(rows):
    with tempfile.TemporaryDirectory() as temp_dir:
        log_path = Path(temp_dir) / "authentication.log"

        with log_path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=["timestamp", "source_ip", "username", "status"],
            )
            writer.writeheader()
            writer.writerows(rows)

        result = subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--log-file",
                str(log_path),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout


def event(second, ip="203.0.113.10", username="admin", status="Failed"):
    return {
        "timestamp": f"2026-10-15T10:00:{second:02d}Z",
        "source_ip": ip,
        "username": username,
        "status": status,
    }


class BruteForceDetectorTests(unittest.TestCase):

    def test_five_failures_trigger_alert(self):
        rows = [event(second) for second in [0, 5, 10, 15, 20]]
        output = run_detector(rows)

        self.assertIn("ALERT: Potential brute-force activity", output)
        self.assertIn("203.0.113.10", output)

    def test_four_failures_do_not_trigger_alert(self):
        rows = [event(second) for second in [0, 5, 10, 15]]
        output = run_detector(rows)

        self.assertIn("No activity met the detection threshold.", output)

    def test_different_ips_are_not_combined(self):
        rows = [
            event(0, ip="203.0.113.10"),
            event(5, ip="203.0.113.10"),
            event(10, ip="198.51.100.20"),
            event(15, ip="198.51.100.20"),
            event(20, ip="192.0.2.30"),
        ]
        output = run_detector(rows)

        self.assertIn("No activity met the detection threshold.", output)

    def test_failures_outside_five_minute_window_do_not_alert(self):
        timestamps = [
            "2026-10-15T10:00:00Z",
            "2026-10-15T10:01:00Z",
            "2026-10-15T10:02:00Z",
            "2026-10-15T10:03:00Z",
            "2026-10-15T10:06:00Z",
        ]

        rows = [
            {
                "timestamp": timestamp,
                "source_ip": "203.0.113.10",
                "username": "admin",
                "status": "Failed",
            }
            for timestamp in timestamps
        ]

        output = run_detector(rows)

        self.assertIn("No activity met the detection threshold.", output)


if __name__ == "__main__":
    unittest.main()
