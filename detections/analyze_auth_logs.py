
import argparse
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

DEFAULT_LOG_FILE = Path("data/authentication.log")
THRESHOLD = 5
WINDOW = timedelta(minutes=5)


def detect_brute_force(log_file):
    events_by_ip = defaultdict(list)

    with log_file.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            if row["status"].strip().lower() != "failed":
                continue

            timestamp = datetime.fromisoformat(
                row["timestamp"].replace("Z", "+00:00")
            )

            events_by_ip[row["source_ip"]].append({
                "timestamp": timestamp,
                "username": row["username"],
            })

    alerts = []

    for ip, events in events_by_ip.items():
        events.sort(key=lambda event: event["timestamp"])
        window_events = deque()

        for event in events:
            window_events.append(event)

            while (
                window_events
                and event["timestamp"] - window_events[0]["timestamp"] > WINDOW
            ):
                window_events.popleft()

            if len(window_events) >= THRESHOLD:
                alerts.append({
                    "source_ip": ip,
                    "failed_attempts": len(window_events),
                    "targeted_users": sorted({
                        item["username"] for item in window_events
                    }),
                    "start": window_events[0]["timestamp"],
                    "end": event["timestamp"],
                })
                break

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Detect potential brute-force login activity."
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help="Path to the authentication CSV log file.",
    )
    args = parser.parse_args()

    if not args.log_file.is_file():
        parser.error(f"Log file not found: {args.log_file}")

    alerts = detect_brute_force(args.log_file)

    print("=== Brute-Force Detection ===")

    for alert in alerts:
        print("\nALERT: Potential brute-force activity")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Failed attempts in 5 minutes: {alert['failed_attempts']}")
        print(f"Targeted users: {', '.join(alert['targeted_users'])}")
        print(
            f"Window: {alert['start'].isoformat()} "
            f"to {alert['end'].isoformat()}"
        )

    if not alerts:
        print("No activity met the detection threshold.")
    else:
        print(f"\nTotal IP alerts: {len(alerts)}")


if __name__ == "__main__":
    main()
