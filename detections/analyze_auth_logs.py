
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

LOG_FILE = "data/authentication.log"
THRESHOLD = 5
WINDOW = timedelta(minutes=5)

events_by_ip = defaultdict(list)

with open(LOG_FILE, newline="", encoding="utf-8") as file:
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

print("=== Brute-Force Detection ===")

alerts = 0

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
            users = sorted({
                item["username"] for item in window_events
            })

            print(f"\nALERT: Potential brute-force activity")
            print(f"Source IP: {ip}")
            print(f"Failed attempts in 5 minutes: {len(window_events)}")
            print(f"Targeted users: {', '.join(users)}")
            print(
                "Window: "
                f"{window_events[0]['timestamp'].isoformat()} "
                f"to {event['timestamp'].isoformat()}"
            )
            alerts += 1
            break

if alerts == 0:
    print("No activity met the detection threshold.")
else:
    print(f"\nTotal IP alerts: {alerts}")
