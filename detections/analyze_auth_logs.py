import csv
from collections import Counter

LOG_FILE = "data/authentication.log"
THRESHOLD = 5

failed_by_ip = Counter()
users_by_ip = {}

with open(LOG_FILE, newline="", encoding="utf-8") as file:
    reader = csv.DictReader(file)

    for row in reader:
        ip = row["source_ip"]
        username = row["username"]
        status = row["status"].strip().lower()

        if status == "failed":
            failed_by_ip[ip] += 1
            users_by_ip.setdefault(ip, set()).add(username)

print("=== Authentication Log Analysis ===")

for ip, count in failed_by_ip.most_common():
    print(f"IP: {ip} | Failed attempts: {count}")

    if count >= THRESHOLD:
        users = ", ".join(sorted(users_by_ip[ip]))
        print("  ALERT: Potential brute-force activity")
        print(f"  Targeted users: {users}")
