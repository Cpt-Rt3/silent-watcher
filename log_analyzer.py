import re
from collections import Counter
from datetime import datetime

LOG_FILE = "sample_auth.log"
ALERT_FILE = "alerts.txt"
BRUTE_FORCE_THRESHOLD = 3

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

ACCEPTED_LOGIN_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def analyze_logs(log_file: str):
    failed_attempts = Counter()
    successful_logins = []
    suspicious_alerts = []

    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            failed_match = FAILED_LOGIN_PATTERN.search(line)
            accepted_match = ACCEPTED_LOGIN_PATTERN.search(line)

            if failed_match:
                ip = failed_match.group("ip")
                user = failed_match.group("user")
                failed_attempts[ip] += 1
                suspicious_alerts.append(
                    f"Failed login attempt detected: user='{user}', ip='{ip}'"
                )

            elif accepted_match:
                ip = accepted_match.group("ip")
                user = accepted_match.group("user")
                successful_logins.append((user, ip))

    return failed_attempts, successful_logins, suspicious_alerts


def detect_brute_force(failed_attempts: Counter, threshold: int):
    brute_force_ips = []
    for ip, count in failed_attempts.items():
        if count >= threshold:
            brute_force_ips.append((ip, count))
    return brute_force_ips


def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_date_only():
    return datetime.now().strftime("%Y-%m-%d")


def write_alerts(alert_file, suspicious_alerts, brute_force_ips, successful_logins):
    filename = f"alerts_{get_date_only()}.txt"

    with open(filename, "w") as f:
        f.write("=== Silent Watcher Alert Report ===\n\n")

        # HIGH severity
        for ip, count in brute_force_ips:
            f.write(f"[{get_timestamp()}] HIGH - Brute force detected from {ip} ({count} attempts)\n")

        # MEDIUM severity
        for alert in suspicious_alerts:
            f.write(f"[{get_timestamp()}] MEDIUM - {alert}\n")

        # INFO
        for user, ip in successful_logins:
            f.write(f"[{get_timestamp()}] INFO - Successful login: user={user}, ip={ip}\n")

    print(f"\nDetailed alert report written to {filename}")



def print_summary(
    failed_attempts: Counter,
    brute_force_ips: list[tuple[str, int]],
    successful_logins: list[tuple[str, str]]
):
    print("\n=== Silent Watcher Summary ===")
    print(f"Unique IPs with failed logins: {len(failed_attempts)}")
    print(f"Potential brute-force IPs: {len(brute_force_ips)}")
    print(f"Successful logins: {len(successful_logins)}")

    if brute_force_ips:
        print("\nBrute-force suspects:")
        for ip, count in brute_force_ips:
            print(f" - {ip}: {count} failed attempts")


def main():
    failed_attempts, successful_logins, suspicious_alerts = analyze_logs(LOG_FILE)
    brute_force_ips = detect_brute_force(failed_attempts, BRUTE_FORCE_THRESHOLD)
    write_alerts(ALERT_FILE, suspicious_alerts, brute_force_ips, successful_logins)
    print_summary(failed_attempts, brute_force_ips, successful_logins)
    print("\nAlert report generated successfully.")


if __name__ == "__main__":
    main()