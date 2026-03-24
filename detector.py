from collections import defaultdict

THRESHOLD = 5

def detect_brute_force(logs):
    failed_attempts = defaultdict(int)

    for log in logs:
        if log["status"] == "failed":
            ip = log["ip"]
            failed_attempts[ip] += 1

    suspicious_ips = []

    for ip, count in failed_attempts.items():
        if count > THRESHOLD:
            suspicious_ips.append(ip)

    return suspicious_ips