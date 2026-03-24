from monitor import read_logs
from detector import detect_brute_force
from responder import block_ip
from logger import log_event

def main():
    logs = read_logs("data/logs.json")
    log_event("Logs loaded")

    suspicious_ips = detect_brute_force(logs)

    if suspicious_ips:
        log_event(f"Suspicious IPs detected: {suspicious_ips}")

        for ip in suspicious_ips:
            block_ip(ip)
    else:
        log_event("No threats detected")

if __name__ == "__main__":
    main()