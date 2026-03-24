import json

BLOCKED_FILE = "blocked_ips.json"

def block_ip(ip):
    try:
        with open(BLOCKED_FILE, 'r') as file:
            blocked = json.load(file)
    except:
        blocked = []

    if ip not in blocked:
        blocked.append(ip)

    with open(BLOCKED_FILE, 'w') as file:
        json.dump(blocked, file, indent=4)

    print(f"[ACTION] Blocked IP: {ip}")