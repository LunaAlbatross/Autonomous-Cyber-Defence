import json
import os

DEFAULT_LOG_FILE = "data/logs.json"

def read_logs(file_path=DEFAULT_LOG_FILE):
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r') as file:
        try:
            logs = json.load(file)
        except json.JSONDecodeError:
            logs = []
    return logs


def save_log_entry(entry, file_path=DEFAULT_LOG_FILE):
    logs = read_logs(file_path)
    logs.append(entry)
    with open(file_path, 'w') as file:
        json.dump(logs, file, indent=4)
    return entry
