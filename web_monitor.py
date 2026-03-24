from flask import Flask, render_template, jsonify, request
import json
import os
from datetime import datetime
from monitor import read_logs, save_log_entry
from detector import detect_brute_force
from responder import BLOCKED_FILE

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/logs')
def get_logs():
    logs = read_logs("data/logs.json")
    return jsonify(logs)


@app.route('/api/ingest', methods=['POST'])
def ingest_log():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON payload'}), 400

    required = ['ip', 'username', 'status']
    if not all(key in data for key in required):
        return jsonify({'error': f'Required fields: {required}'}), 400

    entry = {
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'ip': data['ip'],
        'username': data['username'],
        'status': data['status']
    }

    save_log_entry(entry, 'data/logs.json')

    return jsonify({'message': 'Log ingested', 'entry': entry}), 201

@app.route('/api/blocked')
def get_blocked():
    try:
        with open(BLOCKED_FILE, 'r') as file:
            blocked = json.load(file)
    except:
        blocked = []
    return jsonify(blocked)

@app.route('/api/stats')
def get_stats():
    logs = read_logs("data/logs.json")
    suspicious_ips = detect_brute_force(logs)

    total_logs = len(logs)
    failed_attempts = sum(1 for log in logs if log.get('status') == 'failed')
    successful_attempts = total_logs - failed_attempts

    blocked_data = []
    try:
        with open(BLOCKED_FILE, 'r') as file:
            blocked_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        blocked_data = []

    return jsonify({
        'total_logs': total_logs,
        'failed_attempts': failed_attempts,
        'successful_attempts': successful_attempts,
        'suspicious_ips_count': len(suspicious_ips),
        'suspicious_ips': suspicious_ips,
        'blocked_ips_count': len(blocked_data)
    })


@app.route('/api/reload')
def run_detection():
    logs = read_logs("data/logs.json")
    suspicious_ips = detect_brute_force(logs)

    blocked = []
    try:
        with open(BLOCKED_FILE, 'r') as file:
            blocked = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        blocked = []

    new_blocked = []
    for ip in suspicious_ips:
        if ip not in blocked:
            blocked.append(ip)
            new_blocked.append(ip)

    with open(BLOCKED_FILE, 'w') as file:
        json.dump(blocked, file, indent=4)

    return jsonify({'suspicious_ips': suspicious_ips, 'newly_blocked': new_blocked})


@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    data = request.get_json(silent=True)
    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address required'}), 400
    
    ip = data['ip'].strip()
    
    # Load current blocked list
    try:
        with open(BLOCKED_FILE, 'r') as file:
            blocked = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        blocked = []
    
    # Add IP if not already blocked
    was_new = False
    if ip not in blocked:
        blocked.append(ip)
        was_new = True
    
    # Save updated list
    with open(BLOCKED_FILE, 'w') as file:
        json.dump(blocked, file, indent=4)
    
    return jsonify({
        'message': f'IP {ip} {"blocked" if was_new else "already blocked"}',
        'ip': ip,
        'newly_blocked': was_new
    }), 201


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)