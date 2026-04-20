from flask import Flask, render_template, jsonify, request
from core.database import get_stats, get_active_blocks, get_recent_traffic, unblock_ip

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    stats = get_stats()
    # To interface easily with existing JS:
    return jsonify({
        'total_logs': stats['total_logs'],
        'failed_attempts': stats['threats_blocked'],
        'successful_attempts': stats['total_logs'] - stats['threats_blocked'],
        'suspicious_ips_count': stats['threats_blocked'], # Simulating metric mapping
        'blocked_ips_count': stats['active_blocks']
    })

@app.route('/api/blocked')
def api_blocked():
    blocks = get_active_blocks()
    formatted = {b['ip']: {'blocked_at': b['blocked_at'], 'reason': b['reason']} for b in blocks}
    return jsonify(formatted)

@app.route('/api/logs')
def api_logs():
    traffic = get_recent_traffic()
    formatted = []
    for t in traffic:
        formatted.append({
            'timestamp': t['timestamp'],
            'username': f"{t['method']} {t['path']}",
            'ip': t['ip'],
            'status': t['status_state'] 
        })
    return jsonify(formatted)

@app.route('/api/unblock-ip', methods=['POST'])
def api_unblock_ip():
    data = request.get_json(silent=True)
    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address required'}), 400
    
    ip = data['ip'].strip()
    was_removed = unblock_ip(ip)
    
    return jsonify({
        'message': f'IP {ip} {"unblocked" if was_removed else "was not blocked"}',
        'ip': ip,
        'unblocked': was_removed
    }), 200

if __name__ == '__main__':
    print("[*] Starting Admin WAF Dashboard on port 5002...")
    app.run(debug=True, host='0.0.0.0', port=5002)
