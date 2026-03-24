from flask import Flask, render_template, request, redirect, url_for, flash
from monitor import save_log_entry
import json
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'dev-key'

VALID_CREDENTIALS = {
    'admin': 'adminpass',
    'user': 'userpass'
}

BLOCKED_FILE = "blocked_ips.json"

def get_blocked_ips():
    """Load list of blocked IPs from file"""
    try:
        with open(BLOCKED_FILE, 'r') as file:
            return json.load(file)
    except:
        return []

def is_ip_blocked(ip):
    """Check if IP is in the blocked list"""
    blocked = get_blocked_ips()
    return ip in blocked

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    client_ip = request.remote_addr
    
    # Check if IP is blocked
    if is_ip_blocked(client_ip):
        return """
        <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Access Denied</title>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body {
                        font-family: 'Segoe UI', sans-serif;
                        background: linear-gradient(-45deg, #ee7752, #e73c7e, #23a6d5, #23d5ab);
                        background-size: 400% 400%;
                        animation: gradientShift 15s ease infinite;
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                    @keyframes gradientShift {
                        0% { background-position: 0% 50%; }
                        50% { background-position: 100% 50%; }
                        100% { background-position: 0% 50%; }
                    }
                    .container {
                        background: rgba(255, 255, 255, 0.95);
                        backdrop-filter: blur(10px);
                        border-radius: 20px;
                        padding: 60px 40px;
                        text-align: center;
                        max-width: 500px;
                        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                    }
                    .icon {
                        font-size: 4rem;
                        margin-bottom: 20px;
                    }
                    h1 {
                        color: #ff4757;
                        margin-bottom: 15px;
                        font-size: 2rem;
                    }
                    p {
                        color: #666;
                        margin-bottom: 10px;
                        line-height: 1.6;
                    }
                    .ip-info {
                        background: #ffe6e6;
                        padding: 15px;
                        border-radius: 10px;
                        margin: 20px 0;
                        font-family: monospace;
                        color: #c92a2a;
                        font-weight: bold;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="icon">🚫</div>
                    <h1>Access Denied</h1>
                    <p>Your IP address has been <strong>blocked</strong> by the IDS/IPS system.</p>
                    <div class="ip-info">""" + client_ip + """</div>
                    <p style="font-size: 0.9rem; color: #999;">
                        If you believe this is an error, please contact the administrator.
                    </p>
                </div>
            </body>
        </html>
        """, 403
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if VALID_CREDENTIALS.get(username) == password:
            status = 'success'
            flash('Login successful', 'success')
        else:
            status = 'failed'
            flash('Login failed', 'danger')

        save_log_entry({
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'ip': client_ip,
            'username': username,
            'status': status
        })

        return redirect(url_for('login'))

    return render_template('blog_login.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
