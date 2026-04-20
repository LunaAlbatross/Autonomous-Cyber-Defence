from flask import Flask, request, Response
import requests
import json
from core.database import is_ip_blocked, log_traffic, log_threat, block_ip
from core.waf_engine import evaluate_request
from core.notifier import send_alert

app = Flask(__name__)
TARGET_URL = "http://localhost:5001"

HTML_FORBIDDEN = """
<!DOCTYPE html>
<html>
<head>
    <title>WAF Intercept: 403 Forbidden</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background: #0a0a0f; color: #fff; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; overflow: hidden; }
        .box { text-align: center; background: rgba(255, 8, 68, 0.05); border: 1px solid rgba(255, 8, 68, 0.2); border-radius: 20px; padding: 60px; box-shadow: 0 0 50px rgba(255, 8, 68, 0.1); }
        h1 { color: #ff0844; font-size: 3.5rem; margin-bottom: 20px; text-shadow: 0 0 20px rgba(255,8,68,0.5); }
        p { color: #8b8b9e; font-size: 1.1rem; line-height: 1.6; }
        code { background: rgba(0,0,0,0.5); padding: 5px 10px; border-radius: 5px; color: #ff0844; }
    </style>
</head>
<body>
    <div class="box">
        <h1>[!] ACCESS DENIED</h1>
        <p>A fatal security violation was intercepted by the WAF Engine.</p>
        <p>Payload triggered a <code>403 FORBIDDEN</code> protective state.</p>
    </div>
</body>
</html>
"""

HTML_BLOCKED = """
<!DOCTYPE html>
<html>
<head>
    <title>WAF Intercept: IP Ban</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background: #000; color: #fff; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background-image: radial-gradient(circle at 50% 50%, rgba(255,8,68,0.1), transparent 50%); }
        .box { text-align: center; border: 1px solid rgba(255,8,68,0.3); padding: 80px; box-shadow: inset 0 0 80px rgba(255,8,68,0.1), 0 0 50px rgba(255,8,68,0.2); border-radius: 10px; background: rgba(10,10,15,0.8); backdrop-filter: blur(10px); }
        h1 { color: #ff0844; font-size: 4rem; margin: 0 0 15px 0; letter-spacing: 5px; }
        p { color: #8b8b9e; font-size: 1.2rem; text-transform: uppercase; letter-spacing: 2px; margin: 0; }
    </style>
</head>
<body>
    <div class="box">
        <h1>QUARANTINE</h1>
        <p>Your IP Address has been actively banned.</p>
    </div>
</body>
</html>
"""

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def reverse_proxy(path):
    client_ip = request.remote_addr

    if is_ip_blocked(client_ip):
        return Response(HTML_BLOCKED, status=403, mimetype='text/html')

    import urllib.parse
    headers_dict = {key: value for key, value in request.headers if key.lower() != 'host'}
    raw_body = request.get_data().decode('utf-8', errors='ignore')
    eval_body = urllib.parse.unquote_plus(raw_body)
    
    target_path = "/" + path
    if request.query_string:
        target_path += "?" + request.query_string.decode('utf-8')
        
    eval_path = urllib.parse.unquote_plus(target_path)

    is_safe, threat_type, details = evaluate_request(eval_path, headers_dict, eval_body)
    
    if not is_safe:
        log_threat(client_ip, threat_type, details)
        block_ip(client_ip, reason=threat_type)
        log_traffic(client_ip, request.method, target_path, 403)
        send_alert(client_ip, threat_type, details)
        return Response(HTML_FORBIDDEN, status=403, mimetype='text/html')

    try:
        resp = requests.request(
            method=request.method,
            url=f"{TARGET_URL}{target_path}",
            headers=headers_dict,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]

        log_traffic(client_ip, request.method, target_path, resp.status_code)

        return Response(resp.content, resp.status_code, headers)
        
    except requests.exceptions.ConnectionError:
        return Response("Target Backend Offline", status=502)

if __name__ == '__main__':
    print("[*] Starting WAF Reverse Proxy on port 5000...")
    app.run(debug=True, host='0.0.0.0', port=5000)
