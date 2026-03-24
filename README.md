# Autonomous-Cyber-Defence

An Intrusion Detection and Prevention System (IDS/IPS) with real-time web monitoring.

## Features

- Log monitoring and analysis
- Brute force detection
- Automatic IP blocking
- Real-time web dashboard

## Installation

1. Clone the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`

## Usage

### Command Line

Run the main detection script:
```bash
python main.py
```

### Web Monitor

Start the web monitoring interface:
```bash
python web_monitor.py
```

Then open your browser to `http://localhost:5000` to view the real-time dashboard.

### Blog target app (demo)

Start the blog login application in a second terminal:
```bash
python blog_app.py
```

Then open your browser to `http://localhost:5001/login` and attempt a few logins.

Each attempt is saved in `data/logs.json` and immediately reflected in the monitor dashboard at `http://localhost:5000`.

The dashboard shows:
- Statistics on logs and threats
- List of blocked IPs
- Recent log entries with real-time updates

### Ingestion API (real external integration)

To monitor a real blog web server, send login event JSON to this endpoint from your application:

POST `http://<monitor-host>:5000/api/ingest`

Body:
```json
{
  "ip": "203.0.113.5",
  "username": "admin",
  "status": "failed"
}
```

This allows real-time intrusion detection for any external app using webhook/log shipping.

## Files

- `main.py`: Main detection script
- `monitor.py`: Log reading functionality
- `detector.py`: Threat detection algorithms
- `responder.py`: IP blocking actions
- `logger.py`: Event logging
- `web_monitor.py`: Flask web application
- `data/logs.json`: Log data
- `blocked_ips.json`: Blocked IP addresses