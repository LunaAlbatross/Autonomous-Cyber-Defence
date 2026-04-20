import sqlite3
import os
from datetime import datetime, timedelta

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'waf_data.db')

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip TEXT,
            method TEXT,
            path TEXT,
            status INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip TEXT,
            threat_type TEXT,
            payload_details TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_traffic(ip, method, path, status):
    conn = get_connection()
    c = conn.cursor()
    c.execute('INSERT INTO traffic_logs (ip, method, path, status) VALUES (?, ?, ?, ?)', (ip, method, path, status))
    conn.commit()
    conn.close()

def log_threat(ip, threat_type, details):
    conn = get_connection()
    c = conn.cursor()
    c.execute('INSERT INTO threat_logs (ip, threat_type, payload_details) VALUES (?, ?, ?)', (ip, threat_type, details))
    conn.commit()
    conn.close()

def block_ip(ip, reason, ttl_hours=1):
    conn = get_connection()
    c = conn.cursor()
    expires_at = (datetime.utcnow() + timedelta(hours=ttl_hours)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute('''
        INSERT INTO blocked_ips (ip, blocked_at, expires_at, reason) 
        VALUES (?, CURRENT_TIMESTAMP, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET 
        blocked_at=CURRENT_TIMESTAMP, expires_at=?, reason=?
    ''', (ip, expires_at, reason, expires_at, reason))
    conn.commit()
    conn.close()

def unblock_ip(ip):
    conn = get_connection()
    c = conn.cursor()
    c.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
    was_removed = c.rowcount > 0
    conn.commit()
    conn.close()
    return was_removed

def is_ip_blocked(ip):
    conn = get_connection()
    c = conn.cursor()
    c.execute('DELETE FROM blocked_ips WHERE expires_at < CURRENT_TIMESTAMP')
    conn.commit()

    c.execute('SELECT * FROM blocked_ips WHERE ip = ? AND expires_at > CURRENT_TIMESTAMP', (ip,))
    record = c.fetchone()
    conn.close()
    return record is not None

def get_stats():
    conn = get_connection()
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM traffic_logs')
    total_logs = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM threat_logs')
    total_threats = c.fetchone()[0]
    
    c.execute('DELETE FROM blocked_ips WHERE expires_at < CURRENT_TIMESTAMP')
    conn.commit()
    
    c.execute('SELECT COUNT(*) FROM blocked_ips')
    blocked_count = c.fetchone()[0]
    
    conn.close()
    return {
        'total_logs': total_logs,
        'threats_blocked': total_threats,
        'active_blocks': blocked_count
    }

def get_active_blocks():
    conn = get_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM blocked_ips WHERE expires_at > CURRENT_TIMESTAMP ORDER BY blocked_at DESC')
    blocks = [dict(row) for row in c.fetchall()]
    conn.close()
    return blocks

def get_recent_traffic(limit=50):
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT t.timestamp, t.ip, t.method, t.path, t.status, 
               CASE WHEN tl.threat_type IS NOT NULL THEN 'blocked' ELSE 'success' END as status_state
        FROM traffic_logs t
        LEFT JOIN threat_logs tl ON t.ip = tl.ip AND t.timestamp = tl.timestamp AND tl.timestamp >= datetime(t.timestamp, '-1 seconds')
        ORDER BY t.timestamp DESC LIMIT ?
    ''', (limit,))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

init_db()
