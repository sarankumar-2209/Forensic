import os
import sys
import json
import time
import hashlib
import smtplib
import sqlite3
import platform
import urllib.request
from datetime import datetime
from email.mime.text import MIMEText
from flask import Flask, request, render_template, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.urandom(32)  # Random secret key for each run

# Configuration
CONFIG = {
    'LOG_DIR': 'logs',
    'DB_FILE': 'forensics.db',
    'EMAIL_ALERTS': False,
    'EMAIL_TO': 'saran2209kumar@gmail.com',
    'MAX_LOGIN_ATTEMPTS': 5,
    'BAN_TIME_MINUTES': 30,
    'LOG_RETENTION_DAYS': 30
}

# Ensure directories exist
os.makedirs(CONFIG['LOG_DIR'], exist_ok=True)

def init_db():
    """Initialize SQLite database for forensic data"""
    conn = sqlite3.connect(CONFIG['DB_FILE'])
    c = conn.cursor()
    
    # Drop existing tables if they exist (for development)
    c.execute("DROP TABLE IF EXISTS events")
    c.execute("DROP TABLE IF EXISTS banned_ips")
    c.execute("DROP TABLE IF EXISTS login_attempts")
    
    # Create tables with correct schema
    c.execute('''CREATE TABLE events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  ip TEXT,
                  location TEXT,
                  city TEXT,
                  country TEXT,
                  user_agent TEXT,
                  path TEXT,
                  event_type TEXT,
                  details TEXT)''')
    
    c.execute('''CREATE TABLE banned_ips
                 (ip TEXT PRIMARY KEY,
                  ban_time TEXT,
                  reason TEXT)''')
    
    c.execute('''CREATE TABLE login_attempts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip TEXT,
                  timestamp TEXT,
                  username TEXT,
                  success INTEGER)''')
    
    conn.commit()
    conn.close()

def get_client_ip():
    """Get client IP considering proxy headers"""
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def get_geo_info(ip):
    """Get geolocation data with fallback to localhost info"""
    if ip in ['127.0.0.1', '::1']:
        return "0,0", "Localhost", "Local Network"
    
    try:
        req = urllib.request.Request(
            f"https://ipwho.is/{ip}",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as url:
            data = json.loads(url.read().decode())
            if data.get("success", False):
                lat = data.get("latitude", 0)
                lon = data.get("longitude", 0)
                city = data.get("city", "Unknown")
                country = data.get("country", "Unknown")
                loc = f"{lat},{lon}"
                return loc, city, country
    except Exception as e:
        print(f"Geo lookup failed: {e}", file=sys.stderr)
    
    return "0,0", "Unknown", "Unknown"

def log_event(ip, event_type, details, path=None):
    """Log event to both database and text file"""
    if path is None:
        path = request.path
    ua = request.headers.get('User-Agent', 'Unknown')
    timestamp = datetime.now().isoformat()
    loc, city, country = get_geo_info(ip)
    
    # Log to database
    conn = sqlite3.connect(CONFIG['DB_FILE'])
    c = conn.cursor()
    c.execute("INSERT INTO events (timestamp, ip, location, city, country, user_agent, path, event_type, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (timestamp, ip, loc, city, country, ua, path, event_type, details))
    conn.commit()
    conn.close()
    
    # Log to text file
    log_file = os.path.join(CONFIG['LOG_DIR'], 'activity.log')
    with open(log_file, 'a') as f:
        f.write(f"{timestamp} | {ip} | {loc} | {city}, {country} | {ua} | {path} | {event_type} | {details}\n")
    
    # Send email alert if suspicious
    if CONFIG['EMAIL_ALERTS'] and "SUSPICIOUS" in event_type.upper():
        send_alert_email(ip, event_type, details, loc, city, country)

def send_alert_email(ip, event_type, details, loc, city, country):
    """Send email alert about suspicious activity"""
    subject = f"Security Alert: {event_type}"
    body = f"""
    Suspicious activity detected:
    - IP: {ip}
    - Location: {loc} ({city}, {country})
    - Time: {datetime.now().isoformat()}
    - Event: {event_type}
    - Details: {details}
    - Path: {request.path}
    - User Agent: {request.headers.get('User-Agent', 'Unknown')}
    """
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'security@yourdomain.com'
    msg['To'] = CONFIG['EMAIL_TO']
    
    try:
        with smtplib.SMTP('localhost') as server:
            server.send_message(msg)
    except Exception as e:
        print(f"Failed to send email alert: {e}", file=sys.stderr)

def is_banned(ip):
    """Check if IP is banned"""
    conn = sqlite3.connect(CONFIG['DB_FILE'])
    c = conn.cursor()
    c.execute("SELECT ban_time FROM banned_ips WHERE ip = ?", (ip,))
    result = c.fetchone()
    conn.close()
    
    if result:
        ban_time = datetime.fromisoformat(result[0])
        if (datetime.now() - ban_time).total_seconds() < CONFIG['BAN_TIME_MINUTES'] * 60:
            return True
        else:
            # Ban expired, remove from database
            conn = sqlite3.connect(CONFIG['DB_FILE'])
            c = conn.cursor()
            c.execute("DELETE FROM banned_ips WHERE ip = ?", (ip,))
            conn.commit()
            conn.close()
    return False

def ban_ip(ip, reason):
    """Ban an IP address"""
    conn = sqlite3.connect(CONFIG['DB_FILE'])
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO banned_ips VALUES (?, ?, ?)",
              (ip, datetime.now().isoformat(), reason))
    conn.commit()
    conn.close()
    log_event(ip, "IP_BANNED", reason)

def detect_attack(data):
    """Detect common attack patterns"""
    suspicious_patterns = [
        "<script>", "' OR", "--", "/*", "*/", "DROP TABLE", 
        "UNION SELECT", "onerror=", "alert(", "eval(", "document.cookie"
    ]
    
    for key, value in data.items():
        if not isinstance(value, str):
            continue
            
        # Check for suspicious patterns
        for pattern in suspicious_patterns:
            if pattern.lower() in value.lower():
                return True
                
        # Check for unusually long input
        if len(value) > 1000:
            return True
            
    return False

@app.before_request
def security_checks():
    """Perform security checks before each request"""
    ip = get_client_ip()
    
    # Check if IP is banned
    if is_banned(ip):
        log_event(ip, "BANNED_ACCESS_ATTEMPT", "Attempted access while banned")
        return "Access denied. Your IP has been temporarily blocked.", 403
    
    # Skip logging for static files
    if request.path == '/favicon.ico':
        return
    
    log_event(ip, "REQUEST", f"{request.method} {request.path}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = get_client_ip()
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Check for attack patterns
        if detect_attack(request.form):
            log_event(ip, "SUSPICIOUS_LOGIN_ATTEMPT", 
                     f"Possible injection attack with username: {username}")
            return "Invalid credentials", 401
            
        # Simple authentication (in real app, use proper password hashing)
        if username == 'admin' and password == 'password':
            session['user'] = username
            session['login_time'] = datetime.now().isoformat()
            session['ip'] = ip
            
            # Log successful login
            conn = sqlite3.connect(CONFIG['DB_FILE'])
            c = conn.cursor()
            c.execute("INSERT INTO login_attempts (ip, timestamp, username, success) VALUES (?, ?, ?, ?)",
                      (ip, datetime.now().isoformat(), username, 1))
            conn.commit()
            conn.close()
            
            log_event(ip, "LOGIN_SUCCESS", f"User: {username}")
            return redirect(url_for('admin'))
        else:
            # Log failed attempt
            conn = sqlite3.connect(CONFIG['DB_FILE'])
            c = conn.cursor()
            c.execute("INSERT INTO login_attempts (ip, timestamp, username, success) VALUES (?, ?, ?, ?)",
                      (ip, datetime.now().isoformat(), username, 0))
            conn.commit()
            conn.close()
            
            log_event(ip, "LOGIN_FAILED", f"Username: {username}")
            
            # Check if IP should be banned
            conn = sqlite3.connect(CONFIG['DB_FILE'])
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND success = 0 AND timestamp > datetime('now', '-1 hour')",
                      (ip,))
            failed_attempts = c.fetchone()[0]
            conn.close()
            
            if failed_attempts >= CONFIG['MAX_LOGIN_ATTEMPTS']:
                ban_ip(ip, "Too many failed login attempts")
                return "Too many failed attempts. Your IP has been temporarily blocked.", 403
                
            return "Invalid credentials", 401
    else:
        return render_template('login.html')

@app.route('/admin')
def admin():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    # Verify session IP matches current IP
    if session.get('ip') != get_client_ip():
        log_event(get_client_ip(), "SESSION_HIJACK_ATTEMPT", 
                 f"Original IP: {session.get('ip')}, Current IP: {get_client_ip()}")
        session.clear()
        return redirect(url_for('login'))
    
    # Get recent events for admin view
    conn = sqlite3.connect(CONFIG['DB_FILE'])
    c = conn.cursor()
    
    # Get database events
    c.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT 100")
    db_events = c.fetchall()
    
    # Get login attempts
    c.execute("SELECT ip, timestamp, username, success FROM login_attempts ORDER BY timestamp DESC LIMIT 100")
    login_attempts = c.fetchall()
    
    # Get banned IPs
    c.execute("SELECT ip, ban_time, reason FROM banned_ips ORDER BY ban_time DESC")
    banned_ips = c.fetchall()
    
    conn.close()
    
    # Get file logs
    log_file = os.path.join(CONFIG['LOG_DIR'], 'activity.log')
    try:
        with open(log_file, 'r') as f:
            file_logs = f.readlines()
    except FileNotFoundError:
        file_logs = ["Log file not found"]
    
    return render_template('admin.html', 
                         db_events=db_events,
                         file_logs=file_logs[-100:],  # Show last 100 lines
                         login_attempts=login_attempts,
                         banned_ips=banned_ips)

@app.route('/logs')
def view_logs():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    log_file = os.path.join(CONFIG['LOG_DIR'], 'activity.log')
    with open(log_file, 'r') as f:
        logs = f.readlines()
    
    return render_template('logs.html', logs=logs)

@app.route('/logout')
def logout():
    if 'user' in session:
        log_event(get_client_ip(), "LOGOUT", f"User: {session['user']}")
        session.clear()
    return redirect(url_for('index'))



if __name__ == '__main__':
    # Initialize database
    init_db()
    
    
    # Determine the appropriate host and port
    host = '0.0.0.0' if os.getenv('IN_CONTAINER', 'false').lower() == 'true' else '127.0.0.1'
    port = int(os.getenv('PORT', 5000))
    
    # Run the application
    app.run(host=host, port=port, debug=False)