from flask import Flask, request, render_template, redirect, url_for, session, abort
from werkzeug.security import check_password_hash, generate_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import smtplib, re, json, os, urllib.request
from email.mime.text import MIMEText
from logging.handlers import RotatingFileHandler
import logging

# === Configuration ===
app = Flask(_name_)
app.secret_key = os.environ.get("SECRET_KEY", "default_insecure_key")
EMAIL_ALERTS = True
EMAIL_TO = os.environ.get("ALERT_EMAIL", "saran2209kumar@gmail.com")
BAN_DURATION = 600  # seconds (10 minutes)

# === Rate Limiting ===
limiter = Limiter(app=app, key_func=get_remote_address)

# === Logger Setup ===
LOG_PATH = 'logs/activity.log'
os.makedirs('logs', exist_ok=True)
logger = logging.getLogger('SecurityLogger')
handler = RotatingFileHandler(LOG_PATH, maxBytes=100000, backupCount=3)
formatter = logging.Formatter('%(asctime)s | %(message)s')
handler.setFormatter(formatter)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# === Ban Handling ===
BAN_LIST = {}
FAILED_LOGINS = {}

# === Utils ===
def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def get_geo_info(ip):
    try:
        req = urllib.request.Request(f"https://ipwho.is/{ip}", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as url:
            data = json.loads(url.read().decode())
            if data.get("success", False):
                return f"{data['latitude']},{data['longitude']}", data['city'], data['country']
    except Exception as e:
        logger.warning(f"[GeoError] Failed for {ip}: {e}")
    return "0,0", "Unknown", "Unknown"

def log_event(ip, ua, msg, path):
    loc, city, country = get_geo_info(ip)
    line = f"IP: {ip} | Loc: {loc} ({city}, {country}) | UA: {ua} | Path: {path} | Event: {msg}"
    logger.info(line)
    if EMAIL_ALERTS and "Suspicious" in msg:
        send_email_alert(ip, msg, path, loc, city, country)

def send_email_alert(ip, msg, path, loc, city, country):
    content = f"""
    Suspicious activity detected:

    IP: {ip}
    Location: {loc} ({city}, {country})
    Event: {msg}
    Path: {path}
    Time: {datetime.now().isoformat()}
    """
    message = MIMEText(content)
    message['Subject'] = "Security Alert"
    message['From'] = 'alert@yourdomain.com'
    message['To'] = EMAIL_TO

    try:
        with smtplib.SMTP('localhost') as server:
            server.send_message(message)
    except Exception as e:
        logger.warning(f"Failed to send alert email: {e}")

def detect_attack(data):
    pattern = re.compile(r"(?:<script|onerror=|--|union|select\s|\bOR\b\s+1=1|\bDROP\s+TABLE)", re.IGNORECASE)
    return any(pattern.search(val) for val in data.values())

@app.before_request
def block_banned_ips():
    ip = get_client_ip()
    if ip in BAN_LIST:
        ban_time = BAN_LIST[ip]
        if datetime.now() > ban_time:
            del BAN_LIST[ip]  # Unban after timeout
        else:
            abort(403)

@app.route('/')
def index():
    ip = get_client_ip()
    ua = request.headers.get('User-Agent')
    log_event(ip, ua, "Visited Home Page", request.path)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Prevent brute force
def login():
    ip = get_client_ip()
    ua = request.headers.get('User-Agent')

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        data = {'username': username, 'password': password}

        if detect_attack(data):
            log_event(ip, ua, "Suspicious: Injection Attempt", request.path)
            abort(403)

        # Secure credentials check (replace with DB in production)
        stored_username = "admin"
        stored_hashed_password = generate_password_hash("password")

        if username == stored_username and check_password_hash(stored_hashed_password, password):
            session['user'] = username
            log_event(ip, ua, "Successful Login", request.path)
            return redirect(url_for('admin'))
        else:
            FAILED_LOGINS[ip] = FAILED_LOGINS.get(ip, 0) + 1
            if FAILED_LOGINS[ip] >= 5:
                BAN_LIST[ip] = datetime.now() + timedelta(seconds=BAN_DURATION)
                log_event(ip, ua, "IP Temporarily Banned (Brute Force)", request.path)
            else:
                log_event(ip, ua, "Failed Login Attempt", request.path)
            return "Invalid credentials", 401
    else:
        log_event(ip, ua, "Visited Login Page", request.path)
        return render_template('login.html')

@app.route('/admin')
def admin():
    if 'user' not in session:
        return redirect(url_for('login'))
    ip = get_client_ip()
    ua = request.headers.get('User-Agent')
    log_event(ip, ua, "Accessed Admin Panel", request.path)
    with open(LOG_PATH) as f:
        logs = f.readlines()
    return render_template('admin.html', logs=logs)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

# === Secure Cookie Settings ===
@app.after_request
def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.set_cookie('session', httponly=True, secure=True, samesite='Lax')
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)