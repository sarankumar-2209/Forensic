from flask import Flask, request, render_template, redirect, url_for, session
import hashlib, time, os, json, urllib.request
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = 'MnkYCUA1ysNzrjJo9T6FidGvgDBhpeX8PKHwmRu5Lc3xOSQ7tWfEbl40VIa2Zq'

LOG_PATH = 'logs/activity.log'
BAN_LIST = set()
FAILED_LOGINS = {}

EMAIL_ALERTS = True
EMAIL_TO = 'saran2209kumar@gmail.com'

def get_client_ip():
    # Extract real client IP behind reverse proxy like Render.com
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def get_geo_info(ip):
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
        print(f"[GeoError] Failed for {ip}: {e}")
    return "0,0", "Unknown", "Unknown"


def log_event(ip, ua, msg, path):
    loc, city, country = get_geo_info(ip)
    with open(LOG_PATH, 'a') as f:
        now = datetime.now().isoformat()
        line = f"{now} | IP: {ip} | Location: {loc} ({city}, {country}) | UA: {ua} | Path: {path} | Event: {msg}\n"
        f.write(line)
    if EMAIL_ALERTS and "Suspicious" in msg:
        send_email_alert(ip, msg, path, loc, city, country)

def send_email_alert(ip, msg, path, loc, city, country):
    msg_obj = MIMEText(f"Suspicious activity detected from IP: {ip}\nLocation: {loc} ({city}, {country})\nEvent: {msg}\nPath: {path}")
    msg_obj['Subject'] = "Alert: Suspicious Activity Detected"
    msg_obj['From'] = 'alert@yourdomain.com'
    msg_obj['To'] = EMAIL_TO

    try:
        s = smtplib.SMTP('localhost')
        s.send_message(msg_obj)
        s.quit()
    except Exception as e:
        print("Email alert failed:", e)

def detect_attack(data):
    patterns = ["<script>", "' OR 1=1", "--", "DROP TABLE", "onerror="]
    for val in data.values():
        for pat in patterns:
            if pat.lower() in val.lower():
                return True
    return False

@app.before_request
def block_banned_ips():
    ip = get_client_ip()
    if ip in BAN_LIST:
        return "403 Forbidden", 403

@app.route('/')
def index():
    ip = get_client_ip()
    ua = request.headers.get('User-Agent')
    log_event(ip, ua, "Visited Home", request.path)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = get_client_ip()
    ua = request.headers.get('User-Agent')
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        data = {'username': username, 'password': password}

        if detect_attack(data):
            log_event(ip, ua, "Suspicious: Injection Attempt", request.path)
            return "Attack Detected", 403

        if username == 'admin' and password == 'password':
            session['user'] = username
            log_event(ip, ua, "Successful Login", request.path)
            return redirect(url_for('admin'))
        else:
            FAILED_LOGINS[ip] = FAILED_LOGINS.get(ip, 0) + 1
            if FAILED_LOGINS[ip] >= 5:
                BAN_LIST.add(ip)
                log_event(ip, ua, "IP Banned due to Brute Force", request.path)
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
    with open(LOG_PATH, 'r') as f:
        logs = f.readlines()
    return render_template('admin.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)
