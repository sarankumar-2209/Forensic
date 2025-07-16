from flask import Flask, request, render_template, redirect, url_for, session
import hashlib, time, os, json, urllib.request
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = 'your_secret_key'

LOG_PATH = 'logs/activity.log'
BAN_LIST = set()
FAILED_LOGINS = {}

EMAIL_ALERTS = True
EMAIL_TO = 'admin@example.com'

def get_geo_info(ip):
    try:
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json") as url:
            data = json.loads(url.read().decode())
            loc = data.get("loc", "0,0")
            city = data.get("city", "Unknown")
            country = data.get("country", "Unknown")
            return loc, city, country
    except:
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
    ip = request.remote_addr
    if ip in BAN_LIST:
        return "403 Forbidden", 403

@app.route('/')
def index():
    log_event(request.remote_addr, request.headers.get('User-Agent'), "Visited Home", request.path)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
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
    log_event(request.remote_addr, request.headers.get('User-Agent'), "Accessed Admin Panel", request.path)
    with open(LOG_PATH, 'r') as f:
        logs = f.readlines()
    return render_template('admin.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)
