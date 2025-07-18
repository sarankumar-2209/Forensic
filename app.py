from flask import Flask, request, render_template, redirect, url_for, session
import hashlib, time, os, json, urllib.request, socket, uuid
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'MnkYCUA1ysNzrjJo9T6FidGvgDBhpeX8PKHwmRu5Lc3xOSQ7tWfEbl40VIa2Zq')

LOG_DIR = 'logs'
LOG_PATH = os.path.join(LOG_DIR, 'activity.log')
BAN_LIST = set()
FAILED_LOGINS = {}

EMAIL_ALERTS = True
EMAIL_TO = os.environ.get('EMAIL_TO', 'saran2209kumar@gmail.com')

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

def get_client_ip():
    """Get the real client IP even behind VPN/proxy by checking multiple headers"""
    headers = request.headers
    # List of potential headers that might contain real IP
    potential_ip_headers = [
        'X-Forwarded-For',
        'X-Real-IP',
        'CF-Connecting-IP',  # Cloudflare
        'True-Client-IP',    # Akamai and Cloudflare
        'X-Cluster-Client-IP',
        'Forwarded',
        'X-Original-Forwarded-For',
        'Proxy-Client-IP',
        'WL-Proxy-Client-IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'HTTP_VIA',
        'REMOTE_ADDR'
    ]
    
    ips = []
    for header in potential_ip_headers:
        if header in headers:
            # Handle comma-separated lists (like X-Forwarded-For)
            value = headers[header].split(',')[0].strip()
            if value:
                ips.append(value)
    
    # Add the default remote_addr as last resort
    ips.append(request.remote_addr)
    
    # Filter out known proxy IPs and private IPs
    real_ips = []
    for ip in ips:
        if not is_private_ip(ip) and not is_known_proxy(ip):
            real_ips.append(ip)
    
    # Return the first non-proxy IP found, or the first IP if all are proxies
    return real_ips[0] if real_ips else ips[0]

def is_private_ip(ip):
    """Check if IP is in private range"""
    try:
        ip_num = ip_to_num(ip)
        # Private IP ranges:
        # 10.0.0.0 - 10.255.255.255
        # 172.16.0.0 - 172.31.255.255
        # 192.168.0.0 - 192.168.255.255
        # 127.0.0.0 - 127.255.255.255 (loopback)
        return (ip_num >= ip_to_num('10.0.0.0') and ip_num <= ip_to_num('10.255.255.255')) or \
               (ip_num >= ip_to_num('172.16.0.0') and ip_num <= ip_to_num('172.31.255.255')) or \
               (ip_num >= ip_to_num('192.168.0.0') and ip_num <= ip_to_num('192.168.255.255')) or \
               (ip_num >= ip_to_num('127.0.0.0') and ip_num <= ip_to_num('127.255.255.255'))
    except:
        return False

def ip_to_num(ip):
    """Convert IP address to numerical value"""
    return sum(int(part) * 256**(3-i) for i, part in enumerate(ip.split('.')))

def is_known_proxy(ip):
    """Check if IP is from known VPN/proxy service (simplified version)"""
    # In a real implementation, you'd want to use a database or API for this
    known_proxy_ranges = [
        # Add known VPN/proxy IP ranges here
        # Example: DigitalOcean (just for demonstration)
        '104.236.', '159.203.', '138.197.', '165.227.'
    ]
    return any(ip.startswith(prefix) for prefix in known_proxy_ranges)

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

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
                is_proxy = data.get("proxy", False) or data.get("vpn", False) or data.get("tor", False)
                loc = f"{lat},{lon}"
                return loc, city, country, is_proxy
    except Exception as e:
        print(f"[GeoError] Failed for {ip}: {e}")
    return "0,0", "Unknown", "Unknown", False

def generate_event_id():
    return str(uuid.uuid4())

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def log_event(ip, ua, msg, path, method, params=None):
    event_id = generate_event_id()
    hostname = get_hostname(ip)
    loc, city, country, is_proxy = get_geo_info(ip)
    timestamp = datetime.now().isoformat()
    data_hash = hash_data(json.dumps(params or {}))
    
    proxy_warning = ""
    if is_proxy:
        proxy_warning = " (Proxy/VPN/Tor detected)"
    
    log_entry = (
        f"EventID: {event_id}\n"
        f"Timestamp: {timestamp}\n"
        f"IP: {ip}{proxy_warning}\n"
        f"Hostname: {hostname}\n"
        f"Location: {loc} ({city}, {country})\n"
        f"Method: {method}\n"
        f"Path: {path}\n"
        f"User-Agent: {ua}\n"
        f"Event: {msg}\n"
        f"DataHash: {data_hash}\n"
        f"IntegrityHash: {hash_data(msg + timestamp)}\n"
        f"{'-'*60}\n"
    )
    with open(LOG_PATH, 'a') as f:
        f.write(log_entry)
    if EMAIL_ALERTS and ("Suspicious" in msg or is_proxy):
        send_email_alert(ip, hostname, msg, path, loc, city, country, ua, event_id, is_proxy)

def send_email_alert(ip, hostname, msg, path, loc, city, country, ua, event_id, is_proxy):
    proxy_note = " (Proxy/VPN/Tor detected)" if is_proxy else ""
    body = (
        f"Suspicious Activity Detected{proxy_note}!\n\n"
        f"Event ID: {event_id}\n"
        f"IP: {ip}{proxy_note}\n"
        f"Hostname: {hostname}\n"
        f"Location: {loc} ({city}, {country})\n"
        f"Event: {msg}\n"
        f"Path: {path}\n"
        f"User-Agent: {ua}\n"
        f"Time: {datetime.now().isoformat()}"
    )
    msg_obj = MIMEText(body)
    subject = "Alert: Suspicious Activity Detected"
    if is_proxy:
        subject += " (Proxy/VPN/Tor)"
    msg_obj['Subject'] = subject
    msg_obj['From'] = 'alert@yourdomain.com'
    msg_obj['To'] = EMAIL_TO

    try:
        s = smtplib.SMTP('localhost')
        s.send_message(msg_obj)
        s.quit()
    except Exception as e:
        print("Email alert failed:", e)

def detect_attack(data):
    patterns = [
        "<script>", "alert(", "onerror=", "onload=", "javascript:",
        "' OR 1=1", "--", "DROP TABLE", ";--", "xp_cmdshell",
        "../", "%00", "`", "$(rm", "wget "
    ]
    for val in data.values():
        for pat in patterns:
            if pat.lower() in val.lower():
                return True
    return False

@app.before_request
def block_banned_ips():
    ip = get_client_ip()
    if ip in BAN_LIST:
        return "403 Forbidden - You are banned", 403

@app.route('/')
def index():
    ip = get_client_ip()
    ua = request.headers.get('User-Agent')
    log_event(ip, ua, "Visited Home Page", request.path, request.method)
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
            log_event(ip, ua, "Suspicious: Injection Attempt", request.path, request.method, data)
            return "Attack Detected", 403

        if username == 'admin' and password == 'password':
            session['user'] = username
            log_event(ip, ua, "Successful Login", request.path, request.method, data)
            return redirect(url_for('admin'))
        else:
            FAILED_LOGINS[ip] = FAILED_LOGINS.get(ip, 0) + 1
            if FAILED_LOGINS[ip] >= 5:
                BAN_LIST.add(ip)
                log_event(ip, ua, "IP Banned due to Brute Force", request.path, request.method)
            else:
                log_event(ip, ua, "Failed Login Attempt", request.path, request.method)
            return "Invalid credentials", 401
    else:
        log_event(ip, ua, "Visited Login Page", request.path, request.method)
        return render_template('login.html')

@app.route('/admin')
def admin():
    if 'user' not in session:
        return redirect(url_for('login'))
    ip = get_client_ip()
    ua = request.headers.get('User-Agent')
    log_event(ip, ua, "Accessed Admin Panel", request.path, request.method)
    with open(LOG_PATH, 'r') as f:
        logs = f.readlines()
    return render_template('admin.html', logs=logs)

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    run_simple("0.0.0.0", int(os.environ.get("PORT", 5000)), app)