from flask import Flask, request, render_template, redirect, url_for, session, abort
from werkzeug.security import check_password_hash, generate_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import smtplib, re, json, os, urllib.request
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from logging.handlers import RotatingFileHandler, SMTPHandler
import logging
import socket
import platform
import uuid
import math

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default_insecure_key")

# Enhanced Configuration
SECURITY_CONFIG = {
    'geoip_enabled': True,
    'threat_intel_enabled': True,
    'request_analysis': True,
    'known_threat_ips': {
        'TOR_EXIT_NODE': ['1.1.1.1', '2.2.2.2'],
        'SPAMMER': ['3.3.3.3'],
        'MALWARE': ['4.4.4.4']
    },
    'suspicious_networks': ['185.', '45.']
}

EMAIL_CONFIG = {
    'alerts_enabled': True,
    'recipient': os.environ.get("ALERT_EMAIL", "admin@example.com"),
    'smtp_server': os.environ.get("SMTP_SERVER", "smtp.example.com"),
    'smtp_port': int(os.environ.get("SMTP_PORT", 587)),
    'smtp_user': os.environ.get("SMTP_USER", "alerts@example.com"),
    'smtp_pass': os.environ.get("SMTP_PASS", ""),
    'from_address': os.environ.get("FROM_EMAIL", "security-alerts@example.com")
}

BAN_DURATION = 600
MAX_LOG_SIZE = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5

limiter = Limiter(app=app, key_func=lambda: get_client_info()[0])

# Advanced Logger Setup
LOG_PATH = 'logs/security.log'
os.makedirs('logs', exist_ok=True)

logger = logging.getLogger('AdvancedSecurityLogger')
logger.setLevel(logging.INFO)

file_handler = RotatingFileHandler(
    LOG_PATH,
    maxBytes=MAX_LOG_SIZE,
    backupCount=LOG_BACKUP_COUNT,
    encoding='utf-8'
)

log_format = '%(asctime)s | %(levelname)s | %(message)s | IP: %(client_ip)s | ' \
             'User: %(user)s | Session: %(session_id)s | ' \
             'Location: %(location)s | Threat: %(threat_info)s'

formatter = logging.Formatter(log_format)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

if EMAIL_CONFIG['alerts_enabled'] and EMAIL_CONFIG['smtp_pass']:
    mail_handler = SMTPHandler(
        mailhost=(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']),
        fromaddr=EMAIL_CONFIG['from_address'],
        toaddrs=[EMAIL_CONFIG['recipient']],
        subject='Critical Security Alert',
        credentials=(EMAIL_CONFIG['smtp_user'], EMAIL_CONFIG['smtp_pass']),
        secure=()
    )
    mail_handler.setLevel(logging.CRITICAL)
    mail_handler.setFormatter(logging.Formatter('''
    Message type:       %(levelname)s
    Time:               %(asctime)s
    Message:            %(message)s
    Client IP:          %(client_ip)s
    Threat Level:       %(threat_info)s
    Location:           %(location)s
    '''))
    logger.addHandler(mail_handler)

BAN_LIST = {}
FAILED_LOGINS = {}

def get_client_info():
    """Advanced client information with proxy detection"""
    ip = (
        request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
        request.headers.get('X-Real-IP', '').split(',')[0].strip() or
        request.remote_addr
    )
    
    # Cloud platform specific handling
    if ip == '127.0.0.1':
        for header in ['X-Forwarded-For', 'X-Render-Forwarded-For']:
            if header in request.headers:
                ips = [x.strip() for x in request.headers[header].split(',')]
                ip = next((x for x in reversed(ips) if x not in ('127.0.0.1', '::1')), ip)

    ua = request.headers.get('User-Agent', 'Unknown')
    session_id = session.get('session_id', 'pre-auth')
    user = session.get('user', 'anonymous')
    
    device_info = {
        'user_agent': ua,
        'accept_language': request.headers.get('Accept-Language', ''),
        'referrer': request.headers.get('Referer', 'direct'),
        'timezone': request.headers.get('X-Timezone-Offset', 'unknown')
    }
    
    return ip, ua, session_id, user, device_info

def get_geo_info(ip):
    """Simplified geo location without coordinates"""
    if not SECURITY_CONFIG['geoip_enabled'] or ip in ['127.0.0.1', '::1']:
        return "Local Network"
    
    try:
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            return f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}"
    except Exception:
        return "Unknown Location"

def check_ip_threat(ip):
    """Advanced threat intelligence check"""
    if not SECURITY_CONFIG['threat_intel_enabled']:
        return {'is_threat': False}
    
    threat_info = {
        'is_threat': False,
        'threat_type': None,
        'confidence': 0
    }
    
    # Check known threat databases
    for threat_type, ips in SECURITY_CONFIG['known_threat_ips'].items():
        if ip in ips:
            threat_info.update({
                'is_threat': True,
                'threat_type': threat_type,
                'confidence': 90
            })
            return threat_info
    
    # Check suspicious networks
    for network in SECURITY_CONFIG['suspicious_networks']:
        if ip.startswith(network):
            threat_info.update({
                'is_threat': True,
                'threat_type': 'SUSPICIOUS_NETWORK',
                'confidence': 70
            })
            return threat_info
    
    return threat_info

def analyze_request(request):
    """Comprehensive request analysis"""
    if not SECURITY_CONFIG['request_analysis']:
        return {}
    
    analysis = {
        'header_anomalies': [],
        'path_anomalies': [],
        'parameter_anomalies': []
    }
    
    # Header analysis
    ua = request.headers.get('User-Agent', '')
    if len(ua) > 200:
        analysis['header_anomalies'].append('oversized_user_agent')
    if 'Accept' in request.headers and request.headers['Accept'] == '*/*':
        analysis['header_anomalies'].append('generic_accept_header')
    
    # Path analysis
    if '..' in request.path or '//' in request.path:
        analysis['path_anomalies'].append('path_traversal_attempt')
    if len(request.path) > 100:
        analysis['path_anomalies'].append('overly_long_path')
    
    # Parameter analysis
    for param, value in request.args.items():
        if len(value) > 100:
            analysis['parameter_anomalies'].append(f'oversized_parameter_{param}')
        if any(char in value for char in [';', '%', '$']):
            analysis['parameter_anomalies'].append(f'suspicious_chars_in_{param}')
    
    return analysis

def detect_attack(data):
    """Detect common attack patterns in input data"""
    attack_patterns = {
        'sql_injection': [r'(\'|\"|--|;|/\*|\*/|@@|char\(|xp_|sp_|exec|union|select|insert|update|delete|drop|alter)'],
        'xss': [r'(<script|javascript:|onerror=|onload=|onmouseover=|alert\(|document\.cookie)'],
        'command_injection': [r'(\||&|;|`|\$\(|\n|\r)']
    }
    
    for field, value in data.items():
        if not isinstance(value, str):
            continue
            
        for attack_type, patterns in attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return True
    return False

def log_event(level, message, extra_data=None):
    """Enhanced logging with threat detection"""
    ip, ua, session_id, user, device_info = get_client_info()
    location = get_geo_info(ip)
    threat_info = check_ip_threat(ip)
    request_analysis = analyze_request(request)
    
    log_data = {
        'client_ip': ip,
        'user': user,
        'session_id': session_id,
        'location': location,
        'threat_info': threat_info.get('threat_type', 'None'),
        'device_info': device_info,
        'request_analysis': request_analysis if request_analysis else None,
        'extra': str(extra_data) if extra_data else None
    }
    
    # Elevate to critical if threat detected
    if threat_info.get('is_threat', False):
        level = 'critical'
        message = f"THREAT DETECTED: {message}"
    
    getattr(logger, level)(message, extra=log_data)
    
    if level == 'critical' and EMAIL_CONFIG['alerts_enabled']:
        send_security_alert(ip, message, location, threat_info, request_analysis)

def send_security_alert(ip, message, location, threat_info, request_analysis):
    """Enhanced security alert email"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"SECURITY ALERT: {message[:50]}..."
        msg['From'] = EMAIL_CONFIG['from_address']
        msg['To'] = EMAIL_CONFIG['recipient']
        
        html = f"""
        <html>
          <body>
            <h2>Security Alert</h2>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Event:</strong> {message}</p>
            
            <h3>Threat Details</h3>
            <table border="1">
              <tr><td>IP Address</td><td>{ip}</td></tr>
              <tr><td>Location</td><td>{location}</td></tr>
              <tr><td>Threat Type</td><td>{threat_info.get('threat_type', 'None')}</td></tr>
              <tr><td>Confidence</td><td>{threat_info.get('confidence', 0)}%</td></tr>
            </table>
            
            <h3>Request Analysis</h3>
            <pre>{json.dumps(request_analysis, indent=2) if request_analysis else 'None'}</pre>
          </body>
        </html>
        """
        
        msg.attach(MIMEText(html, 'html'))
        
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['smtp_user'], EMAIL_CONFIG['smtp_pass'])
            server.send_message(msg)
            
    except Exception as e:
        logger.error(f"Failed to send security alert: {str(e)}")

@app.before_request
def security_checks():
    """Advanced pre-request security checks"""
    ip, _, _, _, _ = get_client_info()
    
    # IP Ban check
    if ip in BAN_LIST:
        if datetime.now() > BAN_LIST[ip]:
            del BAN_LIST[ip]
            log_event('info', f"IP ban expired for {ip}")
        else:
            log_event('warning', "Attempted access from banned IP")
            abort(403, description="IP address temporarily banned")
    
    # New session handling
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
        log_event('info', "New session created")
    
    # Request analysis
    request_analysis = analyze_request(request)
    if request_analysis:
        log_event('warning', "Suspicious request detected", request_analysis)

@app.route('/')
def index():
    log_event('info', "Accessed home page")
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", key_func=lambda: f"{get_client_info()[0]}-login")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        data = {'username': username, 'password': password}

        if detect_attack(data):
            log_event('critical', "Potential attack attempt on login", {
                'username_attempt': username,
                'input_analysis': "Matched known attack patterns"
            })
            abort(403, description="Suspicious activity detected")
        
        # Authentication logic (replace with proper DB in production)
        stored_username = "admin"
        stored_hashed_password = generate_password_hash("password")

        if username == stored_username and check_password_hash(stored_hashed_password, password):
            session['user'] = username
            session['last_login'] = datetime.now().isoformat()
            session['login_count'] = session.get('login_count', 0) + 1
            
            log_event('info', "Successful login", {
                'login_count': session['login_count'],
                'last_login': session['last_login']
            })
            return redirect(url_for('admin'))
        else:
            ip = get_client_info()[0]
            FAILED_LOGINS[ip] = FAILED_LOGINS.get(ip, 0) + 1
            
            if FAILED_LOGINS[ip] >= 5:
                BAN_LIST[ip] = datetime.now() + timedelta(seconds=BAN_DURATION)
                log_event('warning', "IP temporarily banned due to failed logins", {
                    'failed_attempts': FAILED_LOGINS[ip],
                    'ban_duration': BAN_DURATION
                })
            else:
                log_event('warning', "Failed login attempt", {
                    'username_attempt': username,
                    'failed_attempts': FAILED_LOGINS[ip]
                })
            
            return "Invalid credentials", 401
    else:
        log_event('info', "Accessed login page")
        return render_template('login.html')

@app.route('/admin')
def admin():
    if 'user' not in session:
        log_event('warning', "Unauthorized access attempt to admin panel")
        return redirect(url_for('login'))
    
    log_event('info', "Accessed admin panel")
    
    # Read logs with error handling
    try:
        with open(LOG_PATH, 'r', encoding='utf-8') as f:
            logs = f.readlines()[-100:]  # Show last 100 lines
    except Exception as e:
        logs = [f"Error reading log file: {str(e)}"]
        log_event('error', "Failed to read log file", {
            'error': str(e)
        })
    
    return render_template('admin.html', logs=logs)

@app.route('/logout')
def logout():
    user = session.get('user', 'unknown')
    session_id = session.get('session_id', 'unknown')
    
    log_event('info', "User logged out", {
        'user': user,
        'session_duration': str(datetime.now() - datetime.fromisoformat(session.get('last_login', datetime.now().isoformat())))
    })
    
    session.clear()
    return redirect(url_for('index'))

# === Enhanced Security Headers ===
@app.after_request
def apply_security_headers(response):
    """Apply comprehensive security headers"""
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                 "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                 "connect-src 'self'; frame-ancestors 'none';",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
    }
    
    for header, value in headers.items():
        response.headers[header] = value
    
    # Secure cookies
    if 'session' in response.headers.get('Set-Cookie', ''):
        response.headers['Set-Cookie'] = response.headers['Set-Cookie'] + "; SameSite=Strict; Secure; HttpOnly"
    
    return response

if __name__ == '__main__':
    # Log startup information
    startup_log = {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'flask_version': '1.1.2',  # Should be dynamically detected
        'startup_time': datetime.now().isoformat()
    }
    
    logger.info("Application starting", extra={
        'client_ip': '127.0.0.1',
        'user': 'system',
        'session_id': 'startup',
        'location': 'local',
        'threat_info': 'None',
        'device_info': startup_log
    })
    
    app.run(debug=False, host='0.0.0.0', port=5000)