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

# === Configuration ===
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default_insecure_key")

# Enhanced email configuration
EMAIL_CONFIG = {
    'alerts_enabled': True,
    'recipient': os.environ.get("ALERT_EMAIL", "saran2209kumar@gmail.com"),
    'smtp_server': os.environ.get("SMTP_SERVER", "smtp.example.com"),
    'smtp_port': int(os.environ.get("SMTP_PORT", 587)),
    'smtp_user': os.environ.get("SMTP_USER", "alerts@example.com"),
    'smtp_pass': os.environ.get("SMTP_PASS", ""),
    'from_address': os.environ.get("FROM_EMAIL", "security-alerts@example.com")
}

BAN_DURATION = 600  # seconds (10 minutes)
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# === Rate Limiting ===
limiter = Limiter(app=app, key_func=get_remote_address)

# === Logger Setup ===
LOG_PATH = 'logs/activity.log'
os.makedirs('logs', exist_ok=True)

# Create main logger
logger = logging.getLogger('SecurityLogger')
logger.setLevel(logging.INFO)

# File handler with rotation
file_handler = RotatingFileHandler(
    LOG_PATH,
    maxBytes=MAX_LOG_SIZE,
    backupCount=LOG_BACKUP_COUNT,
    encoding='utf-8'
)

# Detailed log format
log_format = '%(asctime)s | %(levelname)s | %(message)s | IP: %(client_ip)s | ' \
              'User: %(user)s | Session: %(session_id)s | ' \
              'Location: %(location)s | Device: %(device_info)s'

formatter = logging.Formatter(log_format)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Optional email logging for critical events
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
    User:               %(user)s
    Session ID:         %(session_id)s
    Location:           %(location)s
    Device Info:        %(device_info)s
    '''))
    logger.addHandler(mail_handler)

# === Ban Handling ===
BAN_LIST = {}
FAILED_LOGINS = {}

# === Utils ===
def get_client_info():
    """Collect comprehensive client information"""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    ua = request.headers.get('User-Agent', 'Unknown')
    session_id = session.get('session_id', 'pre-auth')
    user = session.get('user', 'anonymous')
    
    # Get additional headers that might be useful
    accept_lang = request.headers.get('Accept-Language', '')
    referrer = request.headers.get('Referer', 'direct')
    
    # Basic device detection
    device_info = {
        'user_agent': ua,
        'accept_language': accept_lang,
        'platform': platform.platform(),
        'hostname': socket.gethostname(),
        'referrer': referrer
    }
    
    return ip, ua, session_id, user, device_info

def get_geo_info(ip):
    """Enhanced geo location with fallbacks"""
    try:
        req = urllib.request.Request(f"https://ipwho.is/{ip}", 
                                   headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as url:
            data = json.loads(url.read().decode())
            if data.get("success", False):
                loc = f"{data['latitude']},{data['longitude']}"
                city = data.get('city', 'Unknown')
                country = data.get('country', 'Unknown')
                isp = data.get('connection', {}).get('isp', 'Unknown')
                return loc, city, country, isp
    except Exception as e:
        logger.warning(f"GeoIP lookup failed for {ip}: {str(e)}", extra={
            'client_ip': ip,
            'user': 'system',
            'session_id': 'N/A',
            'location': '0,0',
            'device_info': 'GeoIP service error'
        })
    return "0,0", "Unknown", "Unknown", "Unknown"

def log_event(level, message, extra_data=None):
    """Enhanced logging with contextual information"""
    ip, ua, session_id, user, device_info = get_client_info()
    loc, city, country, isp = get_geo_info(ip)
    
    # Prepare log data
    log_data = {
        'client_ip': ip,
        'user': user,
        'session_id': session_id,
        'location': f"{loc} ({city}, {country}, ISP: {isp})",
        'device_info': str(device_info),
        'path': request.path,
        'method': request.method,
        'extra': str(extra_data) if extra_data else None
    }
    
    # Log at appropriate level
    if level == 'info':
        logger.info(message, extra=log_data)
    elif level == 'warning':
        logger.warning(message, extra=log_data)
    elif level == 'error':
        logger.error(message, extra=log_data)
    elif level == 'critical':
        logger.critical(message, extra=log_data)
    else:
        logger.debug(message, extra=log_data)
    
    # For critical events, trigger additional alerting
    if level == 'critical' and EMAIL_CONFIG['alerts_enabled']:
        send_email_alert(ip, message, request.path, loc, city, country, isp, extra_data)

def send_email_alert(ip, message, path, loc, city, country, isp, extra_data=None):
    """Enhanced email alerts with more details"""
    try:
        # Create message container
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"SECURITY ALERT: {message[:50]}..."
        msg['From'] = EMAIL_CONFIG['from_address']
        msg['To'] = EMAIL_CONFIG['recipient']
        
        # Create HTML content
        html = f"""
        <html>
          <head></head>
          <body>
            <h2>Security Alert</h2>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p><strong>Event:</strong> {message}</p>
            
            <h3>Client Details</h3>
            <table border="1">
              <tr><td>IP Address</td><td>{ip}</td></tr>
              <tr><td>Location</td><td>{loc} ({city}, {country})</td></tr>
              <tr><td>ISP</td><td>{isp}</td></tr>
              <tr><td>Path Accessed</td><td>{path}</td></tr>
              <tr><td>Method</td><td>{request.method}</td></tr>
            </table>
            
            <h3>Additional Data</h3>
            <pre>{json.dumps(extra_data, indent=2) if extra_data else 'None'}</pre>
            
            <h3>Full Headers</h3>
            <pre>{dict(request.headers)}</pre>
          </body>
        </html>
        """
        
        # Attach HTML part
        msg.attach(MIMEText(html, 'html'))
        
        # Send the email
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['smtp_user'], EMAIL_CONFIG['smtp_pass'])
            server.send_message(msg)
            
    except Exception as e:
        logger.error(f"Failed to send email alert: {str(e)}", extra={
            'client_ip': ip,
            'user': 'system',
            'session_id': 'N/A',
            'location': loc,
            'device_info': 'Email alert system'
        })

def detect_attack(data):
    """Enhanced attack detection with comprehensive patterns and heuristics"""
    # Base patterns (expanded list)
    patterns = [
        # SQL Injection
        r"(?:[\s'\"](?:union|select|insert|update|delete|drop|alter|create|truncate|declare|exec|execute|grant|revoke)\s)",
        r"(?:\b(?:OR|AND)\s+\d+=\d+)",
        r"(?:;\s*(?:--|#|/\*))",
        r"(?:\b(?:waitfor|delay|benchmark|sleep)\s*\(\s*)",
        
        # XSS and HTML Injection
        r"(?:<script|<iframe|<img|<svg|<meta|<body|<style|<link|<form|<input|<object|<embed|<video|<audio)",
        r"(?:on\w+\s*=|javascript:|vbscript:|data:|<\?php|<\?)",
        r"(?:\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;)",
        
        # Path/Directory Traversal
        r"(?:\.\./|\.\.\\|~/|\\|//|\\\\|\.\.%2f|\.\.%5c)",
        
        # Command Injection
        r"(?:\|\||&&|;|`|\$(?:\{|\(|\[))",
        r"(?:\b(?:cmd|sh|bash|powershell|python|perl|ruby)\b)",
        
        # Server-Side Template Injection
        r"(?:\{\{.*\}\}|\[\[.*\]\]|<\%.*\%>)",
        
        # File Inclusion
        r"(?:\b(?:include|require)(?:_once)?\s*\(|\b(?:file_get_contents|fopen|readfile)\s*\()",
        
        # XML/XXE
        r"(?:<!DOCTYPE|<!ENTITY|SYSTEM|PUBLIC|CDATA|%[^;]+;)",
        
        # Deserialization attacks
        r"(?:\b(?:unserialize|pickle|yaml\.load|marshal\.loads)\s*\()",
        
        # Regex Injection
        r"(?:\\[sSwWdDbDZzGABb]|\^|\$|\(.*\)|\{\d+,?\d*\})",
        
        # Obfuscation techniques
        r"(?:String\.fromCharCode|eval\(|setTimeout\(|setInterval\(|Function\()",
        r"(?:\.replace\(|\.concat\(|\.substr\(|\.substring\()",
        
        # Special suspicious characters
        r"(?:\x00|\x1a|\x08|\x09|\x0a|\x0d|\x7f)"
    ]
    
    # Context-specific patterns
    username_patterns = [
        r"(?:admin\s*'|root\s*'|system\s*')",
        r"(?:\bor\b\s+\d+=\d+)"
    ]
    
    password_patterns = [
        r"(?:password\s*=|passwd\s*=|pwd\s*=)",
        r"(?:\b(?:true|false|null)\b)"
    ]
    
    # Heuristic checks
    suspicious = False
    attack_details = {
        'fields': {},
        'heuristics': {}
    }
    
    for key, value in data.items():
        if not isinstance(value, str):
            continue
            
        field_details = {
            'patterns_matched': [],
            'length': len(value),
            'entropy': calculate_entropy(value),
            'is_suspicious': False
        }
        
        # Check for extremely long inputs
        if len(value) > 1024:
            field_details['heuristics'] = {'oversized_input': True}
            field_details['is_suspicious'] = True
            log_event('warning', f"Oversized input in field {key} ({len(value)} chars)")
        
        # Check for high entropy (potential encoded/obfuscated payload)
        if field_details['entropy'] > 4.5:  # Normal text entropy is typically 3.5-4.5
            field_details['heuristics']['high_entropy'] = True
            field_details['is_suspicious'] = True
            log_event('warning', f"High entropy input in field {key} ({field_details['entropy']:.2f})")
        
        # Field-specific pattern checks
        current_patterns = patterns.copy()
        if 'user' in key.lower() or 'name' in key.lower():
            current_patterns.extend(username_patterns)
        if 'pass' in key.lower():
            current_patterns.extend(password_patterns)
        
        # Pattern matching
        for pattern in current_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                field_details['patterns_matched'].append(pattern)
                field_details['is_suspicious'] = True
        
        if field_details['is_suspicious']:
            attack_details['fields'][key] = field_details
            suspicious = True
    
    # Additional context checks
    if 'username' in data and 'password' in data:
        # Check for credential stuffing patterns
        if data['username'] == data['password']:
            attack_details['heuristics']['username_password_match'] = True
            suspicious = True
        
        # Check for common default credentials
        common_creds = [
            ('admin', 'admin'),
            ('root', 'toor'),
            ('test', 'test'),
            ('guest', 'guest')
        ]
        for user, pwd in common_creds:
            if data['username'].lower() == user and data['password'].lower() == pwd:
                attack_details['heuristics']['common_credentials'] = True
                suspicious = True
    
    if suspicious:
        log_event('critical', "Potential attack attempt detected", {
            'input_analysis': attack_details,
            'recommended_action': 'block_and_alert'
        })
        return True
    
    return False

def calculate_entropy(s):
    """Calculate Shannon entropy of a string"""
    import math
    if not s:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(s.count(chr(x)))/len(s)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

@app.before_request
def security_checks():
    """Comprehensive pre-request security checks"""
    ip, ua, session_id, user, device_info = get_client_info()
    
    # IP Ban check
    if ip in BAN_LIST:
        ban_time = BAN_LIST[ip]
        if datetime.now() > ban_time:
            del BAN_LIST[ip]
            log_event('info', f"IP ban expired for {ip}")
        else:
            log_event('warning', "Attempted access from banned IP", {
                'ban_expires': ban_time.isoformat(),
                'remaining_ban_time': str(ban_time - datetime.now())
            })
            abort(403, description="IP address temporarily banned")
    
    # Generate session ID if new session
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
        log_event('info', "New session created", {
            'session_id': session['session_id']
        })
    
    # Log all requests (with sensitive data filtered)
    filtered_headers = {k: v for k, v in request.headers.items() 
                       if k.lower() not in ['authorization', 'cookie']}
    
    log_event('debug', "Request received", {
        'headers': filtered_headers,
        'query_params': dict(request.args),
        'form_data': {k: '[FILTERED]' if 'pass' in k.lower() else v 
                     for k, v in request.form.items()} if request.form else None
    })

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
        'device_info': startup_log
    })
    
    app.run(debug=False, host='0.0.0.0', port=5000)