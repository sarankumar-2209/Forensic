from flask import Flask, request, render_template, redirect, url_for, session, make_response, flash
import hashlib
import os
import json
import socket
import uuid
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from werkzeug.serving import make_ssl_devcert
from functools import wraps
import re
import time
import ipaddress
import hmac
import urllib.request
import logging
from urllib.parse import urlparse
import geocoder  # New library for enhanced geolocation

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32).hex())

# Security configurations
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
    TEMPLATES_AUTO_RELOAD=True,
    MAX_LOGIN_ATTEMPTS=5,
    BAN_TIME=3600  # 1 hour in seconds
)

# File paths
LOG_DIR = 'logs'
LOG_PATH = os.path.join(LOG_DIR, 'activity.log')
USER_LOGINS_PATH = os.path.join(LOG_DIR, 'user_logins.json')
os.makedirs(LOG_DIR, exist_ok=True)

# Security lists
BAN_LIST = {}  # Now a dict with timestamp for temporary bans
FAILED_LOGINS = {}
RATE_LIMIT = {}

# Email configuration
EMAIL_ALERTS = os.environ.get('EMAIL_ALERTS', 'False').lower() == 'true'
EMAIL_TO = os.environ.get('EMAIL_TO', 'admin@example.com')
EMAIL_FROM = os.environ.get('EMAIL_FROM', 'alerts@example.com')

# TLS Configuration
CERT_FILE = os.environ.get('CERT_FILE', 'cert.pem')
KEY_FILE = os.environ.get('KEY_FILE', 'key.pem')

# Known VPN/Proxy IP ranges
KNOWN_PROXY_NETWORKS = set([
    ipaddress.ip_network('141.101.0.0/16'),  # Cloudflare
    ipaddress.ip_network('108.162.0.0/16'),   # Cloudflare
    ipaddress.ip_network('172.64.0.0/13'),    # Cloudflare
    ipaddress.ip_network('104.16.0.0/12'),    # Cloudflare
    ipaddress.ip_network('162.158.0.0/15'),   # Cloudflare
])

def get_client_ip():
    """Get client IP address considering proxy headers with improved security"""
    headers = request.headers
    ip_chain = headers.get('X-Forwarded-For', headers.get('X-Real-IP', request.remote_addr))
    ips = [ip.strip() for ip in ip_chain.split(',')] if ip_chain else []
    
    # Validate IPs and return the first non-proxy IP
    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not is_proxy_ip(ip_obj):
                return ip
        except ValueError:
            continue
    
    return ips[0] if ips else request.remote_addr

def is_proxy_ip(ip_obj):
    """Check if an IP is likely a proxy/VPN"""
    # First check if it's a private IP
    if ip_obj.is_private:
        return False  # Changed to False since we want to track local IPs
        
    for network in KNOWN_PROXY_NETWORKS:
        if ip_obj in network:
            return True
    return False

def get_hostname(ip):
    """Resolve IP to hostname"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def get_geo_info(ip):
    """Get comprehensive geographical information for an IP address"""
    try:
        # Handle localhost and private IPs with more descriptive info
        if ip in ('127.0.0.1', 'localhost'):
            return {
                "coordinates": "0,0",
                "latitude": 0,
                "longitude": 0,
                "city": "This Device (localhost)",
                "region": "Internal Network",
                "country": "Local Network",
                "isp": "Local Device",
                "timezone": "UTC",
                "proxy": False,
                "map_url": "",
                "network_type": "localhost"
            }
            
        # Check for private IP ranges
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return {
                    "coordinates": "0,0",
                    "latitude": 0,
                    "longitude": 0,
                    "city": f"Local Device ({ip})",
                    "region": "Internal Network",
                    "country": "Local Network",
                    "isp": "Local Network",
                    "timezone": "UTC",
                    "proxy": False,
                    "map_url": "",
                    "network_type": "private"
                }
        except ValueError:
            pass
            
        # First try with geocoder (offline option)
        g = geocoder.ip(ip)
        if g.ok:
            return {
                "coordinates": f"{g.lat},{g.lng}",
                "latitude": g.lat,
                "longitude": g.lng,
                "city": g.city or "Unknown",
                "region": g.state or "Unknown",
                "country": g.country or "Unknown",
                "isp": g.org or "Unknown",
                "timezone": g.timezone or "UTC",
                "proxy": g.is_proxy,
                "map_url": f"https://www.google.com/maps?q={g.lat},{g.lng}"
            }
        
        # Fallback to ipwho.is API
        req = urllib.request.Request(
            f"https://ipwho.is/{ip}",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as url:
            data = json.loads(url.read().decode())
            if data.get("success", False):
                lat = data.get("latitude", 0)
                lon = data.get("longitude", 0)
                return {
                    "coordinates": f"{lat},{lon}",
                    "latitude": lat,
                    "longitude": lon,
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "isp": data.get("connection", {}).get("isp", "Unknown"),
                    "timezone": data.get("timezone", {}).get("id", "UTC"),
                    "proxy": data.get("connection", {}).get("proxy", False),
                    "map_url": f"https://www.google.com/maps?q={lat},{lon}"
                }
    except Exception as e:
        logger.error(f"Geo info error for {ip}: {e}")
        return {
            "coordinates": "0,0",
            "latitude": 0,
            "longitude": 0,
            "city": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "isp": "Unknown",
            "timezone": "UTC",
            "proxy": False,
            "map_url": ""
        }
        
        # Fallback to ipwho.is API
        req = urllib.request.Request(
            f"https://ipwho.is/{ip}",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as url:
            data = json.loads(url.read().decode())
            if data.get("success", False):
                lat = data.get("latitude", 0)
                lon = data.get("longitude", 0)
                return {
                    "coordinates": f"{lat},{lon}",
                    "latitude": lat,
                    "longitude": lon,
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "isp": data.get("connection", {}).get("isp", "Unknown"),
                    "timezone": data.get("timezone", {}).get("id", "UTC"),
                    "proxy": data.get("connection", {}).get("proxy", False),
                    "map_url": f"https://www.google.com/maps?q={lat},{lon}"
                }
                
    except Exception as e:
        logger.error(f"Geo info error for {ip}: {e}")
        
    return {
        "coordinates": "0,0",
        "latitude": 0,
        "longitude": 0,
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "isp": "Unknown",
        "timezone": "UTC",
        "proxy": False,
        "map_url": ""
    }

def generate_event_id():
    """Generate unique event ID"""
    return str(uuid.uuid4())

def hash_data(data):
    """Generate SHA-256 hash of data"""
    if isinstance(data, str):
        return hashlib.sha256(data.encode()).hexdigest()
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

def log_event(ip, ua, msg, path, method, params=None):
    """Enhanced logging with geo information and better error handling"""
    try:
        event_id = generate_event_id()
        timestamp = datetime.now().isoformat()
        hostname = get_hostname(ip)
        geo_info = get_geo_info(ip)
        
        # Sanitize sensitive parameters
        safe_params = {}
        if params:
            for k, v in params.items():
                if isinstance(v, str) and ('pass' in k.lower() or 'token' in k.lower()):
                    safe_params[k] = '*****'
                else:
                    safe_params[k] = v
        
        log_entry = (
            f"EventID: {event_id}\n"
            f"Timestamp: {timestamp}\n"
            f"IP: {ip}\n"
            f"Hostname: {hostname}\n"
            f"ISP: {geo_info['isp']}\n"
            f"City: {geo_info['city']}\n"
            f"Region: {geo_info['region']}\n"
            f"Country: {geo_info['country']}\n"
            f"Coordinates: {geo_info['coordinates']}\n"
            f"Latitude: {geo_info['latitude']}\n"
            f"Longitude: {geo_info['longitude']}\n"
            f"Timezone: {geo_info['timezone']}\n"
            f"Proxy/VPN: {'Yes' if geo_info['proxy'] else 'No'}\n"
            f"Method: {method}\n"
            f"Path: {path}\n"
            f"User-Agent: {ua}\n"
            f"Event: {msg}\n"
            f"DataHash: {hash_data(safe_params)}\n"
            f"IntegrityHash: {hash_data(msg + timestamp)}\n"
            f"{'-'*60}\n"
        )
        
        try:
            with open(LOG_PATH, 'a') as f:
                f.write(log_entry)
        except IOError as e:
            logger.error(f"Failed to write log: {e}")
        
        # Send email alert for suspicious activities
        if EMAIL_ALERTS and ("Suspicious" in msg or "Failed" in msg or "Banned" in msg):
            send_email_alert(ip, hostname, msg, path, geo_info)
    except Exception as e:
        logger.error(f"Error in log_event: {e}")

def log_user_login(username, ip, geo_info):
    """Log user login with location details"""
    try:
        login_data = {
            "timestamp": datetime.now().isoformat(),
            "username": username,
            "ip": ip,
            "geo_info": geo_info,
            "user_agent": request.headers.get('User-Agent', 'Unknown')
        }
        
        # Read existing logins
        logins = []
        if os.path.exists(USER_LOGINS_PATH):
            try:
                with open(USER_LOGINS_PATH, 'r') as f:
                    logins = json.load(f)
            except (IOError, json.JSONDecodeError):
                logins = []
        
        # Add new login and keep only last 100 entries per user
        logins.append(login_data)
        user_logins = [x for x in logins if x.get('username') == username]
        if len(user_logins) > 100:
            logins = [x for x in logins if x not in user_logins[:-100]]
        
        # Save back to file
        with open(USER_LOGINS_PATH, 'w') as f:
            json.dump(logins, f, indent=2)
            
    except Exception as e:
        logger.error(f"Error logging user login: {e}")

def send_email_alert(ip, hostname, msg, path, geo_info):
    """Enhanced email alerts with more information"""
    try:
        body = (
            f"Security Event Alert!\n\n"
            f"Time: {datetime.now().isoformat()}\n"
            f"IP: {ip}\n"
            f"Hostname: {hostname}\n"
            f"ISP: {geo_info['isp']}\n"
            f"Location: {geo_info['city']}, {geo_info['region']}, {geo_info['country']}\n"
            f"Coordinates: {geo_info['coordinates']}\n"
            f"Map: {geo_info['map_url']}\n"
            f"Proxy/VPN: {'Yes' if geo_info['proxy'] else 'No'}\n"
            f"Event: {msg}\n"
            f"Path: {path}\n"
            f"User-Agent: {request.headers.get('User-Agent', 'Unknown')}\n\n"
            f"Review logs for more details."
        )
        
        msg_obj = MIMEText(body)
        msg_obj['Subject'] = f"ALERT: {msg[:50]}..." if len(msg) > 50 else f"ALERT: {msg}"
        msg_obj['From'] = EMAIL_FROM
        msg_obj['To'] = EMAIL_TO

        with smtplib.SMTP('localhost') as s:
            s.send_message(msg_obj)
    except Exception as e:
        logger.error(f"Email alert failed: {e}")

def validate_csrf():
    """Validate CSRF token using constant-time comparison"""
    try:
        token = request.form.get('csrf_token')
        if not token or not hmac.compare_digest(token, session.get('csrf_token', '')):
            return False
        return True
    except Exception as e:
        logger.error(f"CSRF validation error: {e}")
        return False

def rate_limit(ip, endpoint, limit=10, window=60):
    """Improved rate limiting implementation"""
    try:
        now = time.time()
        key = f"{ip}:{endpoint}"
        
        if key not in RATE_LIMIT:
            RATE_LIMIT[key] = []
        
        # Clean up old entries
        RATE_LIMIT[key] = [t for t in RATE_LIMIT[key] if now - t < window]
        
        if len(RATE_LIMIT[key]) >= limit:
            return True
        
        RATE_LIMIT[key].append(now)
        return False
    except Exception as e:
        logger.error(f"Rate limit error: {e}")
        return False

def login_required(f):
    """Decorator to ensure user is logged in with session validation"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if 'user' not in session:
                ip = get_client_ip()
                ua = request.headers.get('User-Agent', 'Unknown')
                log_event(ip, ua, "Unauthorized access attempt", request.path, request.method)
                flash("Please log in to access this page", "error")
                return redirect(url_for('login', next=request.url))
            
            # Validate session consistency
            ip = get_client_ip()
            ua = request.headers.get('User-Agent', 'Unknown')
            if (ip != session.get('login_ip') or 
                ua != session.get('user_agent')):
                log_event(ip, ua, "Possible session hijacking attempt", request.path, request.method)
                session.clear()
                flash("Session security violation detected. Please log in again.", "error")
                return redirect(url_for('login'))
            
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Login required error: {e}")
            session.clear()
            flash("An error occurred. Please log in again.", "error")
            return redirect(url_for('login'))
    return decorated_function

def detect_attack(data):
    """Comprehensive attack pattern detection"""
    try:
        patterns = [
            # XSS patterns
            r"<script[^>]*>", r"alert\s*\(", r"onerror\s*=", r"onload\s*=", 
            r"javascript\s*:", r"<\?php", r"eval\s*\(", r"document\.cookie",
            r"window\.location", r"<iframe", r"<img\s+src=x\s+onerror=",
            
            # SQL injection patterns
            r"'?\s+OR\s+1\s*=\s*1", r"--", r"DROP\s+TABLE", r";\s*--", 
            r"xp_cmdshell", r"union\s+select", r"sleep\s*\(", r"benchmark\s*\(", 
            r"waitfor\s+delay", r"exec\s*\(", r"sys\.", r"system\s*\(",
            
            # Command injection patterns
            r"passthru\s*\(", r"shell_exec\s*\(", r"`", r"\$\s*\(\s*rm", 
            r"wget\s+", r"curl\s+", r"\.\./", r"%00",
            
            # Other dangerous patterns
            r"<\?=", r"<\?", r"<\?php", r"<\?", r"<\?=", r"<\?php", r"<\?"
        ]
        
        for key, val in data.items():
            if not isinstance(val, str):
                continue
                
            # Check for suspicious parameter names
            if any(kw in key.lower() for kw in ['cmd', 'exec', 'shell', 'sh', 'php']):
                return True
                
            # Check for attack patterns in values
            for pat in patterns:
                if re.search(pat, val, re.IGNORECASE):
                    return True
        
        return False
    except Exception as e:
        logger.error(f"Attack detection error: {e}")
        return True  # Fail safe - assume attack if detection fails

@app.before_request
def security_checks():
    """Comprehensive security checks before each request"""
    try:
        ip = get_client_ip()
        path = request.path
        
        # Check if IP is banned (with temporary ban support)
        if ip in BAN_LIST:
            if time.time() - BAN_LIST[ip] < app.config['BAN_TIME']:
                log_event(ip, request.headers.get('User-Agent', 'Unknown'), 
                         "Banned IP access attempt", path, request.method)
                return make_response("403 Forbidden - You are banned", 403)
            else:
                # Ban expired
                del BAN_LIST[ip]
        
        # Apply rate limiting
        if rate_limit(ip, path):
            log_event(ip, request.headers.get('User-Agent', 'Unknown'), 
                     "Rate limit exceeded", path, request.method)
            return make_response("429 Too Many Requests", 429)
        
        # Block requests to common malicious paths
        malicious_paths = [
            '/wp-admin', '/wp-login.php', '/adminer.php', 
            '/.env', '/.git/config', '/phpmyadmin',
            '/.htaccess', '/.htpasswd', '/config.php'
        ]
        if any(mp in path for mp in malicious_paths):
            log_event(ip, request.headers.get('User-Agent', 'Unknown'), 
                     "Attempted access to blocked path", path, request.method)
            return make_response("404 Not Found", 404)
        
        # Force HTTPS in production
        if not request.is_secure and os.environ.get('FLASK_ENV') == 'production':
            return redirect(request.url.replace('http://', 'https://'), code=301)
    except Exception as e:
        logger.error(f"Security check error: {e}")
        return make_response("500 Internal Server Error", 500)

@app.after_request
def security_headers(response):
    """Add comprehensive security headers to all responses"""
    try:
        # Standard security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy
        csp = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'self'"
        ]
        response.headers['Content-Security-Policy'] = "; ".join(csp)
        
        # HSTS for production
        if os.environ.get('FLASK_ENV') == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    except Exception as e:
        logger.error(f"Security headers error: {e}")
    
    return response

@app.route('/')
def index():
    """Home page with visitor location information"""
    try:
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', 'Unknown')
        geo_info = get_geo_info(ip)
        
        log_event(ip, ua, "Visited Home Page", request.path, request.method)
        
        # Generate CSRF token if not exists
        if 'csrf_token' not in session:
            session['csrf_token'] = os.urandom(16).hex()
        
        return render_template('index.html', 
                           csrf_token=session['csrf_token'],
                           visitor_ip=ip,
                           visitor_city=geo_info['city'],
                           visitor_country=geo_info['country'],
                           visitor_isp=geo_info['isp'],
                           visitor_coords=geo_info['coordinates'],
                           visitor_map=geo_info['map_url'])
    except Exception as e:
        logger.error(f"Index route error: {e}")
        return make_response("500 Internal Server Error", 500)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login handler with comprehensive security checks and location tracking"""
    try:
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', 'Unknown')
        geo_info = get_geo_info(ip)
        
        if request.method == 'POST':
            # Validate CSRF token
            if not validate_csrf():
                log_event(ip, ua, "CSRF token validation failed", request.path, request.method)
                session.clear()
                session['csrf_token'] = os.urandom(16).hex()
                flash("Session expired. Please try again.", "error")
                return render_template('login.html', 
                                    error="Session expired. Please try again.",
                                    csrf_token=session['csrf_token']), 403
            
            # Get and sanitize credentials
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            # Check for attack patterns
            if detect_attack({'username': username, 'password': password}):
                log_event(ip, ua, "Suspicious: Injection Attempt", request.path, request.method)
                BAN_LIST[ip] = time.time()  # Temporary ban
                flash("Security violation detected", "error")
                return make_response("Attack Detected", 403)

            # Simple authentication (in production, use proper password hashing)
            if username == 'admin' and password == 'password':
                # Set up secure session
                session['user'] = username
                session.permanent = True
                session['login_ip'] = ip
                session['user_agent'] = ua
                session['last_activity'] = time.time()
                session['geo_info'] = geo_info  # Store location info in session
                session.modified = True
                
                # Log successful login with location
                log_event(ip, ua, "Successful Login", request.path, request.method, {'username': username})
                log_user_login(username, ip, geo_info)
                
                # Redirect to admin or requested page
                next_page = request.args.get('next', url_for('admin'))
                flash("Login successful", "success")
                return redirect(next_page)
            else:
                # Handle failed login
                FAILED_LOGINS[ip] = FAILED_LOGINS.get(ip, 0) + 1
                
                # Ban after configured failed attempts
                if FAILED_LOGINS[ip] >= app.config['MAX_LOGIN_ATTEMPTS']:
                    BAN_LIST[ip] = time.time()
                    log_event(ip, ua, f"IP Banned due to Brute Force (Location: {geo_info['city']}, {geo_info['country']})", 
                            request.path, request.method)
                    flash("Too many failed attempts. Your IP has been temporarily banned.", "error")
                    return make_response("Too many failed attempts. Your IP has been temporarily banned.", 403)
                else:
                    log_event(ip, ua, "Failed Login Attempt", request.path, request.method)
                    flash("Invalid credentials", "error")
                    return render_template('login.html', 
                                        error="Invalid credentials", 
                                        csrf_token=session.get('csrf_token')), 401
        else:
            # GET request - show login form
            if 'csrf_token' not in session:
                session['csrf_token'] = os.urandom(16).hex()
            
            log_event(ip, ua, "Visited Login Page", request.path, request.method)
            return render_template('login.html', csrf_token=session.get('csrf_token'))
    except Exception as e:
        logger.error(f"Login route error: {e}")
        session.clear()
        flash("An error occurred during login", "error")
        return make_response("500 Internal Server Error", 500)

@app.route('/logout')
def logout():
    """Logout handler with session cleanup"""
    try:
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', 'Unknown')
        log_event(ip, ua, "User Logged Out", request.path, request.method)
        session.clear()
        flash("You have been logged out", "success")
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Logout route error: {e}")
        return make_response("500 Internal Server Error", 500)

@app.route('/admin')
@login_required
def admin():
    """Admin dashboard with session validation and location display"""
    try:
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', 'Unknown')
        
        # Check session consistency
        if (ip != session.get('login_ip') or 
            ua != session.get('user_agent')):
            log_event(ip, ua, "Possible session hijacking attempt", request.path, request.method)
            session.clear()
            flash("Session security violation detected", "error")
            return redirect(url_for('login'))
        
        # Update last activity time
        session['last_activity'] = time.time()
        
        # Log admin access
        log_event(ip, ua, "Accessed Admin Panel", request.path, request.method)
        
        # Read and display logs
        try:
            with open(LOG_PATH, 'r') as f:
                logs = f.readlines()
        except IOError as e:
            logger.error(f"Failed to read log file: {e}")
            logs = ["Error reading log file"]
        
        # Get current location info from session
        geo_info = session.get('geo_info', {})
        
        return render_template('admin.html', 
                           logs=logs, 
                           username=session.get('user'),
                           csrf_token=session.get('csrf_token'),
                           login_location=geo_info.get('city', 'Unknown'),
                           login_country=geo_info.get('country', 'Unknown'),
                           login_coords=geo_info.get('coordinates', '0,0'),
                           login_map=geo_info.get('map_url', ''),
                           login_time=session.get('last_activity', ''),
                           login_ip=session.get('login_ip', 'Unknown'))
    except Exception as e:
        logger.error(f"Admin route error: {e}")
        session.clear()
        flash("An error occurred", "error")
        return make_response("500 Internal Server Error", 500)

@app.route('/visitor-info')
@login_required
def visitor_info():
    """Display detailed visitor information for admin with map"""
    try:
        visitors = []
        try:
            with open(LOG_PATH, 'r') as f:
                log_data = f.read()
                
            entries = log_data.split('-'*60)
            for entry in entries:
                if not entry.strip():
                    continue
                    
                visitor = {}
                lines = [line.strip() for line in entry.split('\n') if line.strip()]
                for line in lines:
                    if ':' in line:
                        key, val = line.split(':', 1)
                        visitor[key.strip()] = val.strip()
                
                if visitor:
                    # Enhance local network entries
                    if visitor.get('Country') == 'Local Network':
                        visitor['DisplayLocation'] = 'Local Network'
                        if visitor.get('IP') == '127.0.0.1':
                            visitor['City'] = 'This Computer'
                    else:
                        visitor['DisplayLocation'] = f"{visitor.get('City', 'Unknown')}, {visitor.get('Country', 'Unknown')}"
                    
                    visitors.append(visitor)
            
            # Sort by timestamp (newest first)
            visitors.sort(key=lambda x: x.get('Timestamp', ''), reverse=True)
            
        except IOError as e:
            logger.error(f"Failed to read log file: {e}")
            visitors = []
        
        return render_template('visitor_info.html', 
                           visitors=visitors[:100],
                           username=session.get('user'),
                           csrf_token=session.get('csrf_token'))
    except Exception as e:
        logger.error(f"Visitor info error: {e}")
        flash("An error occurred while retrieving visitor data", "error")
        return redirect(url_for('admin'))

@app.route('/login-history')
@login_required
def login_history():
    """Display login history with locations"""
    try:
        if not os.path.exists(USER_LOGINS_PATH):
            return render_template('login_history.html', 
                               logins=[],
                               username=session.get('user'),
                               csrf_token=session.get('csrf_token'))
        
        with open(USER_LOGINS_PATH, 'r') as f:
            logins = json.load(f)
        
        # Filter for current user and sort by timestamp
        user_logins = [x for x in logins if x.get('username') == session.get('user')]
        user_logins.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return render_template('login_history.html', 
                           logins=user_logins[:50],  # Show last 50 logins
                           username=session.get('user'),
                           csrf_token=session.get('csrf_token'))
    except Exception as e:
        logger.error(f"Login history error: {e}")
        flash("An error occurred while retrieving login history", "error")
        return redirect(url_for('admin'))

def generate_self_signed_cert():
    """Generate self-signed certificate for development"""
    try:
        if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
            logger.info("Generating self-signed certificate...")
            make_ssl_devcert('cert', host='localhost')
            os.rename('cert.crt', CERT_FILE)
            os.rename('cert.key', KEY_FILE)
            logger.info(f"Certificate generated: {CERT_FILE}, {KEY_FILE}")
    except Exception as e:
        logger.error(f"Certificate generation failed: {e}")

if __name__ == '__main__':
    # Generate SSL cert for development
    if os.environ.get('FLASK_ENV') != 'production':
        generate_self_signed_cert()
    
    # Configure SSL context
    ssl_context = (CERT_FILE, KEY_FILE) if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE) else None
    
    # Run the application
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        ssl_context=ssl_context,
        threaded=True,
        debug=(os.environ.get('FLASK_ENV') == 'development'))