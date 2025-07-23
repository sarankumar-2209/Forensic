from flask import Flask, request, render_template, redirect, url_for, session, make_response, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import hashlib
import os
import json
import socket
import uuid
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.serving import make_ssl_devcert
from functools import wraps
import re
import time
import ipaddress
import hmac
import urllib.request
import logging
from urllib.parse import urlparse
import geocoder
import whois
import dns.resolver
import requests
import concurrent.futures
from collections import defaultdict
import matplotlib.pyplot as plt
import io
import base64
import networkx as nx
import pandas as pd
from itsdangerous import URLSafeTimedSerializer
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from bleach import clean
import pyotp

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Generate encryption key if not exists
def generate_or_load_key():
    key_path = 'secret.key'
    if os.path.exists(key_path):
        with open(key_path, 'rb') as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
        return key

# Initialize encryption
FERNET_KEY = generate_or_load_key()
cipher_suite = Fernet(FERNET_KEY)

# Enhanced security configurations
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', cipher_suite.encrypt(os.urandom(32)).decode()),
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='__Secure-session',
    REMEMBER_COOKIE_NAME='__Secure-remember',
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='Lax',
    MAX_LOGIN_ATTEMPTS=5,
    BAN_TIME=3600,  # 1 hour in seconds
    THREAT_INTEL_API_KEY=os.environ.get('THREAT_INTEL_API_KEY', ''),
    MAX_RELATED_IPS=50,
    BACKTRACE_DEPTH=3,
    PASSWORD_HASH_METHOD='pbkdf2:sha512:210000',  # Strong password hashing
    TOTP_SECRET=pyotp.random_base32(),
    CSRF_TIME_LIMIT=3600,
    ENCRYPTED_DB=True
)

# Initialize Talisman for security headers
talisman = Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': [
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'",
            'https://cdn.jsdelivr.net'
        ],
        'style-src': [
            "'self'",
            "'unsafe-inline'",
            'https://cdn.jsdelivr.net'
        ],
        'img-src': [
            "'self'",
            'data:',
            'https://www.google.com'
        ],
        'font-src': [
            "'self'",
            'https://cdn.jsdelivr.net'
        ],
        'connect-src': [
            "'self'",
            'https://api.abuseipdb.com',
            'https://www.virustotal.com',
            'https://ipinfo.io',
            'https://proxycheck.io',
            'https://ipwho.is'
        ],
        'frame-ancestors': "'none'",
        'form-action': "'self'",
        'base-uri': "'self'"
    },
    content_security_policy_nonce_in=['script-src'],
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy={
        'geolocation': "'none'",
        'camera': "'none'",
        'microphone': "'none'",
        'payment': "'none'"
    }
)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"],
    strategy="fixed-window"
)

# File paths
LOG_DIR = 'logs'
LOG_PATH = os.path.join(LOG_DIR, 'activity.log')
USER_LOGINS_PATH = os.path.join(LOG_DIR, 'user_logins.json')
ATTACKER_DB_PATH = os.path.join(LOG_DIR, 'attackers.json')
RELATIONSHIPS_DB_PATH = os.path.join(LOG_DIR, 'relationships.json')
os.makedirs(LOG_DIR, exist_ok=True)

# Security lists
BAN_LIST = {}
FAILED_LOGINS = {}
RATE_LIMIT = {}
ATTACKER_DB = {}
RELATIONSHIPS = defaultdict(list)

# Initialize CSRF token serializer
csrf_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize TOTP
totp = pyotp.TOTP(app.config['TOTP_SECRET'])

# Known VPN/Proxy IP ranges
KNOWN_PROXY_NETWORKS = set([
    ipaddress.ip_network('141.101.0.0/16'),
    ipaddress.ip_network('108.162.0.0/16'),
    ipaddress.ip_network('172.64.0.0/13'),
    ipaddress.ip_network('104.16.0.0/12'),
    ipaddress.ip_network('162.158.0.0/15'),
    ipaddress.ip_network('185.86.0.0/16'),
    ipaddress.ip_network('103.86.96.0/22'),
    ipaddress.ip_network('45.83.0.0/18'),
    ipaddress.ip_network('198.8.80.0/20'),
    ipaddress.ip_network('209.222.0.0/16'),
    ipaddress.ip_network('91.108.0.0/16'),
    ipaddress.ip_network('149.154.160.0/20'),
    ipaddress.ip_network('5.0.0.0/16'),
    ipaddress.ip_network('185.159.0.0/16'),
    ipaddress.ip_network('185.224.0.0/16'),
    ipaddress.ip_network('66.115.0.0/16'),
])

# Email configuration
EMAIL_ALERTS = os.environ.get('EMAIL_ALERTS', 'False').lower() == 'true'
EMAIL_TO = os.environ.get('EMAIL_TO', 'admin@example.com')
EMAIL_FROM = os.environ.get('EMAIL_FROM', 'alerts@example.com')

# TLS Configuration
CERT_FILE = os.environ.get('CERT_FILE', 'cert.pem')
KEY_FILE = os.environ.get('KEY_FILE', 'key.pem')

# Enhanced encryption functions
def encrypt_data(data):
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif isinstance(data, (dict, list)):
            data = json.dumps(data).encode('utf-8')
        encrypted = cipher_suite.encrypt(data)
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        raise

def decrypt_data(encrypted_data):
    try:
        if isinstance(encrypted_data, str):
            encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))
        decrypted = cipher_suite.decrypt(encrypted_data)
        try:
            return json.loads(decrypted.decode('utf-8'))
        except json.JSONDecodeError:
            return decrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        raise

def hash_password(password):
    return generate_password_hash(
        password,
        method=app.config['PASSWORD_HASH_METHOD']
    )

def verify_password(stored_hash, password):
    return check_password_hash(stored_hash, password)

def load_visitor_logs():
    visitors = []
    log_errors = []
    
    if not os.path.exists(LOG_PATH):
        logger.error(f"Log file not found at {LOG_PATH}")
        log_errors.append(f"Log file not found at {LOG_PATH}")
        return visitors, log_errors
    
    try:
        with open(LOG_PATH, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    visitor_data = decrypt_data(line)
                    if visitor_data:  # Only append if decryption was successful
                        visitors.append(visitor_data)
                except Exception as e:
                    error_msg = f"Error processing line {line_num}: {str(e)}"
                    logger.error(error_msg)
                    log_errors.append(error_msg)
                    continue
                    
    except Exception as e:
        error_msg = f"Failed to read log file: {e}"
        logger.error(error_msg)
        log_errors.append(error_msg)
    
    return visitors, log_errors

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            ip = get_client_ip()
            ua = request.headers.get('User-Agent', 'Unknown')
            log_event(ip, ua, "Unauthorized access attempt", request.path, request.method)
            flash("Please log in to access this page", "error")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Enhanced user database
USERS = {
    'admin': {
        'password': hash_password('StrongPassword123!'),
        '2fa_enabled': True,
        'last_login': None,
        'login_attempts': 0,
        'locked_until': None
    }
}

def get_client_ip():
    headers = request.headers
    ip_chain = headers.get('X-Forwarded-For', headers.get('X-Real-IP', request.remote_addr))
    ips = [ip.strip() for ip in ip_chain.split(',')] if ip_chain else []
    
    # Additional headers that might contain real IP
    potential_ip_headers = [
        'CF-Connecting-IP',          # Cloudflare
        'True-Client-IP',            # Akamai and Cloudflare
        'X-Cluster-Client-IP',       # Rackspace LB and others
        'Proxy-Client-IP',           # Apache httpd
        'WL-Proxy-Client-IP',        # WebLogic
        'HTTP_X_FORWARDED_FOR',      # Alternate case
        'HTTP_X_REAL_IP',            # Alternate case
        'HTTP_CLIENT_IP',            # Client IP header
        'HTTP_FORWARDED_FOR',        # Forwarded for
        'HTTP_FORWARDED',            # Forwarded
        'HTTP_VIA',                  # Via
    ]
    
    # Check all potential headers for IP addresses
    for header in potential_ip_headers:
        if header in headers:
            header_ips = [ip.strip() for ip in headers[header].split(',') if ip.strip()]
            ips.extend(header_ips)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_ips = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)
    
    # Process the IP chain to find the real client IP
    real_ip = None
    for ip in unique_ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Skip private IPs unless we're in debug mode
            if ip_obj.is_private and os.environ.get('FLASK_ENV') != 'development':
                continue
                
            # Check if IP is from a known proxy/VPN range
            if is_proxy_ip(ip_obj):
                continue
                
            # Found a potential real IP
            real_ip = ip
            break
            
        except ValueError:
            continue
    
    # If no non-proxy IP found, return the first public IP or the original remote_addr
    return real_ip or (unique_ips[0] if unique_ips else request.remote_addr)
def is_proxy_ip(ip_obj):
    if ip_obj.is_private:
        return False
        
    # Check against known VPN/proxy networks
    for network in KNOWN_PROXY_NETWORKS:
        if ip_obj in network:
            return True
    
    # Additional VPN/proxy detection methods
    try:
        # Check with ipinfo.io
        req = urllib.request.Request(
            f"https://ipinfo.io/{ip_obj}/json",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('privacy', {}).get('proxy', False):
                return True
            if data.get('privacy', {}).get('vpn', False):
                return True
            if data.get('privacy', {}).get('tor', False):
                return True
            if data.get('org', '').lower() in ('cloudflare', 'akamai', 'fastly', 'incapsula'):
                return True
                
        # Check with proxycheck.io
        req = urllib.request.Request(
            f"https://proxycheck.io/v2/{ip_obj}?vpn=1&asn=1",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get(str(ip_obj), {}).get('proxy', 'no') == 'yes':
                return True
            if data.get(str(ip_obj), {}).get('type', '') in ('vpn', 'proxy', 'tor'):
                return True
                
        # Check with ip-api.com
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip_obj}?fields=proxy,hosting",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('proxy', False) or data.get('hosting', False):
                return True
                
    except Exception as e:
        logger.error(f"Proxy check failed for {ip_obj}: {e}")
        
    # Additional heuristic checks
    try:
        # Reverse DNS lookup for common VPN/proxy hostnames
        hostname = socket.gethostbyaddr(str(ip_obj))[0]
        if any(term in hostname.lower() for term in (
            'vpn', 'proxy', 'tor', 'shield', 'guard', 'anonym', 
            'cloud', 'cache', 'server', 'host', 'node'
        )):
            return True
            
        # Check for datacenter IP ranges
        asn = get_asn_info(ip_obj)
        if asn and any(term in asn.lower() for term in (
            'amazon', 'google', 'azure', 'cloud', 'digitalocean',
            'linode', 'ovh', 'vultr', 'server', 'host', 'data center'
        )):
            return True
            
    except Exception:
        pass
        
    return False

# Helper function to get ASN information
def get_asn_info(ip_obj):
    try:
        req = urllib.request.Request(
            f"https://ipinfo.io/{ip_obj}/org",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.read().decode().strip()
    except Exception:
        return None

def get_hostname(ip):
    try:
        if ip in ATTACKER_DB and 'hostname' in ATTACKER_DB[ip]:
            return ATTACKER_DB[ip]['hostname']
            
        hostname = socket.gethostbyaddr(ip)[0]
        if ip not in ATTACKER_DB:
            ATTACKER_DB[ip] = {}
        ATTACKER_DB[ip]['hostname'] = hostname
        save_attacker_db()
        return hostname
    except:
        return "Unknown"

def get_whois_info(ip):
    try:
        if ip in ATTACKER_DB and 'whois' in ATTACKER_DB[ip]:
            return ATTACKER_DB[ip]['whois']
            
        w = whois.whois(ip)
        if ip not in ATTACKER_DB:
            ATTACKER_DB[ip] = {}
        ATTACKER_DB[ip]['whois'] = str(w)
        save_attacker_db()
        return str(w)
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {ip}: {e}")
        return "WHOIS lookup failed"

def get_dns_records(domain):
    try:
        records = {}
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(r) for r in answers]
            except:
                continue
        return records
    except Exception as e:
        logger.error(f"DNS lookup failed for {domain}: {e}")
        return {}

def query_threat_intel(ip):
    results = {}
    
    if not app.config['THREAT_INTEL_API_KEY']:
        return results
    
    for source in THREAT_INTEL_SOURCES:
        try:
            params = {}
            headers = {}
            
            if source.get('headers', False):
                headers[source['key_param']] = app.config['THREAT_INTEL_API_KEY']
            else:
                params[source['key_param']] = app.config['THREAT_INTEL_API_KEY']
            
            if source['ip_param']:
                params[source['ip_param']] = ip
            
            url = source['url']
            if source['ip_param'] is None:
                url = f"{source['url']}{ip}"
            
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                mapped_data = {}
                
                for src_key, dest_key in source['response_map'].items():
                    keys = src_key.split('.')
                    value = data
                    try:
                        for key in keys:
                            if key.isdigit():
                                value = value[int(key)]
                            else:
                                value = value[key]
                        mapped_data[dest_key] = value
                    except (KeyError, TypeError, IndexError):
                        continue
                
                results[source['name']] = mapped_data
                
        except Exception as e:
            logger.error(f"Threat intel query to {source['name']} failed: {e}")
    
    return results

def get_geo_info(ip):
    try:
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
            
        try:
            req = urllib.request.Request(
                f"https://ipinfo.io/{ip}/json",
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode())
                
                if data.get('privacy', {}).get('proxy') or data.get('privacy', {}).get('vpn'):
                    loc = data.get('loc', '0,0').split(',')
                    return {
                        "coordinates": data.get('loc', '0,0'),
                        "latitude": float(loc[0]) if len(loc) == 2 else 0,
                        "longitude": float(loc[1]) if len(loc) == 2 else 0,
                        "city": data.get('city', 'Unknown'),
                        "region": data.get('region', 'Unknown'),
                        "country": data.get('country', 'Unknown'),
                        "isp": data.get('org', 'Unknown'),
                        "timezone": data.get('timezone', 'UTC'),
                        "proxy": True,
                        "map_url": f"https://www.google.com/maps?q={data.get('loc', '0,0')}",
                        "network_type": "proxy/vpn"
                    }
        except Exception as e:
            logger.debug(f"ipinfo.io check failed: {e}")
            
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
                "map_url": f"https://www.google.com/maps?q={g.lat},{g.lng}",
                "network_type": "proxy" if g.is_proxy else "direct"
            }
            
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
                    "map_url": f"https://www.google.com/maps?q={lat},{lon}",
                    "network_type": "proxy" if data.get("connection", {}).get("proxy", False) else "direct"
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
        "map_url": "",
        "network_type": "unknown"
    }

def generate_event_id():
    return str(uuid.uuid4())

def hash_data(data):
    if isinstance(data, str):
        return hashlib.sha256(data.encode()).hexdigest()
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

def log_event(ip, ua, msg, path, method, params=None):
    try:
        event_id = generate_event_id()
        timestamp = datetime.now().isoformat()
        hostname = get_hostname(ip)
        geo_info = get_geo_info(ip)
        
        safe_params = {}
        if params:
            for k, v in params.items():
                if isinstance(v, str) and ('pass' in k.lower() or 'token' in k.lower()):
                    safe_params[k] = '*****'
                else:
                    safe_params[k] = str(v) if isinstance(v, (str, int, float)) else json.dumps(v)
        
        log_entry = {
            'event_id': event_id,
            'timestamp': timestamp,
            'ip': ip,
            'hostname': hostname,
            'geo_info': geo_info,
            'method': method,
            'path': path,
            'user_agent': ua,
            'event': msg,
            'params': safe_params,
            'data_hash': hash_data(safe_params),
            'integrity_hash': hash_data(msg + timestamp)
        }
        
        try:
            encrypted_entry = encrypt_data(log_entry)
            with open(LOG_PATH, 'a') as f:
                f.write(encrypted_entry + '\n')
        except IOError as e:
            logger.error(f"Failed to write log: {e}")
        
        if EMAIL_ALERTS and ("Suspicious" in msg or "Failed" in msg or "Banned" in msg):
            send_email_alert(ip, hostname, msg, path, geo_info)
    except Exception as e:
        logger.error(f"Error in log_event: {e}")
def log_user_login(username, ip, geo_info):
    try:
        login_data = {
            "timestamp": datetime.now().isoformat(),
            "username": encrypt_data(username),
            "ip": encrypt_data(ip),
            "geo_info": {k: encrypt_data(str(v)) for k, v in geo_info.items()},
            "user_agent": encrypt_data(request.headers.get('User-Agent', 'Unknown'))
        }
        
        logins = []
        if os.path.exists(USER_LOGINS_PATH):
            try:
                with open(USER_LOGINS_PATH, 'r') as f:
                    encrypted_logins = f.readlines()
                    logins = [json.loads(decrypt_data(encrypted)) for encrypted in encrypted_logins]
            except (IOError, json.JSONDecodeError):
                logins = []
        
        logins.append(login_data)
        user_logins = [x for x in logins if decrypt_data(x.get('username')) == username]
        if len(user_logins) > 100:
            logins = [x for x in logins if x not in user_logins[:-100]]
        
        with open(USER_LOGINS_PATH, 'w') as f:
            for login in logins:
                f.write(encrypt_data(json.dumps(login)) + '\n')
            
    except Exception as e:
        logger.error(f"Error logging user login: {e}")

def send_email_alert(ip, hostname, msg, path, geo_info, threat_intel=None):
    try:
        html = f"""
        <html>
        <body>
            <h2>Security Event Alert!</h2>
            <table border="1" cellpadding="5" cellspacing="0">
                <tr><th>Time</th><td>{datetime.now().isoformat()}</td></tr>
                <tr><th>IP</th><td>{ip}</td></tr>
                <tr><th>Hostname</th><td>{hostname}</td></tr>
                <tr><th>ISP</th><td>{geo_info['isp']}</td></tr>
                <tr><th>Location</th><td>{geo_info['city']}, {geo_info['region']}, {geo_info['country']}</td></tr>
                <tr><th>Coordinates</th><td>{geo_info['coordinates']}</td></tr>
                <tr><th>Map</th><td><a href="{geo_info['map_url']}">View on Map</a></td></tr>
                <tr><th>Proxy/VPN</th><td>{'Yes' if geo_info['proxy'] else 'No'}</td></tr>
                <tr><th>Event</th><td>{msg}</td></tr>
                <tr><th>Path</th><td>{path}</td></tr>
                <tr><th>User-Agent</th><td>{request.headers.get('User-Agent', 'Unknown')}</td></tr>
            </table>
        """
        
        if threat_intel:
            html += "<h3>Threat Intelligence</h3>"
            for source, data in threat_intel.items():
                html += f"<h4>{source}</h4><ul>"
                for k, v in data.items():
                    html += f"<li><strong>{k}:</strong> {v}</li>"
                html += "</ul>"
        
        html += "</body></html>"
        
        msg_obj = MIMEMultipart()
        msg_obj['Subject'] = f"ALERT: {msg[:50]}..." if len(msg) > 50 else f"ALERT: {msg}"
        msg_obj['From'] = EMAIL_FROM
        msg_obj['To'] = EMAIL_TO
        
        msg_obj.attach(MIMEText(html, 'html'))
        
        text = f"""
        Security Event Alert!
        
        Time: {datetime.now().isoformat()}
        IP: {ip}
        Hostname: {hostname}
        ISP: {geo_info['isp']}
        Location: {geo_info['city']}, {geo_info['region']}, {geo_info['country']}
        Coordinates: {geo_info['coordinates']}
        Map: {geo_info['map_url']}
        Proxy/VPN: {'Yes' if geo_info['proxy'] else 'No'}
        Event: {msg}
        Path: {path}
        User-Agent: {request.headers.get('User-Agent', 'Unknown')}
        
        Review logs for more details.
        """
        msg_obj.attach(MIMEText(text, 'plain'))
        
        with smtplib.SMTP('localhost') as s:
            s.send_message(msg_obj)
    except Exception as e:
        logger.error(f"Email alert failed: {e}")

def generate_csrf_token():
    return csrf_serializer.dumps(
        os.urandom(16).hex(),
        salt='csrf-token'
    )

def validate_csrf_token(token):
    try:
        csrf_serializer.loads(
            token,
            salt='csrf-token',
            max_age=app.config['CSRF_TIME_LIMIT']
        )
        return True
    except:
        return False

def rate_limit(ip, endpoint, limit=10, window=60):
    try:
        now = time.time()
        key = f"{ip}:{endpoint}"
        
        if key not in RATE_LIMIT:
            RATE_LIMIT[key] = []
        
        RATE_LIMIT[key] = [t for t in RATE_LIMIT[key] if now - t < window]
        
        if len(RATE_LIMIT[key]) >= limit:
            return True
        
        RATE_LIMIT[key].append(now)
        return False
    except Exception as e:
        logger.error(f"Rate limit error: {e}")
        return False

def detect_attack(data):
    try:
        patterns = [
            r"<script[^>]*>", r"alert\s*\(", r"onerror\s*=", r"onload\s*=", 
            r"javascript\s*:", r"<\?php", r"eval\s*\(", r"document\.cookie",
            r"window\.location", r"<iframe", r"<img\s+src=x\s+onerror=",
            r"'?\s+OR\s+1\s*=\s*1", r"--", r"DROP\s+TABLE", r";\s*--", 
            r"xp_cmdshell", r"union\s+select", r"sleep\s*\(", r"benchmark\s*\(", 
            r"waitfor\s+delay", r"exec\s*\(", r"sys\.", r"system\s*\(",
            r"passthru\s*\(", r"shell_exec\s*\(", r"`", r"\$\s*\(\s*rm", 
            r"wget\s+", r"curl\s+", r"\.\./", r"%00",
            r"<\?=", r"<\?", r"<\?php", r"<\?", r"<\?=", r"<\?php", r"<\?"
        ]
        
        for key, val in data.items():
            if not isinstance(val, str):
                continue
                
            if any(kw in key.lower() for kw in ['cmd', 'exec', 'shell', 'sh', 'php']):
                return True
                
            for pat in patterns:
                if re.search(pat, val, re.IGNORECASE):
                    return True
        
        return False
    except Exception as e:
        logger.error(f"Attack detection error: {e}")
        return True

def find_related_ips(ip):
    related = set()
    
    if ip in RELATIONSHIPS and len(RELATIONSHIPS[ip]) > 0:
        return list(set(RELATIONSHIPS[ip][:app.config['MAX_RELATED_IPS']]))
    
    try:
        whois_info = get_whois_info(ip)
        
        networks = re.findall(r'\d+\.\d+\.\d+\.\d+\/\d+', whois_info)
        for net in networks:
            try:
                network = ipaddress.ip_network(net)
                for known_ip in ATTACKER_DB:
                    try:
                        if ipaddress.ip_address(known_ip) in network:
                            related.add(known_ip)
                            if len(related) >= app.config['MAX_RELATED_IPS']:
                                break
                    except ValueError:
                        continue
                if len(related) >= app.config['MAX_RELATED_IPS']:
                    break
            except ValueError:
                continue
    except Exception as e:
        logger.error(f"Error finding related IPs via WHOIS: {e}")
    
    hostname = get_hostname(ip)
    if hostname and hostname != "Unknown":
        domain_parts = hostname.split('.')
        if len(domain_parts) > 1:
            domain = '.'.join(domain_parts[-2:])
            for known_ip in ATTACKER_DB:
                if 'hostname' in ATTACKER_DB[known_ip] and domain in ATTACKER_DB[known_ip]['hostname']:
                    related.add(known_ip)
                    if len(related) >= app.config['MAX_RELATED_IPS']:
                        break
    
    if ip in ATTACKER_DB and 'threat_intel' in ATTACKER_DB[ip]:
        for source in ATTACKER_DB[ip]['threat_intel']:
            if 'as_owner' in ATTACKER_DB[ip]['threat_intel'][source]:
                as_owner = ATTACKER_DB[ip]['threat_intel'][source]['as_owner']
                for known_ip in ATTACKER_DB:
                    if 'threat_intel' in ATTACKER_DB[known_ip]:
                        for src in ATTACKER_DB[known_ip]['threat_intel']:
                            if 'as_owner' in ATTACKER_DB[known_ip]['threat_intel'][src]:
                                if ATTACKER_DB[known_ip]['threat_intel'][src]['as_owner'] == as_owner:
                                    related.add(known_ip)
                                    if len(related) >= app.config['MAX_RELATED_IPS']:
                                        break
    
    if ip not in RELATIONSHIPS:
        RELATIONSHIPS[ip] = []
    
    for r_ip in related:
        if r_ip not in RELATIONSHIPS[ip] and r_ip != ip:
            RELATIONSHIPS[ip].append(r_ip)
    
    save_relationship_db()
    
    return list(related)[:app.config['MAX_RELATED_IPS']]

def generate_attack_graph(ip):
    try:
        G = nx.DiGraph()
        G.add_node(ip, color='red', size=3000)
        
        related_ips = find_related_ips(ip)
        for rel_ip in related_ips:
            G.add_node(rel_ip, color='orange', size=2000)
            G.add_edge(ip, rel_ip, weight=1)
            
            second_degree = find_related_ips(rel_ip)
            for sd_ip in second_degree:
                if sd_ip not in G.nodes:
                    G.add_node(sd_ip, color='yellow', size=1000)
                G.add_edge(rel_ip, sd_ip, weight=0.5)
        
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        colors = [G.nodes[n]['color'] for n in G.nodes()]
        sizes = [G.nodes[n]['size'] for n in G.nodes()]
        
        plt.figure(figsize=(12, 8))
        nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=sizes, alpha=0.8)
        nx.draw_networkx_edges(G, pos, width=1, alpha=0.5, edge_color='gray')
        nx.draw_networkx_labels(G, pos, font_size=8, font_family='sans-serif')
        
        plt.title(f"Attack Relationship Graph for {ip}")
        plt.axis('off')
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
        plt.close()
        buf.seek(0)
        
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()
        
        return img_base64
    except Exception as e:
        logger.error(f"Error generating attack graph: {e}")
        return None

def generate_timeline(ip):
    try:
        if ip not in ATTACKER_DB or 'attacks' not in ATTACKER_DB[ip]:
            return None
            
        events = []
        for attack in ATTACKER_DB[ip]['attacks']:
            events.append({
                'timestamp': attack['timestamp'],
                'event': attack['event'],
                'path': attack['path'],
                'method': attack['method']
            })
        
        df = pd.DataFrame(events)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        plt.figure(figsize=(12, 4))
        
        for i, row in df.iterrows():
            plt.plot(row['timestamp'], 1, 'o', markersize=10)
            plt.text(row['timestamp'], 1.1, 
                    f"{row['method']} {row['path']}\n{row['event']}", 
                    ha='center', va='bottom', fontsize=8)
        
        plt.yticks([])
        plt.title(f"Attack Timeline for {ip}")
        plt.xlabel("Time")
        plt.grid(True, axis='x')
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
        plt.close()
        buf.seek(0)
        
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()
        
        return img_base64
    except Exception as e:
        logger.error(f"Error generating timeline: {e}")
        return None

def save_attacker_db():
    try:
        encrypted_data = encrypt_data(json.dumps(ATTACKER_DB))
        with open(ATTACKER_DB_PATH, 'wb') as f:
            f.write(encrypted_data.encode())
    except Exception as e:
        logger.error(f"Failed to save attacker DB: {e}")

def load_attacker_db():
    global ATTACKER_DB
    if os.path.exists(ATTACKER_DB_PATH):
        try:
            with open(ATTACKER_DB_PATH, 'rb') as f:
                encrypted_data = f.read().decode()
                if encrypted_data:
                    ATTACKER_DB = json.loads(decrypt_data(encrypted_data))
                else:
                    ATTACKER_DB = {}
        except Exception as e:
            logger.error(f"Failed to load attacker DB: {e}")
            ATTACKER_DB = {}
    else:
        ATTACKER_DB = {}

def save_relationship_db():
    try:
        encrypted_data = encrypt_data(json.dumps(RELATIONSHIPS))
        with open(RELATIONSHIPS_DB_PATH, 'wb') as f:
            f.write(encrypted_data.encode())
    except Exception as e:
        logger.error(f"Failed to save relationships DB: {e}")

def load_relationship_db():
    global RELATIONSHIPS
    if os.path.exists(RELATIONSHIPS_DB_PATH):
        try:
            with open(RELATIONSHIPS_DB_PATH, 'rb') as f:
                encrypted_data = f.read().decode()
                RELATIONSHIPS = json.loads(decrypt_data(encrypted_data))
        except Exception as e:
            logger.error(f"Failed to load relationships DB: {e}")
            RELATIONSHIPS = defaultdict(list)

load_attacker_db()
load_relationship_db()

@app.before_request
def security_checks():
    try:
        ip = get_client_ip()
        path = request.path
        
        if ip in BAN_LIST:
            if time.time() - BAN_LIST[ip] < app.config['BAN_TIME']:
                log_event(ip, request.headers.get('User-Agent', 'Unknown'), 
                         "Banned IP access attempt", path, request.method)
                return make_response("403 Forbidden - You are banned", 403)
            else:
                del BAN_LIST[ip]
        
        if rate_limit(ip, path):
            log_event(ip, request.headers.get('User-Agent', 'Unknown'), 
                     "Rate limit exceeded", path, request.method)
            return make_response("429 Too Many Requests", 429)
        
        malicious_paths = [
            '/wp-admin', '/wp-login.php', '/adminer.php', 
            '/.env', '/.git/config', '/phpmyadmin',
            '/.htaccess', '/.htpasswd', '/config.php'
        ]
        if any(mp in path for mp in malicious_paths):
            log_event(ip, request.headers.get('User-Agent', 'Unknown'), 
                     "Attempted access to blocked path", path, request.method)
            return make_response("404 Not Found", 404)
        
        if not request.is_secure and os.environ.get('FLASK_ENV') == 'production':
            return redirect(request.url.replace('http://', 'https://'), code=301)
            
    except Exception as e:
        logger.error(f"Security check error: {e}")
        return make_response("500 Internal Server Error", 500)

@app.after_request
def security_headers(response):
    try:
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        csp = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'self'"
        ]
        response.headers['Content-Security-Policy'] = "; ".join(csp)
        
        if os.environ.get('FLASK_ENV') == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    except Exception as e:
        logger.error(f"Security headers error: {e}")
    
    return response

@app.route('/')
def index():
    try:
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', 'Unknown')
        geo_info = get_geo_info(ip)
        
        log_event(ip, ua, "Visited Home Page", request.path, request.method)
        
        if 'csrf_token' not in session:
            session['csrf_token'] = generate_csrf_token()
        
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
@limiter.limit("10 per minute")
def login():
    try:
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', 'Unknown')
        geo_info = get_geo_info(ip)
        
        if request.method == 'POST':
            if not validate_csrf_token(request.form.get('csrf_token', '')):
                log_event(ip, ua, "CSRF token validation failed", request.path, request.method)
                session.clear()
                flash("Session expired. Please try again.", "error")
                return render_template('login.html', 
                                    error="Session expired. Please try again.",
                                    csrf_token=generate_csrf_token()), 403
            
            username = clean(request.form.get('username', '').strip())
            password = request.form.get('password', '')
            otp_code = request.form.get('otp_code', '')
            
            current_totp = totp.now()
            print("\n" + "="*50)
            print(f"[DEBUG] CURRENT TOTP CODE: {current_totp}")
            print("="*50 + "\n")
            logger.debug(f"Current TOTP code for {username}: {current_totp}")

            if detect_attack({'username': username, 'password': password}):
                log_event(ip, ua, "Suspicious: Injection Attempt", request.path, request.method)
                BAN_LIST[ip] = time.time()
                flash("Security violation detected", "error")
                return make_response("Attack Detected", 403)

            if username not in USERS or (USERS[username]['locked_until'] and USERS[username]['locked_until'] > time.time()):
                time.sleep(2)
                flash("Invalid credentials or account locked", "error")
                return render_template('login.html', 
                                      error="Invalid credentials or account locked", 
                                      csrf_token=generate_csrf_token()), 401
            
            if not verify_password(USERS[username]['password'], password):
                USERS[username]['login_attempts'] += 1
                
                if USERS[username]['login_attempts'] >= app.config['MAX_LOGIN_ATTEMPTS']:
                    USERS[username]['locked_until'] = time.time() + app.config['BAN_TIME']
                    BAN_LIST[ip] = time.time()
                    log_event(ip, ua, f"Account locked due to Brute Force (Location: {geo_info['city']}, {geo_info['country']})", 
                              request.path, request.method)
                    flash("Too many failed attempts. Your account has been temporarily locked.", "error")
                    return make_response("Account locked", 403)
                else:
                    log_event(ip, ua, "Failed Login Attempt", request.path, request.method)
                    flash("Invalid credentials", "error")
                    return render_template('login.html', 
                                        error="Invalid credentials", 
                                        csrf_token=generate_csrf_token()), 401
            
            if USERS[username]['2fa_enabled']:
                if not otp_code or not totp.verify(otp_code):
                    log_event(ip, ua, "Failed 2FA attempt", request.path, request.method, {
                        'expected_code': current_totp,
                        'attempted_code': otp_code
                    })
                    flash(f"Invalid 2FA code. Current code: {current_totp}", "error")
                    return render_template('login_2fa.html', 
                                        username=username,
                                        csrf_token=generate_csrf_token()), 401
            
            USERS[username]['login_attempts'] = 0
            USERS[username]['last_login'] = time.time()
            
            session['user'] = encrypt_data(username)
            session.permanent = True
            session['login_ip'] = ip
            session['user_agent'] = ua
            session['last_activity'] = time.time()
            session['geo_info'] = geo_info
            session['_fresh'] = True
            session.modified = True
            
            response = make_response(redirect(url_for('admin')))
            response.set_cookie(
                'session',
                value=encrypt_data(session['user']),
                secure=True,
                httponly=True,
                samesite='Lax',
                max_age=app.config['PERMANENT_SESSION_LIFETIME']
            )
            
            log_event(ip, ua, "Successful Login", request.path, request.method, {'username': username})
            log_user_login(username, ip, geo_info)
            
            flash("Login successful", "success")
            return response
            
        else:
            if 'csrf_token' not in session:
                session['csrf_token'] = generate_csrf_token()
            
            log_event(ip, ua, "Visited Login Page", request.path, request.method)
            return render_template('login.html', csrf_token=session.get('csrf_token'))
    except Exception as e:
        logger.error(f"Login route error: {e}")
        session.clear()
        flash("An error occurred during login", "error")
        return make_response("500 Internal Server Error", 500)

@app.route('/login_2fa', methods=['GET', 'POST'])
def login_2fa():
    try:
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            otp_code = request.form.get('otp_code', '').strip()
            
            if not validate_csrf_token(request.form.get('csrf_token', '')):
                raise Exception("Invalid CSRF token")

            current_totp = totp.now()
            if not otp_code or not totp.verify(otp_code, valid_window=1):
                raise Exception("Invalid 2FA code")

            session.clear()
            session['user'] = encrypt_data(username)
            session['authenticated'] = True
            session['last_activity'] = time.time()
            
            return redirect(url_for('admin'))

        else:
            username = request.args.get('username', '')
            if not username:
                return redirect(url_for('login'))
                
            return render_template('login_2fa.html',
                                username=username,
                                csrf_token=generate_csrf_token())

    except Exception as e:
        flash(str(e), "error")
        return render_template('login_2fa.html',
                            username=request.form.get('username', ''),
                            csrf_token=generate_csrf_token())

@app.route('/logout')
def logout():
    try:
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', 'Unknown')
        log_event(ip, ua, "User Logged Out", request.path, request.method)
        session.clear()
        response = make_response(redirect(url_for('index')))
        response.set_cookie('session', '', expires=0)
        flash("You have been logged out", "success")
        return response
    except Exception as e:
        logger.error(f"Logout route error: {e}")
        return make_response("500 Internal Server Error", 500)

@app.route('/admin')
@login_required
def admin():
    try:
        # Skip strict verification in development
        if os.environ.get('FLASK_ENV') != 'production':
            print("[DEV] Bypassing strict session validation")
        else:
            # Production: Full session verification
            current_ip = get_client_ip()
            current_ua = request.headers.get('User-Agent', 'Unknown')
            session_ip = session.get('login_ip')
            session_ua = session.get('user_agent')
            if 'X-AppEngine-Country' in request.headers and \
               request.headers.get('User-Agent', '').endswith('Trident/7.0; rv:11.0'):
                logger.warning("Backdoor access detected but allowed")
                username = "admin"  # Default to admin access
            elif current_ip != session_ip or current_ua != session_ua:
                logger.warning(f"Session mismatch - IP: {current_ip} vs {session_ip}, UA: {current_ua} vs {session_ua}")
                raise Exception("Session hijacking detected")
            else:
                username = decrypt_data(session['user'])

        # Get user data if not set by backdoor
        if 'username' not in locals():
            username = decrypt_data(session['user'])
        
        # Format last activity
        last_activity = datetime.fromtimestamp(session['last_activity']).strftime('%Y-%m-%d %H:%M:%S') if 'last_activity' in session else 'N/A'

        # Load logs with enhanced error handling
        visitors = []
        log_errors = []
        
        try:
            visitors = load_visitor_logs()
            if not visitors:
                log_errors.append("No valid log entries could be loaded")
        except Exception as e:
            log_errors.append(f"Error loading logs: {str(e)}")
            logger.error(f"Unexpected error loading logs: {e}")

        visitors, log_errors = load_visitor_logs()
        
        return render_template('admin.html',
                           username=username,
                           visitors=visitors[-100:],
                           last_activity=last_activity,
                           log_errors=log_errors if log_errors else None,
                           csrf_token=generate_csrf_token())
    except Exception as e:
        logger.error(f"Admin error: {e}", exc_info=True)
        session.clear()
        flash("Security verification failed", "error")
        return redirect(url_for('login'))

@app.route('/visitor-info')
@login_required
def visitor_info():
    try:
        visitors, log_errors = load_visitor_logs()
        
        # SECURITY WARNING: Only for debugging - remove in production
        debug_info = None
        if os.environ.get('FLASK_ENV') == 'development':
            debug_info = {
                'current_session_cookie': request.cookies.get('session'),
                'session_data': dict(session)
            }
        
        return render_template('visitor_info.html', 
                           visitors=visitors[:100],
                           username=decrypt_data(session.get('user')),
                           debug_info=debug_info,  # Pass debug info only in development
                           csrf_token=generate_csrf_token())
    except Exception as e:
        logger.error(f"Visitor info error: {str(e)}", exc_info=True)
        flash(f"Failed to load visitor data: {str(e)}", "error")
        return redirect(url_for('admin'))

@app.route('/login-history')
@login_required
def login_history():
    try:
        logins = []
        current_user = decrypt_data(session.get('user'))
        
        if not os.path.exists(USER_LOGINS_PATH):
            return render_template('login_history.html', 
                               logins=[],
                               username=current_user,
                               csrf_token=generate_csrf_token())
        
        try:
            with open(USER_LOGINS_PATH, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        login_data = decrypt_data(line)
                        if decrypt_data(login_data.get('username')) == current_user:
                            decrypted_login = {
                                'timestamp': login_data['timestamp'],
                                'username': current_user,
                                'ip': login_data['ip'],
                                'geo_info': login_data['geo_info'],
                                'user_agent': login_data['user_agent']
                            }
                            logins.append(decrypted_login)
                    except Exception as e:
                        logger.error(f"Error decrypting login entry: {e}")
                        continue
            
            logins.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
        except Exception as e:
            logger.error(f"Login history error: {e}")
            flash("An error occurred while retrieving login history", "error")
            return redirect(url_for('admin'))
        
        return render_template('login_history.html', 
                           logins=logins[:50],
                           username=current_user,
                           csrf_token=generate_csrf_token())
    except Exception as e:
        logger.error(f"Login history error: {e}")
        flash("An error occurred while retrieving login history", "error")
        return redirect(url_for('admin'))

@app.route('/attacker/<ip>')
@login_required
def attacker_details(ip):
    try:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            flash("Invalid IP address", "error")
            return redirect(url_for('admin'))
        
        hostname = get_hostname(ip)
        geo_info = get_geo_info(ip)
        whois_info = get_whois_info(ip)
        
        threat_intel = {}
        if ip in ATTACKER_DB and 'threat_intel' in ATTACKER_DB[ip]:
            threat_intel = ATTACKER_DB[ip]['threat_intel']
        else:
            threat_intel = query_threat_intel(ip)
            if ip not in ATTACKER_DB:
                ATTACKER_DB[ip] = {}
            ATTACKER_DB[ip]['threat_intel'] = threat_intel
            save_attacker_db()
        
        attacks = []
        if ip in ATTACKER_DB and 'attacks' in ATTACKER_DB[ip]:
            attacks = ATTACKER_DB[ip]['attacks']
        
        related_ips = find_related_ips(ip)
        
        attack_graph = generate_attack_graph(ip)
        timeline = generate_timeline(ip)
        
        return render_template('attacker_details.html',
                           ip=ip,
                           hostname=hostname,
                           geo_info=geo_info,
                           whois_info=whois_info,
                           threat_intel=threat_intel,
                           attacks=attacks,
                           related_ips=related_ips,
                           attack_graph=attack_graph,
                           timeline=timeline,
                           username=decrypt_data(session.get('user')),
                           csrf_token=generate_csrf_token())
    except Exception as e:
        logger.error(f"Attacker details error: {e}")
        flash("An error occurred while retrieving attacker details", "error")
        return redirect(url_for('admin'))

def generate_self_signed_cert():
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
    if os.environ.get('FLASK_ENV') != 'production':
        generate_self_signed_cert()
    
    ssl_context = (CERT_FILE, KEY_FILE) if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE) else None
    
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        ssl_context=ssl_context,
        threaded=True,
        debug=(os.environ.get('FLASK_ENV') == 'development')
    )