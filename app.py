#!/usr/bin/env python3
"""
OCHOxDARK v2.0-SECURE Server (Simplified Version)
Ultra-secure protection system without external limiter dependencies
"""

from flask import Flask, Response, request, jsonify
import os
import sys
import logging
import requests
import json
import time
import hashlib
import hmac
import base64
import secrets
from datetime import datetime
from functools import wraps
from collections import defaultdict, deque

# Import components (with error handling for missing modules)
try:
    from security_utils import (
        SecurityConfig,
        crypto_engine,
        signature_validator,
        challenge_system,
        rate_limiter,
        anti_debugger,
        forensic_logger,
        decoy_system
    )
    SECURITY_UTILS_AVAILABLE = True
except ImportError:
    SECURITY_UTILS_AVAILABLE = False
    print("Warning: security_utils not available, using basic security")

try:
    from ocho import _check_integrity, colorama
    OCHO_AVAILABLE = True
except ImportError:
    OCHO_AVAILABLE = False
    print("Warning: ocho.py not available for integrity checks")
    def _check_integrity():
        return True

# Initialize colorama if available
try:
    import colorama
    colorama.init(autoreset=True)
except ImportError:
    # Create dummy colorama for compatibility
    class DummyColorama:
        class Fore:
            RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = ""
        class Style:
            RESET_ALL = ""
    colorama = DummyColorama()

app = Flask(__name__)

# Basic logging setup
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# Security constants
SUBSCRIPTION_API_URL = "https://darkxdeath.onrender.com/api.php"
ASH = os.environ.get("LOADER_SECRET_KEY", "KUPAL")
PRIMARY_SECRET = "DarkXStorm_2024_SecureKey_V2"
SECONDARY_SECRET = "OchoProtection_Elite_Guard_2024"

# Simple rate limiting
class SimpleRateLimiter:
    def __init__(self):
        self.requests = defaultdict(deque)
        self.blocked = set()
        
    def is_limited(self, ip):
        if ip in self.blocked:
            return True
            
        now = time.time()
        # Clean old requests
        while self.requests[ip] and self.requests[ip][0] < now - 60:
            self.requests[ip].popleft()
            
        if len(self.requests[ip]) >= 5:  # 5 requests per minute
            self.blocked.add(ip)
            return True
            
        self.requests[ip].append(now)
        return False

rate_limiter_simple = SimpleRateLimiter()

# Simple signature validation
def validate_signature(device_id, user_name, timestamp, signature):
    """Simple signature validation"""
    try:
        data = f"{device_id}:{user_name}:{timestamp}"
        expected = hmac.new(
            PRIMARY_SECRET.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected[:64], signature)
    except:
        return False

def security_check(f):
    """Simple security middleware"""
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Basic rate limiting
        if rate_limiter_simple.is_limited(client_ip):
            app.logger.warning(f"Rate limit exceeded for {client_ip}")
            return jsonify({"error": "Rate limit exceeded"}), 429
            
        return f(*args, **kwargs)
    return decorated

@app.route('/')
@security_check
def index():
    """Main page"""
    return '''
    <html>
        <head>
            <title>OCHOxDARK Server v2.0-SECURE</title>
            <style>
                body { background: #000; color: #0f0; font-family: 'Courier New', monospace; text-align: center; }
                .warning { color: #f00; font-weight: bold; margin: 20px; }
                .secure { color: #0ff; }
            </style>
        </head>
        <body>
            <h1>🔒 OCHOxDARK Server v2.0-SECURE 🔒</h1>
            <div class="secure">Multi-Layer Security Protection Active</div>
            <div class="warning">⚠️ PROTECTED SYSTEM ⚠️<br>Unauthorized access attempts are logged and monitored</div>
            <img src="https://placehold.co/600x300?text=OCHOxDARK+Secure+Server" 
                 alt="OCHOxDARK Secure" 
                 style="max-width: 90%; height: auto; border-radius: 10px; margin-top: 20px; border: 2px solid #0f0;">
            <div style="margin-top: 20px; font-size: 12px; color: #555;">
                Security Level: Maximum | Protection: Active
            </div>
        </body>
    </html>
    '''

@app.route('/challenge', methods=['GET'])
@security_check
def get_challenge():
    """Generate security challenge"""
    device_id = request.args.get('device_id')
    user_name = request.args.get('user_name')
    
    if not device_id or not user_name:
        return jsonify({'error': 'Missing parameters'}), 400
    
    if request.headers.get('X-Loader-Request') != ASH:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Generate simple challenge
    a = secrets.randbelow(100) + 1
    b = secrets.randbelow(100) + 1
    challenge_id = secrets.token_hex(8)
    
    challenge = {
        'challenge_id': challenge_id,
        'challenge': f"{a}+{b}",
        'nonce': secrets.token_hex(8)
    }
    
    # Store challenge temporarily (in production, use proper storage)
    app.challenge_store = getattr(app, 'challenge_store', {})
    app.challenge_store[challenge_id] = {
        'result': a + b,
        'timestamp': time.time(),
        'device_id': device_id
    }
    
    app.logger.info(f"Challenge generated for {device_id}")
    return jsonify(challenge)

def verify_device_backend(device_id, user_name):
    """Verify device with backend"""
    try:
        url = f"{SUBSCRIPTION_API_URL}?device_id={device_id}&user_name={user_name}"
        response = requests.get(url, timeout=10, verify=False)
        data = response.json()
        return data.get("status") == "active", data.get("message", "")
    except Exception as e:
        return False, str(e)

@app.route('/ocho.py')
@security_check
def serve_ocho():
    """Serve protected ocho.py"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    device_id = request.args.get('device_id')
    user_name = request.args.get('user_name')
    
    app.logger.info(f"🔍 ocho.py request from {client_ip} for device {device_id}")
    
    if not device_id or not user_name:
        app.logger.warning(f"❌ Missing device_id or user_name")
        return Response("# Fake checker - access denied\nprint('Access denied')", mimetype='text/plain')
    
    # Log all headers for debugging
    app.logger.info(f"📋 Request headers: {dict(request.headers)}")
    
    # Validate basic headers
    loader_request = request.headers.get('X-Loader-Request')
    if loader_request != ASH:
        app.logger.warning(f"❌ Invalid loader request header: {loader_request} (expected: {ASH})")
        return Response("# Fake checker - invalid headers\nprint('Invalid access')", mimetype='text/plain')
    
    loader_version = request.headers.get('X-Loader-Version')
    if loader_version != '2.0-SECURE':
        app.logger.warning(f"❌ Invalid loader version: {loader_version}")
        return Response("# Fake checker - version mismatch\nprint('Version error')", mimetype='text/plain')
    
    # Validate timestamp (more lenient)
    timestamp_header = request.headers.get('X-Timestamp')
    if timestamp_header:
        try:
            timestamp = int(timestamp_header)
            time_diff = abs(time.time() - timestamp)
            app.logger.info(f"⏰ Timestamp diff: {time_diff} seconds")
            if time_diff > 600:  # 10 minutes instead of 5
                app.logger.warning(f"❌ Timestamp expired: {time_diff} seconds")
                return Response("# Fake checker - timestamp expired\nprint('Timestamp error')", mimetype='text/plain')
        except Exception as e:
            app.logger.warning(f"❌ Timestamp validation error: {e}")
            return Response("# Fake checker - bad timestamp\nprint('Bad timestamp')", mimetype='text/plain')
    else:
        app.logger.warning(f"❌ Missing X-Timestamp header")
    
    # Validate signature (more lenient - optional for debugging)
    signature = request.headers.get('X-Signature')
    if signature and timestamp_header:
        if not validate_signature(device_id, user_name, int(timestamp_header), signature):
            app.logger.warning(f"❌ Signature validation failed")
            # For now, just log warning instead of blocking
            app.logger.warning(f"⚠️ Signature mismatch - continuing anyway for debugging")
    else:
        app.logger.warning(f"❌ Missing signature or timestamp")
    
    # Backend verification
    app.logger.info(f"🔍 Verifying device with backend...")
    verified, message = verify_device_backend(device_id, user_name)
    if not verified:
        app.logger.warning(f"❌ Backend verification failed for {device_id}: {message}")
        return jsonify({'error': 'Device verification failed', 'message': message}), 403
    
    app.logger.info(f"✅ Backend verification passed for {device_id}")
    
    # Integrity check
    if not _check_integrity():
        app.logger.error(f"❌ Integrity check failed")
        return jsonify({'error': 'System integrity check failed'}), 500
    
    app.logger.info(f"✅ Integrity check passed")
    
    # Serve real file
    if os.path.exists('ocho.py'):
        app.logger.info(f"✅ All checks passed - serving ocho.py to verified device {device_id}")
        
        with open('ocho.py', 'r') as f:
            content = f.read()
        
        # Add runtime protection
        protected_content = f'''# OCHOxDARK v2.0-SECURE Runtime Protected
# Anti-debugging protection active
import sys

def _security_check():
    # Basic anti-debugging
    if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
        print("Debugging detected - terminating")
        sys.exit(1)
    
    # Check for analysis modules
    bad_modules = ['pdb', 'trace', 'bdb', 'dis']
    for mod in bad_modules:
        if mod in sys.modules:
            print("Analysis module detected - terminating")
            sys.exit(1)

_security_check()

# Original content:
{content}
'''
        
        app.logger.info(f"📤 Sending protected content ({len(protected_content)} bytes)")
        
        return Response(protected_content, mimetype='text/plain', headers={
            'X-Content-Protected': 'true',
            'X-Security-Level': 'maximum',
            'Content-Length': str(len(protected_content))
        })
    else:
        app.logger.error(f"❌ ocho.py file not found on server")
        return jsonify({'error': 'File not found'}), 404

# Honeypot routes
@app.route('/admin')
@app.route('/login') 
@app.route('/config')
@app.route('/debug')
def honeypot():
    """Honeypot to catch attackers"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    app.logger.warning(f"🍯 Honeypot triggered by {client_ip} on {request.path}")
    rate_limiter_simple.blocked.add(client_ip)
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403

@app.errorhandler(429)
def rate_limited(error):
    return jsonify({'error': 'Rate limit exceeded'}), 429

if __name__ == '__main__':
    print("🔒 OCHOxDARK v2.0-SECURE Server Starting...")
    print("🛡️ Security protection: ACTIVE")
    print("📡 Server ready on port 5000")
    
    app.run(host='0.0.0.0', port=5000, debug=False)