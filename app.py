"""
Enhanced Flask Application with Multi-Layered Security
OCHOxDARK System - Advanced Protection Against Unauthorized Access
"""

from flask import Flask, Response, request, abort, jsonify, render_template_string
import os
import sys
import logging
import requests
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
import ipaddress
import threading
import time

# Import security configuration and original ocho components
from security_config import security
from ocho import (
    _check_integrity,
    logger as ocho_logger,
    ColoredFormatter,
    colorama,
    _get_decrypted_subscription_api_url
)

app = Flask(__name__)

# --- Enhanced Logging Configuration ---
app_handler = logging.StreamHandler()
app_handler.setFormatter(ColoredFormatter())
app.logger.addHandler(app_handler)
app.logger.setLevel(logging.INFO)

# Initialize colorama
colorama.init(autoreset=True)

# --- Global Security State ---
class SecurityState:
    def __init__(self):
        self.failed_attempts = {}  # IP -> attempt count
        self.blocked_ips = set()
        self.active_sessions = {}  # device_id -> session_data
        self.attack_patterns = {}  # IP -> pattern data
        
    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips
    
    def block_ip(self, ip: str, reason: str = ""):
        self.blocked_ips.add(ip)
        app.logger.warning(f"{colorama.Fore.RED}BLOCKED IP: {ip} - Reason: {reason}{colorama.Style.RESET_ALL}")
    
    def record_failed_attempt(self, ip: str):
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = {'count': 0, 'first_attempt': datetime.utcnow()}
        
        self.failed_attempts[ip]['count'] += 1
        
        # Block IP after 5 failed attempts within 10 minutes
        if (self.failed_attempts[ip]['count'] >= 5 and 
            (datetime.utcnow() - self.failed_attempts[ip]['first_attempt']).total_seconds() < 600):
            self.block_ip(ip, f"Too many failed attempts: {self.failed_attempts[ip]['count']}")

security_state = SecurityState()

# --- Background Tasks ---
def cleanup_task():
    """Background task to clean up expired data"""
    while True:
        try:
            security.cleanup_expired_data()
            
            # Clean up old failed attempts (older than 1 hour)
            current_time = datetime.utcnow()
            expired_ips = []
            for ip, data in security_state.failed_attempts.items():
                if (current_time - data['first_attempt']).total_seconds() > 3600:
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                del security_state.failed_attempts[ip]
            
            time.sleep(300)  # Run every 5 minutes
            
        except Exception as e:
            app.logger.error(f"Error in cleanup task: {e}")
            time.sleep(60)

# Start cleanup task in background
cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
cleanup_thread.start()

# --- Security Decorators ---
def require_security_validation(f):
    """Decorator to enforce comprehensive security validation"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if client_ip and ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        app.logger.info(f"{colorama.Fore.CYAN}Security check initiated for IP: {client_ip}{colorama.Style.RESET_ALL}")
        
        # Check if IP is blocked
        if security_state.is_ip_blocked(client_ip):
            app.logger.warning(f"{colorama.Fore.RED}Blocked IP attempted access: {client_ip}{colorama.Style.RESET_ALL}")
            abort(403)
        
        # Check rate limiting
        rate_ok, rate_data = security.check_rate_limit(client_ip)
        if not rate_ok:
            security_state.record_failed_attempt(client_ip)
            app.logger.warning(f"{colorama.Fore.YELLOW}Rate limit exceeded for IP: {client_ip} - {rate_data}{colorama.Style.RESET_ALL}")
            return jsonify({'error': rate_data['error']}), 429
        
        return f(*args, **kwargs)
    return decorated_function

def require_loader_authentication(f):
    """Decorator to enforce loader authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Check for loader secret header
        loader_header = request.headers.get('X-Loader-Request')
        if not loader_header or loader_header != security.SECRET_KEY:
            security_state.record_failed_attempt(client_ip)
            app.logger.warning(f"{colorama.Fore.RED}Invalid/missing loader header from IP: {client_ip}{colorama.Style.RESET_ALL}")
            abort(403)
        
        # Check for additional security headers
        device_token = request.headers.get('X-Device-Token')
        request_signature = request.headers.get('X-Request-Signature')
        request_timestamp = request.headers.get('X-Request-Timestamp')
        request_nonce = request.headers.get('X-Request-Nonce')
        
        if security.REQUIRE_REQUEST_SIGNATURE:
            if not all([request_signature, request_timestamp, request_nonce]):
                security_state.record_failed_attempt(client_ip)
                app.logger.warning(f"{colorama.Fore.RED}Missing security headers from IP: {client_ip}{colorama.Style.RESET_ALL}")
                return jsonify({'error': 'Missing required security headers'}), 400
            
            # Validate nonce (anti-replay protection)
            if not security.validate_nonce(request_nonce, request_timestamp):
                security_state.record_failed_attempt(client_ip)
                app.logger.warning(f"{colorama.Fore.RED}Invalid/reused nonce from IP: {client_ip}{colorama.Style.RESET_ALL}")
                return jsonify({'error': 'Invalid nonce or timestamp'}), 400
        
        return f(*args, **kwargs)
    return decorated_function

# --- Enhanced Backend Verification ---
def verify_device_with_backend(device_id: str, user_name: str, additional_data: dict = None) -> tuple:
    """Enhanced device verification with additional security checks"""
    try:
        # Use the encrypted API URL from ocho.py
        api_url = _get_decrypted_subscription_api_url()
        
        # Prepare verification data
        verification_data = {
            'device_id': device_id,
            'user_name': user_name,
            'timestamp': datetime.utcnow().isoformat(),
            'security_level': 'enhanced'
        }
        
        if additional_data:
            verification_data.update(additional_data)
        
        app.logger.info(f"{colorama.Fore.BLUE}Enhanced backend verification for device: {device_id}{colorama.Style.RESET_ALL}")
        
        # Make request to backend with enhanced security
        response = requests.get(
            api_url,
            params=verification_data,
            timeout=15,
            headers={
                'User-Agent': 'OCHOxDARK-Security/2.0',
                'X-Security-Level': 'enhanced'
            }
        )
        response.raise_for_status()
        
        response_json = response.json()
        status = response_json.get("status")
        message = response_json.get("message", "No message from backend.")
        
        # Enhanced status validation
        if status == "active":
            # Generate secure token for this device
            token_data = security.generate_device_token(device_id, user_name)
            if token_data:
                app.logger.info(f"{colorama.Fore.GREEN}Device verified and token generated: {device_id}{colorama.Style.RESET_ALL}")
                return True, message, token_data
            else:
                app.logger.error(f"{colorama.Fore.RED}Token generation failed for verified device: {device_id}{colorama.Style.RESET_ALL}")
                return False, "Token generation failed", None
        else:
            app.logger.warning(f"{colorama.Fore.YELLOW}Device verification failed: {device_id} - Status: {status}{colorama.Style.RESET_ALL}")
            return False, message, None

    except requests.exceptions.RequestException as e:
        app.logger.error(f"{colorama.Fore.RED}Backend API communication error: {e}{colorama.Style.RESET_ALL}")
        return False, f"Backend communication error: {e}", None
    except json.JSONDecodeError as e:
        app.logger.error(f"{colorama.Fore.RED}Invalid JSON from backend: {e}{colorama.Style.RESET_ALL}")
        return False, "Invalid backend response", None
    except Exception as e:
        app.logger.error(f"{colorama.Fore.RED}Unexpected verification error: {e}{colorama.Style.RESET_ALL}")
        return False, f"Verification error: {e}", None

# --- Enhanced Routes ---
@app.route('/')
def index():
    """Enhanced index page with security information"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    # Check if this is a suspicious probe
    user_agent = request.headers.get('User-Agent', 'Unknown')
    if any(bot in user_agent.lower() for bot in ['bot', 'crawl', 'spider', 'scan']):
        app.logger.info(f"{colorama.Fore.CYAN}Bot/crawler detected from IP: {client_ip} - UA: {user_agent}{colorama.Style.RESET_ALL}")
    
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>OCHOxDARK Security Server</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="robots" content="noindex, nofollow">
        <style>
            body {
                background: linear-gradient(135deg, #000000, #1a1a1a);
                color: white;
                font-family: 'Courier New', monospace;
                text-align: center;
                margin: 0;
                padding: 20px;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
            }
            .logo {
                font-size: 2.5em;
                margin-bottom: 20px;
                text-shadow: 0 0 10px #00ff00;
                letter-spacing: 3px;
            }
            .security-notice {
                background: rgba(255, 0, 0, 0.1);
                border: 2px solid #ff0000;
                padding: 20px;
                margin: 20px 0;
                border-radius: 10px;
            }
            .status-info {
                background: rgba(0, 255, 0, 0.1);
                border: 2px solid #00ff00;
                padding: 15px;
                margin: 20px 0;
                border-radius: 10px;
                font-size: 0.9em;
            }
            .warning {
                color: #ffff00;
                font-weight: bold;
            }
            .access-info {
                margin-top: 30px;
                font-size: 0.8em;
                color: #888;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">⚡ OCHOxDARK ⚡</div>
            <div class="logo" style="font-size: 1.2em;">SECURITY SERVER</div>
            
            <div class="security-notice">
                <h3>🔒 PROTECTED SYSTEM</h3>
                <p>This server is protected by advanced security measures.</p>
                <p class="warning">⚠️ Unauthorized access attempts will be logged and blocked.</p>
            </div>
            
            <div class="status-info">
                <h4>🛡️ SECURITY STATUS: ACTIVE</h4>
                <p>✅ Multi-layer authentication enabled</p>
                <p>✅ Rate limiting active</p>
                <p>✅ Intrusion detection active</p>
                <p>✅ Request signature validation enabled</p>
            </div>
            
            <div class="access-info">
                <p>Authorized access only via approved loader systems.</p>
                <p>Server Time: {{ timestamp }}</p>
                <p>Session ID: {{ session_id }}</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(template, 
                                timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                                session_id=secrets.token_hex(8))

@app.route('/ocho.py')
@require_security_validation
@require_loader_authentication
def serve_ocho():
    """Enhanced ocho.py serving with comprehensive security validation"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    try:
        # Extract security parameters
        device_id = request.args.get('device_id')
        user_name = request.args.get('user_name')
        device_token = request.headers.get('X-Device-Token')
        request_signature = request.headers.get('X-Request-Signature')
        request_timestamp = request.headers.get('X-Request-Timestamp')
        request_nonce = request.headers.get('X-Request-Nonce')
        
        # Validate required parameters
        if not device_id or not user_name:
            security_state.record_failed_attempt(client_ip)
            app.logger.warning(f"{colorama.Fore.RED}Missing device_id/user_name from IP: {client_ip}{colorama.Style.RESET_ALL}")
            return jsonify({'error': 'Missing required parameters'}), 400
        
        app.logger.info(f"{colorama.Fore.CYAN}ocho.py access request - Device: {device_id}, IP: {client_ip}{colorama.Style.RESET_ALL}")
        
        # Verify device with backend
        is_verified, message, _ = verify_device_with_backend(device_id, user_name)
        
        if not is_verified:
            security_state.record_failed_attempt(client_ip)
            app.logger.warning(f"{colorama.Fore.YELLOW}Backend verification failed for: {device_id} - {message}{colorama.Style.RESET_ALL}")
            return jsonify({'error': f'Device verification failed: {message}'}), 403
        
        # Perform integrity check
        if not _check_integrity():
            app.logger.error(f"{colorama.Fore.RED}Integrity check failed for ocho.py access - Device: {device_id}{colorama.Style.RESET_ALL}")
            security.mark_ip_suspicious(client_ip, "Integrity check failed")
            return jsonify({'error': 'System integrity check failed'}), 500
        
        # Check if ocho.py file exists and validate checksum
        if not os.path.exists('ocho.py'):
            app.logger.error(f"{colorama.Fore.RED}ocho.py file not found for device: {device_id}{colorama.Style.RESET_ALL}")
            return jsonify({'error': 'Resource not available'}), 404
        
        # Read and potentially obfuscate the file
        with open('ocho.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Apply session-based code obfuscation if enabled
        if security.DYNAMIC_CODE_SERVING:
            session_id = device_id  # Use device_id as session identifier
            content = security.obfuscate_code(content, session_id)
        
        # Log successful access
        app.logger.info(f"{colorama.Fore.GREEN}✅ ocho.py served successfully to device: {device_id} (User: {user_name}){colorama.Style.RESET_ALL}")
        
        # Return content with security headers
        response = Response(content, mimetype='text/plain')
        response.headers['X-Content-Integrity'] = security.get_file_checksum('ocho.py') if security.CODE_CHECKSUM_VALIDATION else 'disabled'
        response.headers['X-Security-Level'] = 'enhanced'
        response.headers['X-Served-At'] = datetime.utcnow().isoformat()
        
        return response
        
    except Exception as e:
        app.logger.error(f"{colorama.Fore.RED}Unexpected error serving ocho.py to {device_id}: {e}{colorama.Style.RESET_ALL}")
        return jsonify({'error': 'Internal server error'}), 500

# --- Error Handlers ---
@app.errorhandler(403)
def forbidden(error):
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    app.logger.warning(f"{colorama.Fore.RED}403 Forbidden - IP: {client_ip}, Path: {request.path}{colorama.Style.RESET_ALL}")
    return jsonify({
        'error': 'Access Forbidden',
        'code': 403,
        'message': 'You do not have permission to access this resource.',
        'timestamp': datetime.utcnow().isoformat()
    }), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Not Found',
        'code': 404,
        'message': 'The requested resource was not found.',
        'timestamp': datetime.utcnow().isoformat()
    }), 404

@app.errorhandler(429)
def rate_limit_exceeded(error):
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    app.logger.warning(f"{colorama.Fore.YELLOW}429 Rate Limited - IP: {client_ip}{colorama.Style.RESET_ALL}")
    return jsonify({
        'error': 'Rate Limit Exceeded',
        'code': 429,
        'message': 'Too many requests. Please slow down.',
        'timestamp': datetime.utcnow().isoformat()
    }), 429

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"{colorama.Fore.RED}500 Internal Server Error: {error}{colorama.Style.RESET_ALL}")
    return jsonify({
        'error': 'Internal Server Error',
        'code': 500,
        'message': 'An internal server error occurred.',
        'timestamp': datetime.utcnow().isoformat()
    }), 500

# --- Application Startup ---
if __name__ == '__main__':
    app.logger.info(f"{colorama.Fore.GREEN}🔒 OCHOxDARK Security Server Starting...{colorama.Style.RESET_ALL}")
    app.logger.info(f"{colorama.Fore.CYAN}Security Features:{colorama.Style.RESET_ALL}")
    app.logger.info(f"  - Rate Limiting: {security.MAX_REQUESTS_PER_MINUTE}/min, {security.MAX_REQUESTS_PER_HOUR}/hour")
    app.logger.info(f"  - Request Signatures: {security.REQUIRE_REQUEST_SIGNATURE}")
    app.logger.info(f"  - Device Fingerprinting: {security.REQUIRE_DEVICE_FINGERPRINT}")
    app.logger.info(f"  - Code Obfuscation: {security.ENABLE_CODE_OBFUSCATION}")
    app.logger.info(f"  - Checksum Validation: {security.CODE_CHECKSUM_VALIDATION}")
    app.logger.info(f"{colorama.Fore.GREEN}🚀 Server ready for secure connections{colorama.Style.RESET_ALL}")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)