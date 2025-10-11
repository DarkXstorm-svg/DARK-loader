"""
DARKxStorms Security Server
Multi-layered protection system for ocho.py
Features: JWT Auth, Device Fingerprinting, Code Encryption, Anti-Tampering
"""

import os
import time
import hashlib
import secrets
import base64
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, abort
from functools import wraps
import jwt
import zlib
import logging
from cryptography.fernet import Fernet
import threading
from collections import defaultdict, deque
import ipaddress
import socket

# Import our security modules
from auth_manager import AuthManager
from code_protector import CodeProtector
from device_manager import DeviceManager
from security_monitor import SecurityMonitor

# Initialize Flask app with security configurations
app = Flask(__name__)

# Security Configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    JWT_SECRET_KEY=os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32)),
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=2),
    MAX_REQUESTS_PER_HOUR=50,
    MAX_FAILED_ATTEMPTS=5,
    LOCKOUT_DURATION=300  # 5 minutes
)

# Initialize security components
auth_manager = AuthManager(app.config)
code_protector = CodeProtector()
device_manager = DeviceManager()
security_monitor = SecurityMonitor()

# Rate limiting storage
request_counts = defaultdict(lambda: deque())
failed_attempts = defaultdict(int)
lockout_times = {}

# Security logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def log_security_event(event_type, details, ip_address, device_id=None):
    """Log security events with comprehensive details"""
    event = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'ip_address': ip_address,
        'device_id': device_id,
        'details': details,
        'user_agent': request.headers.get('User-Agent', 'Unknown')
    }
    logger.warning(f"SECURITY EVENT: {json.dumps(event)}")
    security_monitor.log_event(event)

def get_client_ip():
    """Get real client IP address"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0]
    return request.remote_addr

def is_rate_limited(ip_address):
    """Check if IP is rate limited"""
    current_time = time.time()
    hour_ago = current_time - 3600
    
    # Clean old entries
    while request_counts[ip_address] and request_counts[ip_address][0] < hour_ago:
        request_counts[ip_address].popleft()
    
    # Check rate limit
    if len(request_counts[ip_address]) >= app.config['MAX_REQUESTS_PER_HOUR']:
        return True
    
    request_counts[ip_address].append(current_time)
    return False

def is_locked_out(ip_address):
    """Check if IP is locked out due to failed attempts"""
    if ip_address in lockout_times:
        if time.time() - lockout_times[ip_address] < app.config['LOCKOUT_DURATION']:
            return True
        else:
            del lockout_times[ip_address]
            failed_attempts[ip_address] = 0
    return False

def record_failed_attempt(ip_address):
    """Record failed authentication attempt"""
    failed_attempts[ip_address] += 1
    if failed_attempts[ip_address] >= app.config['MAX_FAILED_ATTEMPTS']:
        lockout_times[ip_address] = time.time()
        log_security_event(
            'IP_LOCKOUT', 
            f'IP locked out after {failed_attempts[ip_address]} failed attempts',
            ip_address
        )

def validate_request_headers():
    """Validate required security headers"""
    required_headers = ['X-Loader-Request', 'User-Agent']
    for header in required_headers:
        if not request.headers.get(header):
            return False
    
    # Validate specific header values
    loader_request = request.headers.get('X-Loader-Request')
    if loader_request != 'KUPAL':
        return False
    
    return True

def security_check():
    """Comprehensive security check decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip_address = get_client_ip()
            
            # Rate limiting check
            if is_rate_limited(ip_address):
                log_security_event('RATE_LIMIT_EXCEEDED', 'Too many requests', ip_address)
                abort(429, 'Rate limit exceeded')
            
            # Lockout check
            if is_locked_out(ip_address):
                log_security_event('ACCESS_BLOCKED', 'IP locked out', ip_address)
                abort(403, 'Access temporarily blocked')
            
            # Header validation
            if not validate_request_headers():
                record_failed_attempt(ip_address)
                log_security_event('INVALID_HEADERS', 'Missing or invalid headers', ip_address)
                abort(400, 'Invalid request headers')
            
            # Anti-fingerprinting check
            if security_monitor.is_suspicious_request(request, ip_address):
                record_failed_attempt(ip_address)
                log_security_event('SUSPICIOUS_REQUEST', 'Suspicious request pattern detected', ip_address)
                abort(403, 'Suspicious activity detected')
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

@app.route('/ocho.py', methods=['GET'])
@security_check()
def serve_protected_code():
    """Serve the protected ocho.py with multiple security layers"""
    ip_address = get_client_ip()
    device_id = request.args.get('device_id')
    user_name = request.args.get('user_name')
    
    # Validate required parameters
    if not device_id or not user_name:
        record_failed_attempt(ip_address)
        log_security_event('MISSING_PARAMETERS', 'Missing device_id or user_name', ip_address)
        abort(400, 'Missing required parameters')
    
    # Authenticate and authorize the request
    try:
        auth_result = auth_manager.authenticate_request(device_id, user_name, ip_address)
        if not auth_result['success']:
            record_failed_attempt(ip_address)
            log_security_event('AUTH_FAILED', auth_result['message'], ip_address, device_id)
            abort(403, auth_result['message'])
        
        # Device verification
        device_verification = device_manager.verify_device(device_id, user_name, request)
        if not device_verification['valid']:
            record_failed_attempt(ip_address)
            log_security_event('DEVICE_VERIFICATION_FAILED', device_verification['reason'], ip_address, device_id)
            abort(403, 'Device verification failed')
        
        # Generate JWT token for this session
        token_payload = {
            'device_id': device_id,
            'user_name': user_name,
            'ip_address': ip_address,
            'issued_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']).isoformat(),
            'device_fingerprint': device_verification['fingerprint']
        }
        
        access_token = jwt.encode(
            token_payload, 
            app.config['JWT_SECRET_KEY'], 
            algorithm='HS256'
        )
        
        # Get and protect the source code
        protected_code = code_protector.get_protected_code(device_id, user_name, access_token)
        
        # Log successful access
        log_security_event(
            'CODE_ACCESS_GRANTED', 
            f'Protected code served to verified device',
            ip_address, 
            device_id
        )
        
        # Reset failed attempts on successful auth
        if ip_address in failed_attempts:
            failed_attempts[ip_address] = 0
        
        # Return the protected code with additional security headers
        response = app.make_response(protected_code)
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Session-Token'] = access_token
        
        return response
        
    except Exception as e:
        record_failed_attempt(ip_address)
        log_security_event('SYSTEM_ERROR', f'Unexpected error: {str(e)}', ip_address, device_id)
        logger.error(f"Error serving protected code: {str(e)}")
        abort(500, 'Internal security error')

@app.route('/verify-session', methods=['POST'])
@security_check()
def verify_session():
    """Verify active session token"""
    ip_address = get_client_ip()
    
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            abort(400, 'Missing session token')
        
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        
        # Verify IP consistency
        if payload.get('ip_address') != ip_address:
            log_security_event('IP_MISMATCH', 'Session IP mismatch detected', ip_address)
            abort(403, 'Session security violation')
        
        # Check if session is still valid
        expires_at = datetime.fromisoformat(payload['expires_at'])
        if datetime.utcnow() > expires_at:
            abort(401, 'Session expired')
        
        return jsonify({
            'valid': True,
            'device_id': payload.get('device_id'),
            'expires_at': payload.get('expires_at')
        })
        
    except jwt.ExpiredSignatureError:
        abort(401, 'Token expired')
    except jwt.InvalidTokenError:
        log_security_event('INVALID_TOKEN', 'Invalid session token provided', ip_address)
        abort(401, 'Invalid token')

@app.route('/security-status', methods=['GET'])
@security_check()
def security_status():
    """Get security status and monitoring data"""
    # This endpoint could be used for debugging or monitoring
    # In production, this should be heavily restricted or removed
    return jsonify({
        'active_sessions': len(auth_manager.active_sessions),
        'blocked_ips': len(lockout_times),
        'total_requests': sum(len(deque_obj) for deque_obj in request_counts.values()),
        'security_level': 'MAXIMUM'
    })

@app.errorhandler(400)
def bad_request(error):
    log_security_event('BAD_REQUEST', str(error), get_client_ip())
    return jsonify({'error': 'Bad request', 'message': str(error)}), 400

@app.errorhandler(401)
def unauthorized(error):
    log_security_event('UNAUTHORIZED', str(error), get_client_ip())
    return jsonify({'error': 'Unauthorized', 'message': str(error)}), 401

@app.errorhandler(403)
def forbidden(error):
    log_security_event('FORBIDDEN', str(error), get_client_ip())
    return jsonify({'error': 'Forbidden', 'message': str(error)}), 403

@app.errorhandler(429)
def rate_limit_exceeded(error):
    log_security_event('RATE_LIMIT', str(error), get_client_ip())
    return jsonify({'error': 'Rate limit exceeded', 'message': 'Too many requests'}), 429

@app.errorhandler(500)
def internal_error(error):
    log_security_event('INTERNAL_ERROR', str(error), get_client_ip())
    return jsonify({'error': 'Internal server error', 'message': 'Security system error'}), 500

if __name__ == '__main__':
    # Security startup checks
    logger.info("Starting DARKxStorms Security Server...")
    logger.info("Initializing security components...")
    
    # Initialize security components
    auth_manager.initialize()
    code_protector.initialize()
    device_manager.initialize()
    security_monitor.initialize()
    
    logger.info("Security server ready - Maximum protection enabled")
    
    # Run in production mode with security hardening
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 8000)),
        debug=False,
        threaded=True,
        ssl_context='adhoc' if os.environ.get('SSL_ENABLED', 'False') == 'True' else None
    )