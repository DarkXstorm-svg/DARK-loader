"""
Authentication Manager
JWT-based authentication with device binding and subscription verification
"""

import time
import hashlib
import secrets
import requests
import json
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

class AuthManager:
    def __init__(self, config):
        self.config = config
        self.active_sessions = {}
        self.device_sessions = defaultdict(list)
        self.subscription_cache = {}
        self.cache_expiry = 300  # 5 minutes cache
        
        # Subscription API configuration
        self.subscription_api = "https://darkxdeath.onrender.com/api.php"
        
    def initialize(self):
        """Initialize authentication manager"""
        logger.info("Authentication Manager initialized")
        
    def _generate_session_id(self):
        """Generate secure session ID"""
        return secrets.token_urlsafe(32)
    
    def _hash_device_info(self, device_id, user_name):
        """Create hash of device information for verification"""
        device_string = f"{device_id}_{user_name}_{int(time.time() // 3600)}"  # Hour-based hash
        return hashlib.sha256(device_string.encode()).hexdigest()
    
    def _check_subscription_status(self, device_id, user_name):
        """Check subscription status with caching"""
        cache_key = f"{device_id}_{user_name}"
        current_time = time.time()
        
        # Check cache first
        if cache_key in self.subscription_cache:
            cache_entry = self.subscription_cache[cache_key]
            if current_time - cache_entry['timestamp'] < self.cache_expiry:
                return cache_entry['data']
        
        # Make API request
        try:
            url = f"{self.subscription_api}?device_id={device_id}&user_name={user_name}&loader_check=true"
            headers = {
                'User-Agent': 'DARKxStorms-Security-Server/1.0',
                'Accept': 'application/json',
                'X-Security-Check': 'loader_verification'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            response.raise_for_status()
            
            data = response.json()
            
            # Cache the result
            self.subscription_cache[cache_key] = {
                'data': data,
                'timestamp': current_time
            }
            
            return data
            
        except requests.RequestException as e:
            logger.error(f"Subscription API error for {device_id}: {e}")
            return {"status": "error", "message": "Subscription verification failed"}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response for {device_id}: {e}")
            return {"status": "error", "message": "Invalid subscription response"}
    
    def _validate_device_format(self, device_id, user_name):
        """Validate device ID and user name format"""
        if not device_id or not user_name:
            return False
        
        # Check device_id format: username_4chars
        if not device_id.startswith(f"{user_name}_"):
            return False
        
        device_suffix = device_id[len(user_name) + 1:]
        if len(device_suffix) != 4:
            return False
        
        # Validate characters (alphanumeric only)
        if not user_name.isalnum() or not device_suffix.isalnum():
            return False
        
        # Length constraints
        if not (3 <= len(user_name) <= 20):
            return False
        
        return True
    
    def _check_device_limits(self, device_id, user_name, ip_address):
        """Check device and IP limits"""
        # Clean old sessions
        current_time = time.time()
        for session_id in list(self.active_sessions.keys()):
            session = self.active_sessions[session_id]
            if current_time - session['created_at'] > 7200:  # 2 hours
                del self.active_sessions[session_id]
        
        # Check concurrent sessions per device
        device_key = f"{device_id}_{user_name}"
        active_device_sessions = [
            s for s in self.active_sessions.values() 
            if s['device_id'] == device_id and s['user_name'] == user_name
        ]
        
        if len(active_device_sessions) >= 3:  # Max 3 concurrent sessions
            return False, "Too many active sessions for this device"
        
        # Check IP-based limits
        ip_sessions = [
            s for s in self.active_sessions.values() 
            if s['ip_address'] == ip_address
        ]
        
        if len(ip_sessions) >= 5:  # Max 5 sessions per IP
            return False, "Too many active sessions from this IP"
        
        return True, "OK"
    
    def authenticate_request(self, device_id, user_name, ip_address):
        """
        Authenticate loader request with multiple verification layers
        """
        try:
            # Step 1: Format validation
            if not self._validate_device_format(device_id, user_name):
                return {
                    'success': False,
                    'message': 'Invalid device ID or username format',
                    'error_code': 'FORMAT_INVALID'
                }
            
            # Step 2: Device and IP limits
            limit_check, limit_message = self._check_device_limits(device_id, user_name, ip_address)
            if not limit_check:
                return {
                    'success': False,
                    'message': limit_message,
                    'error_code': 'LIMIT_EXCEEDED'
                }
            
            # Step 3: Subscription verification
            subscription_response = self._check_subscription_status(device_id, user_name)
            status = subscription_response.get("status")
            
            if status == "active":
                # Create new session
                session_id = self._generate_session_id()
                session_data = {
                    'session_id': session_id,
                    'device_id': device_id,
                    'user_name': user_name,
                    'ip_address': ip_address,
                    'created_at': time.time(),
                    'last_activity': time.time(),
                    'device_hash': self._hash_device_info(device_id, user_name),
                    'subscription_status': status
                }
                
                self.active_sessions[session_id] = session_data
                
                logger.info(f"Authentication successful for {device_id} from {ip_address}")
                
                return {
                    'success': True,
                    'message': 'Authentication successful',
                    'session_id': session_id,
                    'subscription_status': status
                }
            
            elif status in ["pending", "registered_pending"]:
                return {
                    'success': False,
                    'message': 'Subscription pending approval',
                    'error_code': 'SUBSCRIPTION_PENDING',
                    'device_id': device_id
                }
            
            elif status == "expired":
                return {
                    'success': False,
                    'message': 'Subscription expired',
                    'error_code': 'SUBSCRIPTION_EXPIRED',
                    'device_id': device_id
                }
            
            else:
                return {
                    'success': False,
                    'message': f'Subscription status unknown: {status}',
                    'error_code': 'SUBSCRIPTION_ERROR',
                    'device_id': device_id
                }
                
        except Exception as e:
            logger.error(f"Authentication error for {device_id}: {e}")
            return {
                'success': False,
                'message': 'Authentication system error',
                'error_code': 'SYSTEM_ERROR'
            }
    
    def validate_session(self, session_id):
        """Validate existing session"""
        if session_id not in self.active_sessions:
            return {'valid': False, 'reason': 'Session not found'}
        
        session = self.active_sessions[session_id]
        current_time = time.time()
        
        # Check session expiry (2 hours)
        if current_time - session['created_at'] > 7200:
            del self.active_sessions[session_id]
            return {'valid': False, 'reason': 'Session expired'}
        
        # Update last activity
        session['last_activity'] = current_time
        
        return {
            'valid': True,
            'session': session
        }
    
    def revoke_session(self, session_id):
        """Revoke specific session"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            logger.info(f"Session {session_id} revoked")
            return True
        return False
    
    def revoke_device_sessions(self, device_id, user_name):
        """Revoke all sessions for a specific device"""
        sessions_to_remove = []
        
        for session_id, session in self.active_sessions.items():
            if session['device_id'] == device_id and session['user_name'] == user_name:
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            del self.active_sessions[session_id]
        
        logger.info(f"Revoked {len(sessions_to_remove)} sessions for device {device_id}")
        return len(sessions_to_remove)
    
    def cleanup_expired_sessions(self):
        """Cleanup expired sessions"""
        current_time = time.time()
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            if current_time - session['created_at'] > 7200:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.active_sessions[session_id]
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
    
    def get_session_info(self, session_id):
        """Get session information"""
        session = self.active_sessions.get(session_id)
        if session:
            return {
                'device_id': session['device_id'],
                'user_name': session['user_name'],
                'ip_address': session['ip_address'],
                'created_at': datetime.fromtimestamp(session['created_at']).isoformat(),
                'last_activity': datetime.fromtimestamp(session['last_activity']).isoformat(),
                'subscription_status': session['subscription_status']
            }
        return None
    
    def get_active_sessions_count(self):
        """Get count of active sessions"""
        self.cleanup_expired_sessions()
        return len(self.active_sessions)
    
    def is_device_authenticated(self, device_id, user_name):
        """Check if device has active authenticated session"""
        for session in self.active_sessions.values():
            if session['device_id'] == device_id and session['user_name'] == user_name:
                return True
        return False