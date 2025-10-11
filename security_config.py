"""
Advanced Security Configuration Module
Centralized security settings and utilities for the OCHOxDARK system
"""

import os
import hmac
import hashlib
import secrets
import time
import json
import base64
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import platform
import uuid
import ipaddress
from typing import Dict, List, Optional, Tuple
import logging

# Initialize logging
logger = logging.getLogger(__name__)

class SecurityConfig:
    """Centralized security configuration and utilities"""
    
    def __init__(self):
        # Core security settings
        self.SECRET_KEY = os.environ.get("LOADER_SECRET_KEY", "KUPAL")
        self.MASTER_KEY = os.environ.get("MASTER_KEY", self._generate_master_key())
        self.TOKEN_EXPIRY_MINUTES = 15  # Dynamic token expiration
        self.MAX_REQUESTS_PER_MINUTE = 5  # Rate limiting
        self.MAX_REQUESTS_PER_HOUR = 30
        self.NONCE_EXPIRY_SECONDS = 300  # Anti-replay protection
        
        # Advanced security features
        self.REQUIRE_DEVICE_FINGERPRINT = True
        self.REQUIRE_REQUEST_SIGNATURE = True
        self.ENABLE_GEOGRAPHIC_RESTRICTIONS = False
        self.ALLOWED_COUNTRIES = ['US', 'CA', 'GB', 'AU']  # ISO country codes
        
        # Code obfuscation settings
        self.ENABLE_CODE_OBFUSCATION = True
        self.CODE_CHECKSUM_VALIDATION = True
        self.DYNAMIC_CODE_SERVING = True
        
        # Initialize encryption
        self.fernet = self._initialize_encryption()
        
        # In-memory stores (in production, use Redis or database)
        self.active_tokens = {}  # device_id: token_data
        self.rate_limits = {}    # ip_address: request_data
        self.used_nonces = set() # For anti-replay protection
        self.suspicious_ips = set()  # Blocked IPs
        
    def _generate_master_key(self) -> str:
        """Generate a secure master key"""
        return base64.urlsafe_b64encode(os.urandom(32)).decode()
    
    def _initialize_encryption(self) -> Fernet:
        """Initialize Fernet encryption with derived key"""
        password = self.MASTER_KEY.encode()
        salt = b'ocho_dark_salt_2024'  # In production, use random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return Fernet(key)
    
    def generate_device_token(self, device_id: str, user_name: str, 
                            device_fingerprint: str = None) -> Dict:
        """Generate a secure, time-limited token for device access"""
        try:
            current_time = datetime.utcnow()
            expiry_time = current_time + timedelta(minutes=self.TOKEN_EXPIRY_MINUTES)
            
            token_data = {
                'device_id': device_id,
                'user_name': user_name,
                'device_fingerprint': device_fingerprint,
                'issued_at': current_time.isoformat(),
                'expires_at': expiry_time.isoformat(),
                'nonce': secrets.token_hex(16),
                'session_id': secrets.token_hex(8)
            }
            
            # Encrypt the token data
            encrypted_token = self.fernet.encrypt(
                json.dumps(token_data).encode()
            ).decode()
            
            # Store in active tokens
            self.active_tokens[device_id] = {
                'token': encrypted_token,
                'expires_at': expiry_time,
                'user_name': user_name
            }
            
            logger.info(f"Generated secure token for device: {device_id}")
            
            return {
                'token': encrypted_token,
                'expires_at': expiry_time.isoformat(),
                'session_id': token_data['session_id']
            }
            
        except Exception as e:
            logger.error(f"Error generating device token: {e}")
            return None
    
    def validate_device_token(self, device_id: str, token: str) -> Tuple[bool, Dict]:
        """Validate device token and extract data"""
        try:
            # Check if token exists in active tokens
            if device_id not in self.active_tokens:
                return False, {'error': 'Token not found'}
            
            stored_token = self.active_tokens[device_id]
            
            # Check if token matches
            if stored_token['token'] != token:
                return False, {'error': 'Invalid token'}
            
            # Check expiration
            if datetime.utcnow() > stored_token['expires_at']:
                del self.active_tokens[device_id]
                return False, {'error': 'Token expired'}
            
            # Decrypt and validate token data
            decrypted_data = json.loads(
                self.fernet.decrypt(token.encode()).decode()
            )
            
            return True, decrypted_data
            
        except Exception as e:
            logger.error(f"Error validating token: {e}")
            return False, {'error': 'Token validation failed'}
    
    def generate_request_signature(self, device_id: str, timestamp: str, 
                                 nonce: str, data: str = "") -> str:
        """Generate HMAC signature for request validation"""
        try:
            message = f"{device_id}:{timestamp}:{nonce}:{data}"
            signature = hmac.new(
                self.SECRET_KEY.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            return signature
        except Exception as e:
            logger.error(f"Error generating signature: {e}")
            return ""
    
    def validate_request_signature(self, device_id: str, timestamp: str, 
                                 nonce: str, signature: str, data: str = "") -> bool:
        """Validate request signature"""
        try:
            expected_signature = self.generate_request_signature(
                device_id, timestamp, nonce, data
            )
            return hmac.compare_digest(signature, expected_signature)
        except Exception as e:
            logger.error(f"Error validating signature: {e}")
            return False
    
    def check_rate_limit(self, ip_address: str) -> Tuple[bool, Dict]:
        """Check if IP address is within rate limits"""
        try:
            current_time = datetime.utcnow()
            
            if ip_address not in self.rate_limits:
                self.rate_limits[ip_address] = {
                    'requests_this_minute': 0,
                    'requests_this_hour': 0,
                    'last_minute': current_time.minute,
                    'last_hour': current_time.hour,
                    'first_request_time': current_time
                }
            
            rate_data = self.rate_limits[ip_address]
            
            # Reset minute counter
            if current_time.minute != rate_data['last_minute']:
                rate_data['requests_this_minute'] = 0
                rate_data['last_minute'] = current_time.minute
            
            # Reset hour counter
            if current_time.hour != rate_data['last_hour']:
                rate_data['requests_this_hour'] = 0
                rate_data['last_hour'] = current_time.hour
            
            # Check limits
            if rate_data['requests_this_minute'] >= self.MAX_REQUESTS_PER_MINUTE:
                return False, {'error': 'Rate limit exceeded (per minute)'}
            
            if rate_data['requests_this_hour'] >= self.MAX_REQUESTS_PER_HOUR:
                return False, {'error': 'Rate limit exceeded (per hour)'}
            
            # Increment counters
            rate_data['requests_this_minute'] += 1
            rate_data['requests_this_hour'] += 1
            
            return True, {'requests_remaining': 
                         self.MAX_REQUESTS_PER_MINUTE - rate_data['requests_this_minute']}
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return False, {'error': 'Rate limit check failed'}
    
    def validate_nonce(self, nonce: str, timestamp: str) -> bool:
        """Validate nonce to prevent replay attacks"""
        try:
            # Check if nonce was already used
            if nonce in self.used_nonces:
                return False
            
            # Check timestamp is recent (within nonce expiry)
            request_time = datetime.fromisoformat(timestamp)
            current_time = datetime.utcnow()
            
            if (current_time - request_time).total_seconds() > self.NONCE_EXPIRY_SECONDS:
                return False
            
            # Mark nonce as used
            self.used_nonces.add(nonce)
            
            # Clean up old nonces (simple cleanup)
            if len(self.used_nonces) > 10000:  # Arbitrary limit
                self.used_nonces.clear()
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating nonce: {e}")
            return False
    
    def generate_device_fingerprint(self) -> str:
        """Generate device fingerprint for additional validation"""
        try:
            system_info = [
                platform.system(),
                platform.release(),
                platform.version(),
                platform.machine(),
                platform.processor()
            ]
            
            # Get network interface MAC addresses (if available)
            try:
                mac_addresses = []
                import psutil
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == psutil.AF_LINK:
                            mac_addresses.append(addr.address)
                system_info.extend(sorted(mac_addresses))
            except ImportError:
                pass  # psutil not available
            
            fingerprint_string = "|".join(system_info)
            fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
            
            return fingerprint_hash[:16]  # Use first 16 chars
            
        except Exception as e:
            logger.error(f"Error generating device fingerprint: {e}")
            return "unknown_device"
    
    def is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is marked as suspicious"""
        return ip_address in self.suspicious_ips
    
    def mark_ip_suspicious(self, ip_address: str, reason: str = ""):
        """Mark IP address as suspicious"""
        self.suspicious_ips.add(ip_address)
        logger.warning(f"Marked IP {ip_address} as suspicious: {reason}")
    
    def get_file_checksum(self, filepath: str) -> str:
        """Generate file checksum for integrity verification"""
        try:
            with open(filepath, 'rb') as f:
                file_content = f.read()
                return hashlib.sha256(file_content).hexdigest()
        except Exception as e:
            logger.error(f"Error generating checksum for {filepath}: {e}")
            return ""
    
    def obfuscate_code(self, code: str, session_id: str) -> str:
        """Simple code obfuscation based on session"""
        if not self.ENABLE_CODE_OBFUSCATION:
            return code
        
        try:
            # Simple obfuscation: add session-specific comments
            session_hash = hashlib.md5(session_id.encode()).hexdigest()[:8]
            obfuscated_lines = []
            
            for i, line in enumerate(code.split('\n')):
                if i % 10 == 0 and line.strip():  # Every 10th line
                    comment = f"# Session: {session_hash}_{i}"
                    obfuscated_lines.append(comment)
                obfuscated_lines.append(line)
            
            return '\n'.join(obfuscated_lines)
            
        except Exception as e:
            logger.error(f"Error obfuscating code: {e}")
            return code
    
    def cleanup_expired_data(self):
        """Clean up expired tokens and old data"""
        try:
            current_time = datetime.utcnow()
            
            # Clean expired tokens
            expired_devices = []
            for device_id, token_data in self.active_tokens.items():
                if current_time > token_data['expires_at']:
                    expired_devices.append(device_id)
            
            for device_id in expired_devices:
                del self.active_tokens[device_id]
            
            logger.info(f"Cleaned up {len(expired_devices)} expired tokens")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

# Global security instance
security = SecurityConfig()