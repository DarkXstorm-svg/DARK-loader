"""
Device Management and Fingerprinting System
Advanced device verification and tracking
"""

import hashlib
import time
import json
import re
from collections import defaultdict
import logging
from user_agents import parse

logger = logging.getLogger(__name__)

class DeviceManager:
    def __init__(self):
        self.device_registry = {}
        self.device_fingerprints = {}
        self.suspicious_devices = set()
        self.device_access_history = defaultdict(list)
        
    def initialize(self):
        """Initialize device manager"""
        logger.info("Device Manager initialized - Advanced fingerprinting enabled")
        
    def _generate_request_fingerprint(self, request):
        """Generate comprehensive request fingerprint"""
        try:
            # Extract request characteristics
            user_agent = request.headers.get('User-Agent', 'Unknown')
            accept_language = request.headers.get('Accept-Language', '')
            accept_encoding = request.headers.get('Accept-Encoding', '')
            connection = request.headers.get('Connection', '')
            
            # Parse user agent
            parsed_ua = parse(user_agent)
            browser_info = f"{parsed_ua.browser.family}_{parsed_ua.browser.version_string}"
            os_info = f"{parsed_ua.os.family}_{parsed_ua.os.version_string}"
            
            # Create fingerprint components
            fingerprint_data = {
                'user_agent_hash': hashlib.sha256(user_agent.encode()).hexdigest()[:16],
                'browser': browser_info,
                'os': os_info,
                'accept_language': accept_language,
                'accept_encoding': accept_encoding,
                'connection': connection,
                'headers_count': len(request.headers),
                'headers_order': list(request.headers.keys())[:10]  # First 10 headers
            }
            
            # Generate composite fingerprint
            fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
            fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
            
            return fingerprint_hash, fingerprint_data
            
        except Exception as e:
            logger.warning(f"Error generating request fingerprint: {e}")
            return "unknown_fingerprint", {}
    
    def _validate_user_agent(self, user_agent):
        """Validate user agent authenticity"""
        if not user_agent or user_agent == 'Unknown':
            return False, "Missing user agent"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'bot|crawler|spider|scraper',
            r'curl|wget|python|java|go-http',
            r'automated|script|tool',
            r'^$',  # Empty
        ]
        
        user_agent_lower = user_agent.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, user_agent_lower):
                return False, f"Suspicious user agent pattern: {pattern}"
        
        # Validate expected user agent format for loader
        expected_patterns = [
            r'Mozilla/5\.0.*Chrome.*Safari',
            r'DARKxStorms-Loader',
        ]
        
        is_valid = any(re.search(pattern, user_agent) for pattern in expected_patterns)
        if not is_valid:
            return False, "User agent doesn't match expected patterns"
        
        return True, "Valid user agent"
    
    def _check_request_timing(self, device_id, ip_address):
        """Check request timing patterns for suspicious behavior"""
        current_time = time.time()
        device_key = f"{device_id}_{ip_address}"
        
        # Get recent access history
        recent_accesses = [
            access_time for access_time in self.device_access_history[device_key]
            if current_time - access_time < 3600  # Last hour
        ]
        
        # Clean old entries
        self.device_access_history[device_key] = [
            access_time for access_time in self.device_access_history[device_key]
            if current_time - access_time < 86400  # Last 24 hours
        ]
        
        # Check for suspicious patterns
        if len(recent_accesses) >= 10:  # Too many requests in an hour
            return False, "Too many requests in short time"
        
        # Check for very frequent requests (less than 30 seconds apart)
        if recent_accesses:
            last_access = max(recent_accesses)
            if current_time - last_access < 30:
                return False, "Requests too frequent"
        
        # Record current access
        self.device_access_history[device_key].append(current_time)
        
        return True, "Timing check passed"
    
    def _analyze_device_consistency(self, device_id, user_name, fingerprint_data):
        """Analyze device fingerprint consistency"""
        device_key = f"{device_id}_{user_name}"
        
        if device_key in self.device_fingerprints:
            stored_fingerprint = self.device_fingerprints[device_key]
            
            # Check for significant changes in fingerprint
            consistency_score = 0
            total_checks = 0
            
            # Compare browser info
            if stored_fingerprint.get('browser') == fingerprint_data.get('browser'):
                consistency_score += 1
            total_checks += 1
            
            # Compare OS info
            if stored_fingerprint.get('os') == fingerprint_data.get('os'):
                consistency_score += 1
            total_checks += 1
            
            # Compare language settings
            if stored_fingerprint.get('accept_language') == fingerprint_data.get('accept_language'):
                consistency_score += 1
            total_checks += 1
            
            # Compare encoding preferences
            if stored_fingerprint.get('accept_encoding') == fingerprint_data.get('accept_encoding'):
                consistency_score += 1
            total_checks += 1
            
            consistency_ratio = consistency_score / total_checks if total_checks > 0 else 0
            
            # If consistency is too low, flag as suspicious
            if consistency_ratio < 0.5:
                self.suspicious_devices.add(device_key)
                return False, f"Device fingerprint inconsistency: {consistency_ratio:.2f}"
            
        else:
            # First time seeing this device, store fingerprint
            self.device_fingerprints[device_key] = fingerprint_data
        
        return True, "Device consistency check passed"
    
    def _check_device_limits(self, device_id, user_name, ip_address):
        """Check device access limits and patterns"""
        current_time = time.time()
        
        # Check IP-based device limits
        devices_from_ip = set()
        for key, accesses in self.device_access_history.items():
            if ip_address in key:
                recent_accesses = [a for a in accesses if current_time - a < 3600]
                if recent_accesses:
                    devices_from_ip.add(key.split('_')[0])  # Extract device_id
        
        if len(devices_from_ip) > 5:  # Max 5 different devices per IP per hour
            return False, "Too many different devices from same IP"
        
        # Check for device ID pattern abuse
        device_pattern = device_id.split('_')[0] if '_' in device_id else device_id
        similar_devices = [
            key for key in self.device_access_history.keys()
            if key.startswith(device_pattern) and key != f"{device_id}_{ip_address}"
        ]
        
        if len(similar_devices) > 10:  # Suspicious if too many similar device IDs
            return False, "Suspicious device ID pattern detected"
        
        return True, "Device limits check passed"
    
    def verify_device(self, device_id, user_name, request):
        """
        Comprehensive device verification
        """
        try:
            ip_address = request.remote_addr
            if request.headers.getlist("X-Forwarded-For"):
                ip_address = request.headers.getlist("X-Forwarded-For")[0].split(',')[0]
            
            verification_results = []
            
            # Step 1: Generate request fingerprint
            fingerprint_hash, fingerprint_data = self._generate_request_fingerprint(request)
            verification_results.append(("fingerprint", True, "Generated"))
            
            # Step 2: Validate user agent
            user_agent = request.headers.get('User-Agent', '')
            ua_valid, ua_reason = self._validate_user_agent(user_agent)
            verification_results.append(("user_agent", ua_valid, ua_reason))
            
            if not ua_valid:
                return {
                    'valid': False,
                    'reason': f"User agent validation failed: {ua_reason}",
                    'fingerprint': fingerprint_hash,
                    'verification_results': verification_results
                }
            
            # Step 3: Check request timing patterns
            timing_valid, timing_reason = self._check_request_timing(device_id, ip_address)
            verification_results.append(("timing", timing_valid, timing_reason))
            
            if not timing_valid:
                return {
                    'valid': False,
                    'reason': f"Request timing check failed: {timing_reason}",
                    'fingerprint': fingerprint_hash,
                    'verification_results': verification_results
                }
            
            # Step 4: Analyze device consistency
            consistency_valid, consistency_reason = self._analyze_device_consistency(
                device_id, user_name, fingerprint_data
            )
            verification_results.append(("consistency", consistency_valid, consistency_reason))
            
            if not consistency_valid:
                return {
                    'valid': False,
                    'reason': f"Device consistency check failed: {consistency_reason}",
                    'fingerprint': fingerprint_hash,
                    'verification_results': verification_results
                }
            
            # Step 5: Check device limits
            limits_valid, limits_reason = self._check_device_limits(device_id, user_name, ip_address)
            verification_results.append(("limits", limits_valid, limits_reason))
            
            if not limits_valid:
                return {
                    'valid': False,
                    'reason': f"Device limits check failed: {limits_reason}",
                    'fingerprint': fingerprint_hash,
                    'verification_results': verification_results
                }
            
            # All checks passed
            device_key = f"{device_id}_{user_name}"
            if device_key not in self.device_registry:
                self.device_registry[device_key] = {
                    'first_seen': time.time(),
                    'last_verified': time.time(),
                    'verification_count': 1,
                    'fingerprint': fingerprint_hash,
                    'ip_addresses': {ip_address}
                }
            else:
                self.device_registry[device_key]['last_verified'] = time.time()
                self.device_registry[device_key]['verification_count'] += 1
                self.device_registry[device_key]['ip_addresses'].add(ip_address)
            
            logger.info(f"Device verification successful for {device_id} from {ip_address}")
            
            return {
                'valid': True,
                'reason': 'All verification checks passed',
                'fingerprint': fingerprint_hash,
                'device_info': {
                    'browser': fingerprint_data.get('browser', 'Unknown'),
                    'os': fingerprint_data.get('os', 'Unknown'),
                    'first_seen': self.device_registry[device_key]['first_seen'],
                    'verification_count': self.device_registry[device_key]['verification_count']
                },
                'verification_results': verification_results
            }
            
        except Exception as e:
            logger.error(f"Error during device verification for {device_id}: {e}")
            return {
                'valid': False,
                'reason': f'Device verification system error: {str(e)}',
                'fingerprint': 'error',
                'verification_results': [("system_error", False, str(e))]
            }
    
    def is_device_suspicious(self, device_id, user_name):
        """Check if device is flagged as suspicious"""
        device_key = f"{device_id}_{user_name}"
        return device_key in self.suspicious_devices
    
    def flag_device_suspicious(self, device_id, user_name, reason):
        """Flag device as suspicious"""
        device_key = f"{device_id}_{user_name}"
        self.suspicious_devices.add(device_key)
        logger.warning(f"Device {device_id} flagged as suspicious: {reason}")
    
    def clear_device_suspicion(self, device_id, user_name):
        """Clear suspicious flag from device"""
        device_key = f"{device_id}_{user_name}"
        if device_key in self.suspicious_devices:
            self.suspicious_devices.remove(device_key)
            logger.info(f"Cleared suspicious flag for device {device_id}")
    
    def get_device_stats(self, device_id, user_name):
        """Get statistics for a specific device"""
        device_key = f"{device_id}_{user_name}"
        
        if device_key not in self.device_registry:
            return None
        
        device_info = self.device_registry[device_key]
        return {
            'device_id': device_id,
            'user_name': user_name,
            'first_seen': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(device_info['first_seen'])),
            'last_verified': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(device_info['last_verified'])),
            'verification_count': device_info['verification_count'],
            'fingerprint': device_info['fingerprint'],
            'ip_count': len(device_info['ip_addresses']),
            'is_suspicious': device_key in self.suspicious_devices
        }
    
    def cleanup_old_data(self):
        """Clean up old device data and access history"""
        current_time = time.time()
        cleanup_threshold = 86400 * 7  # 7 days
        
        # Clean device registry
        devices_to_remove = []
        for device_key, device_info in self.device_registry.items():
            if current_time - device_info['last_verified'] > cleanup_threshold:
                devices_to_remove.append(device_key)
        
        for device_key in devices_to_remove:
            del self.device_registry[device_key]
            if device_key in self.suspicious_devices:
                self.suspicious_devices.remove(device_key)
        
        # Clean access history
        for device_key in list(self.device_access_history.keys()):
            self.device_access_history[device_key] = [
                access_time for access_time in self.device_access_history[device_key]
                if current_time - access_time < cleanup_threshold
            ]
            
            if not self.device_access_history[device_key]:
                del self.device_access_history[device_key]
        
        if devices_to_remove:
            logger.info(f"Cleaned up {len(devices_to_remove)} old device records")
    
    def get_system_stats(self):
        """Get system-wide device statistics"""
        return {
            'total_devices': len(self.device_registry),
            'suspicious_devices': len(self.suspicious_devices),
            'active_devices_24h': len([
                device for device, info in self.device_registry.items()
                if time.time() - info['last_verified'] < 86400
            ]),
            'total_access_records': sum(len(accesses) for accesses in self.device_access_history.values())
        }