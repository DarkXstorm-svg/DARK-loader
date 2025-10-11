#!/usr/bin/env python3
"""
Advanced Security Utilities for OCHOxDARK Protection System
Multi-layered protection against unauthorized access and reverse engineering
"""

import hashlib
import hmac
import time
import secrets
import base64
import json
import os
import platform
import threading
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ipaddress
from collections import defaultdict, deque
import psutil
import sys

class SecurityConfig:
    """Security configuration constants"""
    # Rotating secrets (change these regularly)
    ASH = "KUPAL"
    YAWA = "ULOL"
    TERTIARY_SECRET = "UltraSecure_AntiReverse_Shield"
    
    # Token validation times
    TOKEN_VALIDITY_MINUTES = 5
    CHALLENGE_VALIDITY_SECONDS = 30
    MAX_REQUEST_PER_MINUTE = 3
    
    # Anti-debugging constants
    DEBUG_DETECTION_INTERVAL = 2
    INTEGRITY_CHECK_INTERVAL = 5
    
    # Forensic settings
    MAX_LOG_ENTRIES = 10000
    THREAT_SCORE_THRESHOLD = 100

class CryptoEngine:
    """Advanced cryptographic operations"""
    
    def __init__(self):
        self.master_key = self._derive_master_key()
        self.cipher_suite = Fernet(self.master_key)
        
    def _derive_master_key(self):
        """Derive master encryption key from multiple sources"""
        combined_secret = (
            SecurityConfig.ASH + 
            SecurityConfig.YAWA + 
            str(int(time.time() // 3600))  # Hour-based rotation
        ).encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'OCHOxDARK_SALT_2024',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(combined_secret))
        return key
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        try:
            encrypted = self.cipher_suite.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception:
            return ""
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher_suite.decrypt(decoded)
            return decrypted.decode()
        except Exception:
            return ""

class SignatureValidator:
    """Advanced signature validation system"""
    
    @staticmethod
    def generate_loader_signature(device_id: str, user_name: str, timestamp: int) -> str:
        """Generate secure signature for loader requests"""
        data = f"{device_id}:{user_name}:{timestamp}"
        
        # Multi-layer signature
        sig1 = hmac.new(
            SecurityConfig.ASH.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        sig2 = hmac.new(
            SecurityConfig.YAWA.encode(),
            sig1.encode(),
            hashlib.sha512
        ).hexdigest()
        
        sig3 = hmac.new(
            SecurityConfig.TERTIARY_SECRET.encode(),
            f"{sig2}:{data}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        return base64.urlsafe_b64encode(sig3.encode()).decode()[:64]
    
    @staticmethod
    def validate_signature(device_id: str, user_name: str, timestamp: int, signature: str) -> bool:
        """Validate loader signature"""
        try:
            expected = SignatureValidator.generate_loader_signature(device_id, user_name, timestamp)
            return hmac.compare_digest(expected, signature)
        except Exception:
            return False

class ChallengeResponseSystem:
    """Dynamic challenge-response authentication"""
    
    def __init__(self):
        self.active_challenges = {}
        self.challenge_history = deque(maxlen=1000)
        
    def generate_challenge(self, client_id: str) -> dict:
        """Generate unique challenge for client"""
        timestamp = int(time.time())
        nonce = secrets.token_hex(16)
        
        # Complex mathematical challenge
        a = secrets.randbelow(1000) + 1
        b = secrets.randbelow(1000) + 1
        operation = secrets.choice(['add', 'multiply', 'xor'])
        
        if operation == 'add':
            expected_result = a + b
            challenge_text = f"{a}+{b}"
        elif operation == 'multiply':
            expected_result = a * b
            challenge_text = f"{a}*{b}"
        else:  # xor
            expected_result = a ^ b
            challenge_text = f"{a}^{b}"
        
        # Create challenge hash
        challenge_data = f"{nonce}:{challenge_text}:{timestamp}"
        challenge_hash = hashlib.sha256(
            f"{challenge_data}:{SecurityConfig.ASH}".encode()
        ).hexdigest()
        
        challenge_obj = {
            'challenge_id': challenge_hash[:16],
            'nonce': nonce,
            'challenge': challenge_text,
            'expected': expected_result,
            'timestamp': timestamp,
            'client_id': client_id
        }
        
        self.active_challenges[challenge_hash[:16]] = challenge_obj
        self.challenge_history.append((timestamp, client_id, challenge_hash[:16]))
        
        # Cleanup old challenges
        self._cleanup_expired_challenges()
        
        return {
            'challenge_id': challenge_hash[:16],
            'challenge': challenge_text,
            'nonce': nonce
        }
    
    def validate_response(self, challenge_id: str, response: int, client_signature: str) -> bool:
        """Validate challenge response"""
        try:
            if challenge_id not in self.active_challenges:
                return False
            
            challenge = self.active_challenges[challenge_id]
            
            # Check expiry
            if time.time() - challenge['timestamp'] > SecurityConfig.CHALLENGE_VALIDITY_SECONDS:
                del self.active_challenges[challenge_id]
                return False
            
            # Validate response
            if challenge['expected'] != response:
                del self.active_challenges[challenge_id]
                return False
            
            # Validate client signature
            expected_sig = hmac.new(
                f"{challenge['nonce']}:{SecurityConfig.ASH}".encode(),
                f"{challenge_id}:{response}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(expected_sig, client_signature):
                del self.active_challenges[challenge_id]
                return False
            
            # Success - remove challenge
            del self.active_challenges[challenge_id]
            return True
            
        except Exception:
            return False
    
    def _cleanup_expired_challenges(self):
        """Remove expired challenges"""
        current_time = time.time()
        expired = [
            cid for cid, challenge in self.active_challenges.items()
            if current_time - challenge['timestamp'] > SecurityConfig.CHALLENGE_VALIDITY_SECONDS
        ]
        for cid in expired:
            del self.active_challenges[cid]

class RateLimiter:
    """Advanced rate limiting and IP protection"""
    
    def __init__(self):
        self.request_history = defaultdict(deque)
        self.blocked_ips = set()
        self.suspicious_ips = defaultdict(int)
        self.whitelist_ips = set()
        
    def is_rate_limited(self, ip_address: str) -> bool:
        """Check if IP is rate limited"""
        if ip_address in self.blocked_ips:
            return True
            
        if ip_address in self.whitelist_ips:
            return False
        
        current_time = time.time()
        
        # Clean old requests
        cutoff_time = current_time - 60  # 1 minute window
        while (self.request_history[ip_address] and 
               self.request_history[ip_address][0] < cutoff_time):
            self.request_history[ip_address].popleft()
        
        # Check rate limit
        if len(self.request_history[ip_address]) >= SecurityConfig.MAX_REQUEST_PER_MINUTE:
            self.suspicious_ips[ip_address] += 1
            if self.suspicious_ips[ip_address] >= 3:
                self.blocked_ips.add(ip_address)
            return True
        
        # Record request
        self.request_history[ip_address].append(current_time)
        return False
    
    def add_to_whitelist(self, ip_address: str):
        """Add IP to whitelist"""
        self.whitelist_ips.add(ip_address)
    
    def block_ip(self, ip_address: str):
        """Manually block IP"""
        self.blocked_ips.add(ip_address)

class AntiDebugger:
    """Anti-debugging and reverse engineering protection"""
    
    def __init__(self):
        self.is_monitoring = False
        self.threat_level = 0
        self.monitor_thread = None
        
    def start_monitoring(self):
        """Start anti-debugging monitoring"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_threats, daemon=True)
            self.monitor_thread.start()
    
    def _monitor_threats(self):
        """Monitor for debugging and reverse engineering attempts"""
        while self.is_monitoring:
            try:
                # Check for common debuggers
                if self._detect_debugger():
                    self.threat_level += 25
                
                # Check for suspicious processes
                if self._detect_analysis_tools():
                    self.threat_level += 20
                
                # Check for VM/sandbox environment
                if self._detect_virtualization():
                    self.threat_level += 15
                
                # Check for memory monitoring
                if self._detect_memory_analysis():
                    self.threat_level += 30
                
                time.sleep(SecurityConfig.DEBUG_DETECTION_INTERVAL)
                
            except Exception:
                pass
    
    def _detect_debugger(self) -> bool:
        """Detect common debuggers"""
        debugger_processes = [
            'gdb', 'lldb', 'windbg', 'x64dbg', 'ida', 'ida64', 
            'ollydbg', 'immunity', 'radare2', 'ghidra'
        ]
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] and any(dbg in proc.info['name'].lower() for dbg in debugger_processes):
                    return True
        except:
            pass
        return False
    
    def _detect_analysis_tools(self) -> bool:
        """Detect reverse engineering tools"""
        analysis_tools = [
            'wireshark', 'fiddler', 'burpsuite', 'cheatengine', 
            'processhacker', 'procmon', 'regmon', 'apimonitor'
        ]
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] and any(tool in proc.info['name'].lower() for tool in analysis_tools):
                    return True
        except:
            pass
        return False
    
    def _detect_virtualization(self) -> bool:
        """Detect virtual machine environment"""
        vm_indicators = [
            'vmware', 'virtualbox', 'vbox', 'qemu', 'xen', 
            'hyperv', 'parallels', 'sandboxie'
        ]
        
        try:
            system_info = platform.system().lower() + platform.release().lower()
            if any(vm in system_info for vm in vm_indicators):
                return True
        except:
            pass
        return False
    
    def _detect_memory_analysis(self) -> bool:
        """Detect memory analysis attempts"""
        try:
            # Check for unusual memory usage patterns
            memory = psutil.virtual_memory()
            if memory.percent > 90:  # High memory usage might indicate analysis
                return True
        except:
            pass
        return False
    
    def get_threat_level(self) -> int:
        """Get current threat level"""
        return min(self.threat_level, 1000)  # Cap at 1000
    
    def is_under_analysis(self) -> bool:
        """Check if system is under analysis"""
        return self.threat_level > SecurityConfig.THREAT_SCORE_THRESHOLD

class ForensicLogger:
    """Advanced forensic logging and threat detection"""
    
    def __init__(self):
        self.log_entries = deque(maxlen=SecurityConfig.MAX_LOG_ENTRIES)
        self.threat_patterns = defaultdict(int)
        self.attack_signatures = []
        
    def log_access_attempt(self, ip: str, user_agent: str, headers: dict, 
                          success: bool, threat_level: int = 0):
        """Log access attempt with forensic data"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'user_agent': user_agent,
            'headers': dict(headers),
            'success': success,
            'threat_level': threat_level,
            'session_id': secrets.token_hex(8)
        }
        
        self.log_entries.append(entry)
        
        # Analyze threat patterns
        self._analyze_threat_patterns(entry)
        
    def _analyze_threat_patterns(self, entry: dict):
        """Analyze entry for threat patterns"""
        ip = entry['ip']
        ua = entry.get('user_agent', '').lower()
        
        # Check for suspicious user agents
        suspicious_ua_patterns = [
            'curl', 'wget', 'python', 'requests', 'scanner', 
            'bot', 'crawler', 'tool', 'automated'
        ]
        
        if any(pattern in ua for pattern in suspicious_ua_patterns):
            self.threat_patterns[f'suspicious_ua_{ip}'] += 1
        
        # Check for rapid requests
        recent_requests = [
            e for e in self.log_entries 
            if e['ip'] == ip and 
            datetime.fromisoformat(e['timestamp']) > datetime.now() - timedelta(minutes=1)
        ]
        
        if len(recent_requests) > 5:
            self.threat_patterns[f'rapid_requests_{ip}'] += 1
        
        # Check for failed attempts
        if not entry['success']:
            self.threat_patterns[f'failed_attempts_{ip}'] += 1
    
    def get_threat_intelligence(self, ip: str) -> dict:
        """Get threat intelligence for IP"""
        patterns = {k: v for k, v in self.threat_patterns.items() if ip in k}
        
        threat_score = sum(patterns.values()) * 10
        
        return {
            'threat_score': threat_score,
            'patterns': patterns,
            'is_threat': threat_score > 50
        }
    
    def export_logs(self, format='json') -> str:
        """Export logs for analysis"""
        if format == 'json':
            return json.dumps(list(self.log_entries), indent=2)
        return str(list(self.log_entries))

class DecoySystem:
    """Decoy responses and honeypot system"""
    
    @staticmethod
    def generate_fake_code() -> str:
        """Generate fake code to mislead attackers"""
        fake_code = '''#!/usr/bin/env python3
# Fake OCHO Checker - Decoy System
import random
import time

def fake_function():
    """This is a decoy function"""
    print("Access granted to fake system")
    return "fake_result_" + str(random.randint(1000, 9999))

def main():
    print("Starting fake checker...")
    time.sleep(2)
    result = fake_function()
    print(f"Fake result: {result}")

if __name__ == "__main__":
    main()
'''
        return fake_code
    
    @staticmethod
    def generate_honeypot_response() -> dict:
        """Generate honeypot response"""
        return {
            'status': 'success',
            'fake_data': secrets.token_hex(32),
            'decoy_timestamp': int(time.time()),
            'message': 'Honeypot activated - access logged'
        }

# Global instances
crypto_engine = CryptoEngine()
signature_validator = SignatureValidator()
challenge_system = ChallengeResponseSystem()
rate_limiter = RateLimiter()
anti_debugger = AntiDebugger()
forensic_logger = ForensicLogger()
decoy_system = DecoySystem()

# Start monitoring
anti_debugger.start_monitoring()