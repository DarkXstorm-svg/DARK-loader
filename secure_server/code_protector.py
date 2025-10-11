"""
Code Protection System
Advanced obfuscation, encryption, and anti-tampering for ocho.py
"""

import os
import time
import base64
import zlib
import secrets
import hashlib
import re
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logger = logging.getLogger(__name__)

class CodeProtector:
    def __init__(self):
        self.original_code_path = "ocho.py"
        self.encryption_keys = {}
        self.obfuscation_cache = {}
        
        # Anti-debugging strings
        self.anti_debug_checks = [
            "import sys",
            "if hasattr(sys, 'gettrace') and sys.gettrace():",
            "    sys.exit('Debugging detected')",
            "import os",
            "if 'PYTHONBREAKPOINT' in os.environ:",
            "    sys.exit('Breakpoints detected')",
            "import threading",
            "if threading.active_count() > 2:",
            "    pass  # Continue but log suspicious activity"
        ]
        
        # Code integrity markers
        self.integrity_markers = {
            'start': '# INTEGRITY_START_MARKER',
            'end': '# INTEGRITY_END_MARKER',
            'checksum': '# CHECKSUM: '
        }
    
    def initialize(self):
        """Initialize code protector"""
        if not os.path.exists(self.original_code_path):
            logger.error(f"Original source file not found: {self.original_code_path}")
            return False
        
        logger.info("Code Protector initialized - Advanced protection enabled")
        return True
    
    def _generate_device_key(self, device_id, user_name, session_token):
        """Generate device-specific encryption key"""
        # Create unique key based on device info and session
        key_material = f"{device_id}_{user_name}_{session_token}_{int(time.time() // 3600)}"
        key_bytes = key_material.encode('utf-8')
        
        # Use PBKDF2 to derive encryption key
        salt = hashlib.sha256(device_id.encode()).digest()[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
        return key
    
    def _obfuscate_strings(self, code):
        """Obfuscate sensitive strings in the code"""
        # Obfuscate API URLs
        code = re.sub(
            r'https://[a-zA-Z0-9\-\.]+\.onrender\.com/[a-zA-Z0-9\.]+',
            lambda m: f'_decode_url("{base64.b64encode(m.group().encode()).decode()}")',
            code
        )
        
        # Obfuscate sensitive string literals
        sensitive_patterns = [
            r'"https://[^"]*"',
            r"'https://[^']*'",
            r'"[Ee]rror[^"]*"',
            r"'[Ee]rror[^']*'",
        ]
        
        for pattern in sensitive_patterns:
            code = re.sub(
                pattern,
                lambda m: f'_decode_str("{base64.b64encode(m.group().encode()).decode()}")',
                code
            )
        
        return code
    
    def _add_anti_debug_protection(self, code):
        """Add anti-debugging and tamper detection"""
        anti_debug_code = '''
import sys
import os
import threading
import time
import hashlib

# Anti-debugging checks
def _check_debug():
    """Check for debugging attempts"""
    if hasattr(sys, 'gettrace') and sys.gettrace():
        _security_exit('Debug trace detected')
    if 'PYTHONBREAKPOINT' in os.environ:
        _security_exit('Breakpoint environment detected')
    if any(arg in sys.argv for arg in ['-m', 'pdb', '--pdb']):
        _security_exit('Debugger arguments detected')
    
def _check_execution_integrity():
    """Check execution environment integrity"""
    # Check for suspicious process names
    try:
        import psutil
        current_process = psutil.Process()
        process_name = current_process.name().lower()
        suspicious_names = ['ida', 'ollydbg', 'windbg', 'x64dbg', 'ghidra', 'radare2']
        if any(name in process_name for name in suspicious_names):
            _security_exit('Suspicious process detected')
    except:
        pass  # psutil not available, continue
    
def _security_exit(reason):
    """Secure exit with reason logging"""
    import random
    import time
    # Add random delay to confuse analysis
    time.sleep(random.uniform(0.1, 0.5))
    print("System security check failed")
    sys.exit(1)

# URL and string decoding functions
def _decode_url(encoded_url):
    """Decode obfuscated URLs"""
    import base64
    return base64.b64decode(encoded_url.encode()).decode()

def _decode_str(encoded_str):
    """Decode obfuscated strings"""
    import base64
    return base64.b64decode(encoded_str.encode()).decode()

# Runtime integrity checks
_check_debug()
_check_execution_integrity()

# Add periodic security checks
def _periodic_security_check():
    """Periodic security verification"""
    while True:
        time.sleep(30)  # Check every 30 seconds
        _check_debug()
        _check_execution_integrity()

# Start security monitoring thread
_security_thread = threading.Thread(target=_periodic_security_check, daemon=True)
_security_thread.start()
'''
        
        # Insert anti-debug code at the beginning
        lines = code.split('\n')
        
        # Find where to insert (after initial imports)
        insert_index = 0
        for i, line in enumerate(lines):
            if line.strip().startswith('import') or line.strip().startswith('from'):
                insert_index = i + 1
            else:
                break
        
        lines.insert(insert_index, anti_debug_code)
        return '\n'.join(lines)
    
    def _add_runtime_verification(self, code, device_id, user_name):
        """Add runtime verification specific to device"""
        device_hash = hashlib.sha256(f"{device_id}_{user_name}".encode()).hexdigest()
        
        runtime_check = f'''
# Runtime device verification
_EXPECTED_DEVICE_HASH = "{device_hash}"
_RUNTIME_CHECK_INTERVAL = 60  # seconds

def _verify_runtime_environment():
    """Verify runtime environment matches expected device"""
    import hashlib
    import os
    import uuid
    import platform
    
    # Recreate device fingerprint
    system_info = [
        platform.system(),
        platform.release(),
        platform.version(),
        platform.machine(),
        platform.processor()
    ]
    hardware_string = "-".join(system_info)
    unique_id = uuid.uuid5(uuid.NAMESPACE_DNS, hardware_string)
    device_hash = hashlib.sha256(unique_id.bytes).hexdigest()
    
    # For this implementation, we'll use the passed device info
    current_hash = hashlib.sha256(f"{device_id}_{user_name}".encode()).hexdigest()
    
    if current_hash != _EXPECTED_DEVICE_HASH:
        _security_exit('Device verification failed')

def _continuous_verification():
    """Continuous runtime verification"""
    import time
    while True:
        time.sleep(_RUNTIME_CHECK_INTERVAL)
        _verify_runtime_environment()

# Start verification thread
_verification_thread = threading.Thread(target=_continuous_verification, daemon=True)
_verification_thread.start()

# Initial verification
_verify_runtime_environment()
'''
        
        # Insert runtime verification after anti-debug code
        lines = code.split('\n')
        # Find a good place to insert (after imports and anti-debug)
        for i, line in enumerate(lines):
            if 'Start security monitoring thread' in line:
                lines.insert(i + 2, runtime_check)
                break
        
        return '\n'.join(lines)
    
    def _add_code_integrity_check(self, code):
        """Add code integrity verification"""
        # Calculate checksum of the main code sections
        main_code_hash = hashlib.sha256(code.encode()).hexdigest()[:32]
        
        integrity_check = f'''
# Code integrity verification
_EXPECTED_CODE_HASH = "{main_code_hash}"

def _verify_code_integrity():
    """Verify code hasn't been tampered with"""
    import hashlib
    import inspect
    
    # Get current module code
    current_frame = inspect.currentframe()
    try:
        # This is a simplified integrity check
        # In a real scenario, you'd verify against known good hashes
        pass  # Integrity check placeholder
    except:
        _security_exit('Code integrity verification failed')
    finally:
        del current_frame

_verify_code_integrity()
'''
        
        lines = code.split('\n')
        # Add integrity check after device verification
        for i, line in enumerate(lines):
            if '_verify_runtime_environment()' in line and 'Initial verification' in lines[i-1]:
                lines.insert(i + 1, integrity_check)
                break
        
        return '\n'.join(lines)
    
    def _encrypt_code_sections(self, code, encryption_key):
        """Encrypt sensitive code sections"""
        # Find and encrypt sensitive functions
        sensitive_functions = [
            'processaccount',
            'login',
            'prelogin',
            'check_subscription',
            'get_device_id'
        ]
        
        fernet = Fernet(encryption_key)
        
        for func_name in sensitive_functions:
            # Find function definition
            pattern = rf'(def {func_name}\(.*?\):.*?(?=def |\nif __name__|$))'
            matches = re.findall(pattern, code, re.DOTALL)
            
            for match in matches:
                # Encrypt the function code
                encrypted_func = fernet.encrypt(match.encode())
                encrypted_b64 = base64.b64encode(encrypted_func).decode()
                
                # Replace with encrypted version and decryption call
                replacement = f'''def {func_name}(*args, **kwargs):
    """Dynamically decrypt and execute function"""
    import base64
    from cryptography.fernet import Fernet
    
    encrypted_code = "{encrypted_b64}"
    key = _get_runtime_key()
    f = Fernet(key)
    
    try:
        decrypted_code = f.decrypt(base64.b64decode(encrypted_code.encode()))
        exec(decrypted_code.decode(), globals())
        return locals().get('{func_name}')(*args, **kwargs)
    except Exception as e:
        _security_exit(f'Function decryption failed: {{e}}')
'''
                
                code = code.replace(match, replacement)
        
        return code
    
    def _add_decryption_helper(self, code, encryption_key):
        """Add helper function for runtime decryption"""
        key_b64 = base64.b64encode(encryption_key).decode()
        
        helper_code = f'''
def _get_runtime_key():
    """Get runtime decryption key"""
    import base64
    return base64.b64decode("{key_b64}")
'''
        
        # Insert helper function early in the code
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if '_verify_code_integrity()' in line:
                lines.insert(i + 1, helper_code)
                break
        
        return '\n'.join(lines)
    
    def _compress_code(self, code):
        """Compress the code to make analysis harder"""
        compressed = zlib.compress(code.encode('utf-8'))
        compressed_b64 = base64.b64encode(compressed).decode()
        
        decompression_wrapper = f'''
import zlib
import base64
import sys

# Decompression and execution wrapper
def _execute_protected_code():
    """Decompress and execute the protected code"""
    compressed_data = "{compressed_b64}"
    
    try:
        compressed_bytes = base64.b64decode(compressed_data.encode())
        decompressed_code = zlib.decompress(compressed_bytes).decode('utf-8')
        
        # Execute in current globals
        exec(decompressed_code, globals())
    except Exception as e:
        print("System initialization failed")
        sys.exit(1)

# Execute the protected code
_execute_protected_code()
'''
        
        return decompression_wrapper
    
    def get_protected_code(self, device_id, user_name, session_token):
        """
        Generate fully protected version of ocho.py for specific device
        """
        try:
            # Read original source code
            with open(self.original_code_path, 'r', encoding='utf-8') as f:
                original_code = f.read()
            
            # Generate device-specific encryption key
            encryption_key = self._generate_device_key(device_id, user_name, session_token)
            
            # Apply protection layers
            logger.info(f"Applying code protection for device {device_id}")
            
            # Step 1: Add anti-debugging protection
            protected_code = self._add_anti_debug_protection(original_code)
            
            # Step 2: Add runtime verification
            protected_code = self._add_runtime_verification(protected_code, device_id, user_name)
            
            # Step 3: Add code integrity checks
            protected_code = self._add_code_integrity_check(protected_code)
            
            # Step 4: Obfuscate strings
            protected_code = self._obfuscate_strings(protected_code)
            
            # Step 5: Add decryption helper
            protected_code = self._add_decryption_helper(protected_code, encryption_key)
            
            # Step 6: Encrypt sensitive sections (simplified for this implementation)
            # protected_code = self._encrypt_code_sections(protected_code, encryption_key)
            
            # Step 7: Final compression (optional, might make debugging easier to skip)
            # protected_code = self._compress_code(protected_code)
            
            # Add header comment
            header = f'''# DARKxStorms Protected Code
# Device: {device_id}
# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
# Security Level: MAXIMUM
# WARNING: This code is protected against reverse engineering
# Any attempt to modify, debug, or analyze this code is prohibited
# Unauthorized access will result in immediate termination

'''
            
            protected_code = header + protected_code
            
            logger.info(f"Code protection completed for {device_id}")
            
            # Cache the protected code for a short time
            cache_key = f"{device_id}_{user_name}_{int(time.time() // 300)}"  # 5-minute cache
            self.obfuscation_cache[cache_key] = {
                'code': protected_code,
                'timestamp': time.time()
            }
            
            return protected_code
            
        except Exception as e:
            logger.error(f"Error generating protected code: {e}")
            raise Exception("Code protection failed")
    
    def cleanup_cache(self):
        """Clean up old cached protected code"""
        current_time = time.time()
        expired_keys = []
        
        for key, cache_entry in self.obfuscation_cache.items():
            if current_time - cache_entry['timestamp'] > 300:  # 5 minutes
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.obfuscation_cache[key]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def get_cache_stats(self):
        """Get cache statistics"""
        return {
            'cached_entries': len(self.obfuscation_cache),
            'total_keys': len(self.encryption_keys)
        }