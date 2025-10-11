"""
Enhanced DARKxStorms Loader with Advanced Security
Multi-layered protection, integrity verification, and encrypted communication
"""

import requests
import os
import sys
import subprocess
import hashlib
import platform
import uuid
import time
import warnings
import urllib3
import threading
import re
import json
import base64
import secrets
from datetime import datetime
from colorama import Fore, Style, init
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# Security Configuration
SECURE_SERVER_URL = "https://ochoxash.onrender.com"  # Your secure server URL
CHECKER_ENDPOINT = "/ocho.py"
VERIFY_SESSION_ENDPOINT = "/verify-session"
TEMP_DIR = os.path.join(os.path.expanduser("~"), ".darkxstorms_secure")
ID_DIR = os.path.expanduser("~/.darkxstorms_loader_id")
ID_FILE = os.path.join(ID_DIR, "loader_id.txt")
SESSION_FILE = os.path.join(TEMP_DIR, "session.dat")
INTEGRITY_FILE = os.path.join(TEMP_DIR, "integrity.hash")

# Security constants
LOADER_SIGNATURE = "KUPAL"
EXPECTED_SERVER_HEADERS = ['X-Session-Token', 'X-Content-Type-Options']
MAX_DOWNLOAD_SIZE = 10 * 1024 * 1024  # 10MB max
REQUEST_TIMEOUT = 30

class SecurityError(Exception):
    """Custom security exception"""
    pass

class LoaderSecurity:
    """Enhanced security manager for loader"""
    
    def __init__(self):
        self.session_token = None
        self.device_fingerprint = None
        self.last_verification = 0
        self.failed_attempts = 0
        self.max_failed_attempts = 3
        
    def generate_device_fingerprint(self):
        """Generate comprehensive device fingerprint"""
        try:
            # Collect system information
            system_info = {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'architecture': platform.architecture()[0]
            }
            
            # Create fingerprint hash
            fingerprint_data = json.dumps(system_info, sort_keys=True)
            fingerprint_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()
            
            self.device_fingerprint = fingerprint_hash
            return fingerprint_hash
            
        except Exception as e:
            print_status(f"Error generating device fingerprint: {e}", "error")
            return None
    
    def verify_server_response(self, response):
        """Verify server response integrity"""
        # Check required headers
        for header in EXPECTED_SERVER_HEADERS:
            if header not in response.headers:
                raise SecurityError(f"Missing security header: {header}")
        
        # Verify content type
        content_type = response.headers.get('Content-Type', '')
        if 'text/plain' not in content_type:
            raise SecurityError("Invalid content type in response")
        
        # Check response size
        content_length = len(response.content)
        if content_length > MAX_DOWNLOAD_SIZE:
            raise SecurityError("Response size exceeds security limit")
        
        if content_length < 1000:  # Minimum expected size
            raise SecurityError("Response size too small - possible attack")
        
        # Extract session token
        self.session_token = response.headers.get('X-Session-Token')
        if not self.session_token:
            raise SecurityError("Missing session token in response")
        
        return True
    
    def verify_code_integrity(self, code_content):
        """Verify downloaded code integrity"""
        # Check for security markers
        required_markers = [
            '# DARKxStorms Protected Code',
            '_check_debug',
            '_verify_runtime_environment'
        ]
        
        for marker in required_markers:
            if marker not in code_content:
                raise SecurityError(f"Missing security marker: {marker}")
        
        # Check for suspicious modifications
        suspicious_patterns = [
            r'exec\s*\(\s*input\s*\(',  # Dangerous exec with input
            r'__import__\s*\(\s*[\'"]os[\'"]',  # Suspicious os imports
            r'subprocess\s*\.\s*call\s*\([\'"]rm',  # Dangerous system calls
            r'eval\s*\(\s*input\s*\(',  # Dangerous eval with input
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, code_content, re.IGNORECASE):
                raise SecurityError(f"Suspicious code pattern detected: {pattern}")
        
        # Calculate and store integrity hash
        code_hash = hashlib.sha256(code_content.encode()).hexdigest()
        
        try:
            os.makedirs(TEMP_DIR, exist_ok=True)
            with open(INTEGRITY_FILE, 'w') as f:
                f.write(json.dumps({
                    'hash': code_hash,
                    'timestamp': time.time(),
                    'device_fingerprint': self.device_fingerprint
                }))
        except Exception as e:
            print_status(f"Warning: Could not save integrity hash: {e}", "warning")
        
        return code_hash
    
    def save_session_data(self):
        """Save encrypted session data"""
        if not self.session_token:
            return False
        
        try:
            os.makedirs(TEMP_DIR, exist_ok=True)
            
            session_data = {
                'token': self.session_token,
                'timestamp': time.time(),
                'device_fingerprint': self.device_fingerprint,
                'failed_attempts': self.failed_attempts
            }
            
            # Simple base64 encoding for session data
            encoded_data = base64.b64encode(json.dumps(session_data).encode()).decode()
            
            with open(SESSION_FILE, 'w') as f:
                f.write(encoded_data)
            
            return True
            
        except Exception as e:
            print_status(f"Could not save session data: {e}", "warning")
            return False
    
    def load_session_data(self):
        """Load encrypted session data"""
        try:
            if not os.path.exists(SESSION_FILE):
                return False
            
            with open(SESSION_FILE, 'r') as f:
                encoded_data = f.read().strip()
            
            # Decode session data
            session_data = json.loads(base64.b64decode(encoded_data.encode()).decode())
            
            # Verify session data is recent (within 2 hours)
            if time.time() - session_data['timestamp'] > 7200:
                print_status("Session data expired", "warning")
                return False
            
            # Verify device fingerprint matches
            if session_data.get('device_fingerprint') != self.device_fingerprint:
                print_status("Device fingerprint mismatch", "warning")
                return False
            
            self.session_token = session_data['token']
            self.failed_attempts = session_data.get('failed_attempts', 0)
            
            return True
            
        except Exception as e:
            print_status(f"Could not load session data: {e}", "warning")
            return False
    
    def cleanup_session_data(self):
        """Clean up session and temporary files"""
        files_to_remove = [SESSION_FILE, INTEGRITY_FILE]
        
        for file_path in files_to_remove:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                print_status(f"Could not remove {file_path}: {e}", "warning")
    
    def record_failed_attempt(self):
        """Record failed attempt"""
        self.failed_attempts += 1
        print_status(f"Security failure #{self.failed_attempts}/{self.max_failed_attempts}", "warning")
        
        if self.failed_attempts >= self.max_failed_attempts:
            print_status("Maximum security failures reached. Cleaning up and exiting.", "error")
            self.cleanup_session_data()
            sys.exit(1)

def print_status(message, status_type="info"):
    """Enhanced status printing with security indicators"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    if status_type == "success":
        print(f"{Fore.GREEN}[{timestamp}][SUCCESS]{Style.RESET_ALL} {message}")
    elif status_type == "warning":
        print(f"{Fore.YELLOW}[{timestamp}][WARNING]{Style.RESET_ALL} {message}")
    elif status_type == "error":
        print(f"{Fore.RED}[{timestamp}][ERROR]{Style.RESET_ALL} {message}")
    elif status_type == "security":
        print(f"{Fore.CYAN}[{timestamp}][SECURITY]{Style.RESET_ALL} {message}")
    else:
        print(f"{Fore.WHITE}[{timestamp}][INFO]{Style.RESET_ALL} {message}")

def get_permanent_manual_id():
    """Enhanced device ID management with security validation"""
    os.makedirs(ID_DIR, exist_ok=True)
    
    if os.path.exists(ID_FILE):
        try:
            with open(ID_FILE, 'r') as file:
                device_id = file.read().strip()
                if device_id and '_' in device_id:
                    user_name = device_id.split('_', 1)[0]
                    if 3 <= len(user_name) <= 20 and len(device_id.split('_', 1)[1]) == 4:
                        print_status(f"Loaded secure device ID: {device_id[:8]}***", "security")
                        return device_id, user_name
        except IOError:
            pass
        print_status("Device ID validation failed - requesting new credentials", "warning")
    
    print_status("Secure device registration required", "security")
    
    while True:
        user_name = input(f"{Fore.CYAN}Enter secure username (3-20 alphanumeric): {Style.RESET_ALL}").strip()
        if 3 <= len(user_name) <= 20 and re.match(r'^[a-zA-Z0-9]+$', user_name):
            break
        print_status("Invalid format: Must be 3-20 alphanumeric characters", "error")
    
    while True:
        device_code = input(f"{Fore.CYAN}Enter device code (4 alphanumeric chars): {Style.RESET_ALL}").strip()
        if len(device_code) == 4 and re.match(r'^[a-zA-Z0-9]+$', device_code):
            device_id = f"{user_name}_{device_code}"
            try:
                with open(ID_FILE, 'w') as file:
                    file.write(device_id)
                print_status(f"Secure device registered: {device_id[:8]}***", "security")
                return device_id, user_name
            except IOError:
                print_status("Failed to save device credentials", "error")
                return device_id, user_name
        else:
            print_status("Invalid code: Must be exactly 4 alphanumeric characters", "error")

def check_loader_subscription(device_id, user_name):
    """Enhanced subscription check with security validation"""
    subscription_api = "https://darkxdeath.onrender.com/api.php"
    url = f"{subscription_api}?device_id={device_id}&user_name={user_name}&loader_check=true"
    
    headers = {
        'User-Agent': 'DARKxStorms-Enhanced-Loader/2.0',
        'Accept': 'application/json',
        'X-Loader-Signature': LOADER_SIGNATURE,
        'X-Security-Check': 'enhanced_loader'
    }
    
    try:
        print_status("Verifying subscription with enhanced security...", "security")
        response = requests.get(url, headers=headers, verify=False, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        
        response_json = response.json()
        print_status("Subscription verification completed", "success")
        
        return response_json
        
    except requests.exceptions.RequestException as e:
        print_status(f"Subscription verification failed: {e}", "error")
        return {"status": "error", "message": "Subscription server unavailable"}
    except json.JSONDecodeError:
        print_status("Invalid subscription response format", "error")
        return {"status": "error", "message": "Invalid server response"}

def create_secure_session(device_id, user_name):
    """Create secure request session with enhanced headers"""
    session = requests.Session()
    
    # Enhanced security headers
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'X-Loader-Request': LOADER_SIGNATURE,
        'X-Device-ID': device_id,
        'X-User-Name': user_name,
        'X-Request-Time': str(int(time.time())),
        'X-Security-Version': '2.0'
    })
    
    return session

def download_protected_code(device_id, user_name, security_manager):
    """Download and verify protected code with enhanced security"""
    url = f"{SECURE_SERVER_URL}{CHECKER_ENDPOINT}"
    params = {
        'device_id': device_id,
        'user_name': user_name,
        'timestamp': int(time.time()),
        'fingerprint': security_manager.device_fingerprint
    }
    
    # Create secure session
    session = create_secure_session(device_id, user_name)
    
    # Progress tracking
    local_checker_path = os.path.join(TEMP_DIR, "secure_checker.py")
    os.makedirs(TEMP_DIR, exist_ok=True)
    
    download_success = False
    error_details = None

    def download_with_security():
        nonlocal download_success, error_details
        try:
            print_status("Initiating secure download...", "security")
            
            response = session.get(url, params=params, stream=True, timeout=REQUEST_TIMEOUT)
            
            # Security verification
            if response.status_code == 403:
                error_details = "Access denied - security verification failed"
                return
            elif response.status_code == 429:
                error_details = "Rate limit exceeded - try again later"
                return
            elif response.status_code != 200:
                error_details = f"Server error: {response.status_code}"
                return
            
            # Verify server response
            security_manager.verify_server_response(response)
            
            # Download with progress
            total_size = int(response.headers.get('Content-Length', 0))
            downloaded = 0
            
            with open(local_checker_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
            
            # Verify file was written
            if not os.path.exists(local_checker_path) or os.path.getsize(local_checker_path) == 0:
                error_details = "Download verification failed - file not created"
                return
            
            # Read and verify code integrity
            with open(local_checker_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            security_manager.verify_code_integrity(code_content)
            
            download_success = True
            print_status("Secure download completed and verified", "success")
            
        except SecurityError as e:
            error_details = f"Security verification failed: {e}"
            security_manager.record_failed_attempt()
        except Exception as e:
            error_details = f"Download error: {e}"
            security_manager.record_failed_attempt()

    # Start download in thread
    download_thread = threading.Thread(target=download_with_security)
    download_thread.start()

    # Progress animation
    progress_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    char_index = 0
    
    while download_thread.is_alive():
        sys.stdout.write(f"\r{Fore.CYAN}Secure Loading {progress_chars[char_index]} {Style.RESET_ALL}")
        sys.stdout.flush()
        char_index = (char_index + 1) % len(progress_chars)
        time.sleep(0.1)

    download_thread.join()
    sys.stdout.write(f"\r{' ' * 50}\r")  # Clear progress line

    if not download_success:
        print_status(error_details or "Download failed for unknown reason", "error")
        security_manager.cleanup_session_data()
        sys.exit(1)

    # Save session data
    security_manager.save_session_data()

    return local_checker_path

def execute_protected_code(checker_path, original_args):
    """Execute protected code with security monitoring"""
    try:
        print_status("Executing protected code with security monitoring...", "security")
        
        # Execute with original arguments
        cmd = [sys.executable, checker_path] + original_args
        
        # Set secure environment
        env = os.environ.copy()
        env['DARKX_SECURE_MODE'] = '1'
        env['DARKX_LOADER_VERSION'] = '2.0'
        
        # Execute
        result = subprocess.run(cmd, env=env, capture_output=False, text=True)
        
        print_status(f"Execution completed with code: {result.returncode}", "info")
        
        return result.returncode
        
    except Exception as e:
        print_status(f"Execution error: {e}", "error")
        return 1
    finally:
        # Cleanup
        cleanup_temporary_files(checker_path)

def cleanup_temporary_files(checker_path):
    """Clean up temporary files securely"""
    try:
        if os.path.exists(checker_path):
            # Overwrite file with random data before deletion
            file_size = os.path.getsize(checker_path)
            with open(checker_path, 'wb') as f:
                f.write(os.urandom(file_size))
            os.remove(checker_path)
        
        print_status("Temporary files cleaned up securely", "security")
        
    except Exception as e:
        print_status(f"Cleanup warning: {e}", "warning")

def main():
    """Main loader function with enhanced security"""
    try:
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════")
        print(f"{Fore.CYAN}  DARKxStorms Enhanced Secure Loader v2.0")
        print(f"{Fore.CYAN}  Advanced Security • Tamper Protection • Encrypted Communication")
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        print()
        
        # Initialize security manager
        security_manager = LoaderSecurity()
        
        # Generate device fingerprint
        print_status("Generating secure device fingerprint...", "security")
        if not security_manager.generate_device_fingerprint():
            print_status("Device fingerprinting failed", "error")
            sys.exit(1)
        
        # Load device credentials
        device_id, user_name = get_permanent_manual_id()
        
        # Try to load existing session
        session_loaded = security_manager.load_session_data()
        if session_loaded:
            print_status("Existing secure session loaded", "security")
        
        # Check subscription status
        subscription_response = check_loader_subscription(device_id, user_name)
        status = subscription_response.get("status")
        
        if status == "active":
            print_status("Subscription verified - Access granted", "success")
            
            # Download and execute protected code
            checker_path = download_protected_code(device_id, user_name, security_manager)
            exit_code = execute_protected_code(checker_path, sys.argv[1:])
            
            sys.exit(exit_code)
            
        elif status in ["pending", "registered_pending"]:
            print_status("Subscription Status: Pending Approval", "warning")
            print_status(f"Your Device ID: {device_id}", "info")
            print_status("Contact administrator for approval", "info")
            
        elif status == "expired":
            print_status("Subscription Status: Expired", "error")
            print_status(f"Your Device ID: {device_id}", "info")
            print_status("Please renew your subscription", "info")
            
        else:
            print_status(f"Subscription Status Unknown: {status}", "error")
            print_status(f"Your Device ID: {device_id}", "info")
        
        sys.exit(0)
        
    except KeyboardInterrupt:
        print_status("\\nOperation cancelled by user", "warning")
        sys.exit(1)
    except Exception as e:
        print_status(f"Critical error: {e}", "error")
        sys.exit(1)

if __name__ == "__main__":
    main()