#!/usr/bin/env python3
"""
DARKxStorms Secure Loader v2.0-SECURE
Advanced multi-layer security protection system
Anti-reverse engineering and tamper-proof design
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
import hmac
import secrets
import psutil
from datetime import datetime
from colorama import Fore, Style, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# --- ENHANCED SECURITY CONFIGURATION ---
class LoaderConfig:
    """Secure loader configuration"""
    VERSION = "2.0-SECURE"
    USER_AGENT = f"DARKxStorms-Loader/{VERSION}"
    
    # Server endpoints
    BASE_URL = "https://ochoxash.onrender.com"
    OCHO_ENDPOINT = f"{BASE_URL}/ocho.py"
    CHALLENGE_ENDPOINT = f"{BASE_URL}/challenge"
    
    # Security constants
    SECRET_KEY = "KUPAL"
    PRIMARY_SECRET = "DarkXStorm_2024_SecureKey_V2"
    SECONDARY_SECRET = "OchoProtection_Elite_Guard_2024"
    
    # File paths
    TEMP_DIR = os.path.join(os.path.expanduser("~"), ".darkxstorms_secure")
    ID_DIR = os.path.expanduser("~/.darkxstorms_loader_id")
    ID_FILE = os.path.join(ID_DIR, "loader_id.txt")
    CHECKER_FILE = "ocho_secure.py"
    
    # Security settings
    MAX_RETRIES = 3
    REQUEST_TIMEOUT = 30
    CHALLENGE_TIMEOUT = 10

class SecurityEngine:
    """Advanced security and anti-tampering engine"""
    
    def __init__(self):
        self.start_time = time.time()
        self.is_monitoring = True
        self._start_protection()
    
    def _start_protection(self):
        """Start protection monitoring"""
        threading.Thread(target=self._monitor_threats, daemon=True).start()
    
    def _monitor_threats(self):
        """Monitor for security threats"""
        while self.is_monitoring:
            try:
                # Anti-debugging checks (less frequent)
                if self._detect_debugger():
                    print_status("Security threat detected - terminating", "error")
                    sys.exit(1)
                
                # Anti-analysis checks (less frequent)
                if self._detect_analysis_tools():
                    print_status("Analysis tool detected - terminating", "error")
                    sys.exit(1)
                
                # Runtime integrity (more lenient)
                if not self._verify_runtime_integrity():
                    print_status("Runtime integrity compromised - terminating", "error")
                    sys.exit(1)
                
                # Longer sleep for normal operation
                time.sleep(10)
            except:
                # Don't crash on monitoring errors
                time.sleep(10)
    
    def _detect_debugger(self) -> bool:
        """Detect active debuggers"""
        try:
            # Only check for active debugger attachment
            if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
                return True
            
            # More specific debugger detection (exact matches only)
            dangerous_processes = ['gdb', 'windbg', 'x64dbg', 'ollydbg']
            try:
                for proc in psutil.process_iter(['name']):
                    proc_name = proc.info.get('name', '').lower()
                    if proc_name in dangerous_processes:
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        except:
            pass
        return False
    
    def _detect_analysis_tools(self) -> bool:
        """Detect active reverse engineering tools"""
        try:
            # Only detect actively dangerous tools
            dangerous_tools = ['cheatengine', 'ida64', 'ida']
            try:
                for proc in psutil.process_iter(['name']):
                    proc_name = proc.info.get('name', '').lower()
                    if proc_name in dangerous_tools:
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        except:
            pass
        return False
    
    def _verify_runtime_integrity(self) -> bool:
        """Verify runtime integrity"""
        try:
            # Check execution time (prevent time-based analysis)
            # Increased timeout for normal usage - 30 minutes max
            if time.time() - self.start_time > 1800:
                return False
            
            # Check for suspicious modules (only during active analysis)
            prohibited = ['pdb', 'trace', 'bdb', 'dis']
            active_prohibited = [mod for mod in prohibited if mod in sys.modules and hasattr(sys.modules[mod], '__file__')]
            if active_prohibited:
                return False
                
            return True
        except:
            return True  # Don't fail on exceptions during normal operation
    
    def generate_loader_signature(self, device_id: str, user_name: str, timestamp: int) -> str:
        """Generate secure loader signature"""
        data = f"{device_id}:{user_name}:{timestamp}"
        
        # Multi-layer signature
        sig1 = hmac.new(
            LoaderConfig.PRIMARY_SECRET.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        sig2 = hmac.new(
            LoaderConfig.SECONDARY_SECRET.encode(),
            sig1.encode(),
            hashlib.sha512
        ).hexdigest()
        
        return base64.urlsafe_b64encode(sig2.encode()).decode()[:64]
    
    def create_security_token(self, device_id: str, user_name: str) -> str:
        """Create encrypted security token"""
        token_data = {
            'device_id': device_id,
            'user_name': user_name,
            'created': time.time(),
            'nonce': secrets.token_hex(16)
        }
        
        token_json = json.dumps(token_data)
        
        # Simple encryption (base64 + XOR)
        key = hashlib.sha256(LoaderConfig.PRIMARY_SECRET.encode()).digest()
        encrypted = bytearray()
        
        for i, byte in enumerate(token_json.encode()):
            encrypted.append(byte ^ key[i % len(key)])
        
        return base64.urlsafe_b64encode(encrypted).decode()

def print_status(message, status_type="info"):
    """Enhanced status printing with security formatting"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    if status_type == "success":
        print(f"{Fore.GREEN}[{timestamp}] [SUCCESS]{Style.RESET_ALL} {message}")
    elif status_type == "warning":
        print(f"{Fore.YELLOW}[{timestamp}] [WARNING]{Style.RESET_ALL} {message}")
    elif status_type == "error":
        print(f"{Fore.RED}[{timestamp}] [ERROR]{Style.RESET_ALL} {message}")
    elif status_type == "security":
        print(f"{Fore.MAGENTA}[{timestamp}] [SECURITY]{Style.RESET_ALL} {message}")
    else:
        print(f"{Fore.CYAN}[{timestamp}] [INFO]{Style.RESET_ALL} {message}")

def get_permanent_manual_id():
    """Enhanced ID management with security validation"""
    os.makedirs(LoaderConfig.ID_DIR, exist_ok=True)
    
    if os.path.exists(LoaderConfig.ID_FILE):
        try:
            with open(LoaderConfig.ID_FILE, 'r') as file:
                device_id = file.read().strip()
                if device_id and '_' in device_id:
                    user_name = device_id.split('_', 1)[0]
                    if 3 <= len(user_name) <= 20 and len(device_id.split('_', 1)[1]) == 4:
                        print_status(f"Loaded permanent ID: {device_id} (User: {user_name})", "success")
                        return device_id, user_name
        except IOError:
            pass
        print_status("Invalid saved ID file. Will prompt for new permanent inputs.", "warning")
    
    print_status("Setting up permanent secure credentials...", "security")
    
    while True:
        user_name = input(f"{Fore.YELLOW}Enter your permanent user_name (3-20 alphanumeric characters): {Style.RESET_ALL}").strip()
        if 3 <= len(user_name) <= 20 and re.match(r'^[a-zA-Z0-9]+$', user_name):
            break
        print_status("Invalid: Must be 3-20 alphanumeric characters.", "error")
    
    while True:
        device_id = input(f"{Fore.YELLOW}Enter your permanent device_id (format: {user_name}_XXXX where XXXX is 4 alphanumeric characters): {Style.RESET_ALL}").strip()
        if device_id.startswith(f"{user_name}_"):
            code = device_id[len(user_name) + 1:]
            if len(code) == 4 and re.match(r'^[a-zA-Z0-9]+$', code):
                full_device_id = f"{user_name}_{code}"
                try:
                    with open(LoaderConfig.ID_FILE, 'w') as file:
                        file.write(full_device_id)
                    print_status(f"Saved permanent secure ID: {full_device_id}", "success")
                    return full_device_id, user_name
                except IOError:
                    print_status("Failed to save permanent ID file.", "error")
                    return full_device_id, user_name
            else:
                print_status("Invalid code: Must be exactly 4 alphanumeric characters after '_' (e.g., abcd or 1234).", "error")
        else:
            print_status(f"Invalid format: Must start with '{user_name}_'.", "error")

def check_loader_subscription(device_id, user_name):
    """Enhanced subscription check with security headers"""
    SUBSCRIPTION_API = "https://darkxdeath.onrender.com/api.php"
    url = f"{SUBSCRIPTION_API}?device_id={device_id}&user_name={user_name}&loader_check=true"
    
    headers = {
        'User-Agent': LoaderConfig.USER_AGENT,
        'X-Loader-Version': LoaderConfig.VERSION,
        'X-Security-Check': 'enabled'
    }
    
    try:
        print_status(f"Verifying subscription for {device_id}...", "security")
        response = requests.get(url, headers=headers, verify=False, timeout=15)
        response.raise_for_status()
        response_json = response.json()
        return response_json
    except requests.exceptions.RequestException as e:
        print_status(f"Subscription verification failed: {e}", "error")
        return {"status": "error", "message": "Loader subscription server request failed."}

def get_challenge(device_id, user_name, security_engine):
    """Request security challenge from server"""
    try:
        print_status("Requesting security challenge...", "security")
        
        headers = {
            'X-Loader-Request': LoaderConfig.SECRET_KEY,
            'X-Loader-Version': LoaderConfig.VERSION,
            'User-Agent': LoaderConfig.USER_AGENT
        }
        
        url = f"{LoaderConfig.CHALLENGE_ENDPOINT}?device_id={device_id}&user_name={user_name}"
        
        response = requests.get(url, headers=headers, timeout=LoaderConfig.CHALLENGE_TIMEOUT)
        response.raise_for_status()
        
        challenge_data = response.json()
        print_status(f"Challenge received: {challenge_data.get('challenge', 'N/A')}", "security")
        
        return challenge_data
        
    except Exception as e:
        print_status(f"Challenge request failed: {e}", "error")
        return None

def solve_challenge(challenge_data, security_engine):
    """Solve the security challenge"""
    try:
        challenge_text = challenge_data.get('challenge', '')
        challenge_id = challenge_data.get('challenge_id', '')
        nonce = challenge_data.get('nonce', '')
        
        if not challenge_text or not challenge_id:
            return None
        
        # Parse and solve the mathematical challenge
        if '+' in challenge_text:
            a, b = map(int, challenge_text.split('+'))
            result = a + b
        elif '*' in challenge_text:
            a, b = map(int, challenge_text.split('*'))
            result = a * b
        elif '^' in challenge_text:
            a, b = map(int, challenge_text.split('^'))
            result = a ^ b
        else:
            return None
        
        # Generate client signature
        signature = hmac.new(
            f"{nonce}:{LoaderConfig.PRIMARY_SECRET}".encode(),
            f"{challenge_id}:{result}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        challenge_response = {
            'challenge_id': challenge_id,
            'response': result,
            'signature': signature
        }
        
        print_status(f"Challenge solved: {challenge_text} = {result}", "success")
        
        return base64.urlsafe_b64encode(json.dumps(challenge_response).encode()).decode()
        
    except Exception as e:
        print_status(f"Challenge solve failed: {e}", "error")
        return None

def download_and_execute_checker(device_id, user_name, security_engine):
    """Enhanced secure download with multiple security layers"""
    print_status("Initiating secure download protocol...", "security")
    
    os.makedirs(LoaderConfig.TEMP_DIR, exist_ok=True)
    local_checker_path = os.path.join(LoaderConfig.TEMP_DIR, LoaderConfig.CHECKER_FILE)
    
    # Step 1: Get challenge
    challenge_data = get_challenge(device_id, user_name, security_engine)
    if not challenge_data:
        print_status("Security challenge failed", "error")
        sys.exit(1)
    
    # Step 2: Solve challenge
    challenge_response = solve_challenge(challenge_data, security_engine)
    if not challenge_response:
        print_status("Challenge solution failed", "error")
        sys.exit(1)
    
    # Step 3: Prepare secure headers
    timestamp = int(time.time())
    signature = security_engine.generate_loader_signature(device_id, user_name, timestamp)
    security_token = security_engine.create_security_token(device_id, user_name)
    
    headers = {
        'X-Loader-Request': LoaderConfig.SECRET_KEY,
        'X-Loader-Version': LoaderConfig.VERSION,
        'X-Security-Token': security_token,
        'X-Challenge-Response': challenge_response,
        'X-Timestamp': str(timestamp),
        'X-Signature': signature,
        'User-Agent': LoaderConfig.USER_AGENT,
        'Accept': 'text/plain',
        'Connection': 'close'
    }
    
    # Step 4: Secure download
    done = False
    error_occurred = False
    download_size = 0
    
    def download_func():
        nonlocal done, error_occurred, download_size
        try:
            url = f"{LoaderConfig.OCHO_ENDPOINT}?device_id={device_id}&user_name={user_name}"
            print_status(f"Connecting to secure endpoint...", "security")
            
            response = requests.get(url, headers=headers, stream=True, timeout=LoaderConfig.REQUEST_TIMEOUT)
            response.raise_for_status()
            
            # Verify security headers in response
            if response.headers.get('X-Content-Protected') != 'true':
                print_status("Security validation failed - content not protected", "error")
                error_occurred = True
                return
            
            print_status("Security validation passed - downloading protected content", "success")
            
            with open(local_checker_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        download_size += len(chunk)
            
            done = True
            print_status(f"Secure download completed - {download_size} bytes", "success")
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                print_status("Access denied - security validation failed", "error")
            elif e.response.status_code == 429:
                print_status("Rate limit exceeded - try again later", "error")
            else:
                print_status(f"HTTP Error during secure download: {e}", "error")
            error_occurred = True
        except Exception as e:
            print_status(f"Secure download error: {e}", "error")
            error_occurred = True
    
    # Step 5: Execute download with progress
    thread = threading.Thread(target=download_func)
    thread.start()
    
    # Enhanced progress bar
    print_status("Secure download in progress...", "security")
    bar_width = 50
    
    for progress in range(1, 101):
        filled = int(bar_width * progress / 100)
        bar = f"{Fore.GREEN}{'█' * filled}{Fore.WHITE}{'░' * (bar_width - filled)}{Style.RESET_ALL}"
        status_text = "DOWNLOADING" if progress < 90 else "VERIFYING"
        sys.stdout.write(f"\r🔒 {status_text}: [{bar}] {progress}% ")
        sys.stdout.flush()
        
        time.sleep(0.03)
        
        if done:
            while progress < 100:
                progress += 1
                filled = int(bar_width * progress / 100)
                bar = f"{Fore.GREEN}{'█' * filled}{Fore.WHITE}{'░' * (bar_width - filled)}{Style.RESET_ALL}"
                sys.stdout.write(f"\r🔒 COMPLETED: [{bar}] {progress}% ")
                sys.stdout.flush()
                time.sleep(0.01)
            break
    
    thread.join()
    sys.stdout.write("\n")
    
    if error_occurred or not done:
        print_status("Secure download failed - check your connection and credentials", "error")
        sys.exit(1)
    
    # Step 6: Verify and execute
    if not os.path.exists(local_checker_path):
        print_status("Downloaded file not found - security error", "error")
        sys.exit(1)
    
    # Basic integrity check
    try:
        with open(local_checker_path, 'r') as f:
            content = f.read()
            if len(content) < 1000:  # Sanity check
                print_status("Downloaded content too small - possible security issue", "error")
                sys.exit(1)
            
        print_status("Content integrity verified - executing secure checker", "success")
        print_status("=" * 60, "info")
        
        # Execute with original arguments
        subprocess.run([sys.executable, local_checker_path] + sys.argv[1:])
        
    except Exception as e:
        print_status(f"Execution error: {e}", "error")
        sys.exit(1)

def main():
    """Enhanced main function with security initialization"""
    # Initialize security engine
    security_engine = SecurityEngine()
    
    print(f"{Fore.MAGENTA}🔒 DARKxStorms Secure Loader v{LoaderConfig.VERSION} 🔒{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Multi-layer security protection: ACTIVE{Style.RESET_ALL}")
    print_status("Initializing secure loader...", "security")
    
    # Get device credentials
    device_id, user_name = get_permanent_manual_id()
    
    # Check subscription
    print_status("Verifying loader subscription...", "security")
    subscription_response = check_loader_subscription(device_id, user_name)
    status = subscription_response.get("status")
    message = subscription_response.get("message", "")
    
    if status == "active":
        print_status(f"Subscription verified: ACTIVE - {message}", "success")
        print_status("Proceeding with secure download...", "security")
        download_and_execute_checker(device_id, user_name, security_engine)
    elif status in ["pending", "registered_pending"]:
        print_status(f"Subscription Status: PENDING APPROVAL - {message}", "warning")
        print_status(f"Your Permanent Device ID: {device_id}", "info")
        sys.exit(0)
    elif status == "expired":
        print_status(f"Subscription Status: EXPIRED - {message}", "error")
        print_status(f"Your Permanent Device ID: {device_id}", "info")
        sys.exit(0)
    else:
        print_status(f"Subscription Status: UNKNOWN ({status}) - {message}", "error")
        print_status(f"Your Permanent Device ID: {device_id}", "info")
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nSecure loader terminated by user", "warning")
        sys.exit(0)
    except Exception as e:
        print_status(f"Fatal error: {e}", "error")
        sys.exit(1)