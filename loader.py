#!/usr/bin/env python3
"""
OCHOxDARK Secure Loader Client
Advanced Security Client for Accessing Protected ocho.py
"""

import os
import sys
import json
import time
import hashlib
import secrets
import platform
import requests
import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any
import colorama
from colorama import Fore, Style

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

class SecurityClient:
    """Secure client for accessing protected resources"""
    
    def __init__(self):
        # Server configuration
        self.SERVER_URL = "http://localhost:5000"  # Change this to your server URL
        self.SECRET_KEY = "KUPAL"  # Must match server's SECRET_KEY
        
        # Security settings
        self.ENABLE_REQUEST_SIGNATURES = True  # Set to False to disable signatures
        self.MAX_RETRY_ATTEMPTS = 3
        self.REQUEST_TIMEOUT = 30
        
        # Session data
        self.device_id = None
        self.user_name = None
        self.device_token = None
        self.session_id = None
        
        # Setup logging
        self.setup_logging()
        
        # Initialize device information
        self.initialize_device_info()
    
    def setup_logging(self):
        """Setup colored logging for the client"""
        class ColoredFormatter(logging.Formatter):
            COLORS = {
                'DEBUG': Fore.BLUE,
                'INFO': Fore.GREEN,
                'WARNING': Fore.YELLOW,
                'ERROR': Fore.RED,
                'CRITICAL': Fore.RED + Style.BRIGHT,
            }
            
            def format(self, record):
                levelname = record.levelname
                if levelname in self.COLORS:
                    record.msg = f"{self.COLORS[levelname]}{record.msg}{Style.RESET_ALL}"
                return super().format(record)
        
        self.logger = logging.getLogger('SecurityClient')
        handler = logging.StreamHandler()
        handler.setFormatter(ColoredFormatter())
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def initialize_device_info(self):
        """Initialize device identification information"""
        try:
            # Try to load existing device info
            device_info = self.load_device_info()
            
            if device_info:
                self.device_id = device_info['device_id']
                self.user_name = device_info['user_name']
                self.logger.info(f"Loaded existing device info: {self.device_id}")
            else:
                # Create new device info
                self.create_device_info()
                
        except Exception as e:
            self.logger.error(f"Error initializing device info: {e}")
            sys.exit(1)
    
    def load_device_info(self) -> Optional[Dict]:
        """Load existing device information"""
        try:
            device_dir = Path.home() / ".dont_delete_me"
            device_file = device_dir / "here.txt"
            
            if device_file.exists():
                with open(device_file, 'r') as f:
                    content = f.read().strip()
                    if content and '_' in content:
                        parts = content.split('_', 1)
                        return {
                            'device_id': content,
                            'user_name': parts[0]
                        }
            return None
            
        except Exception as e:
            self.logger.error(f"Error loading device info: {e}")
            return None
    
    def create_device_info(self):
        """Create new device identification"""
        try:
            device_dir = Path.home() / ".dont_delete_me"
            device_dir.mkdir(exist_ok=True)
            
            # Get user name
            while True:
                user_name = input(f"{Fore.YELLOW}Enter your name (3-20 characters): {Style.RESET_ALL}").strip()
                if 3 <= len(user_name) <= 20:
                    break
                print(f"{Fore.RED}Name must be between 3 and 20 characters.{Style.RESET_ALL}")
            
            # Generate device hash based on system information
            system_info = [
                platform.system(),
                platform.release(),
                platform.version(),
                platform.machine(),
                platform.processor()
            ]
            
            hardware_string = "-".join(system_info)
            device_hash = hashlib.sha256(hardware_string.encode()).hexdigest()[:8]
            device_id = f"{user_name}_{device_hash}"
            
            # Save device info
            device_file = device_dir / "here.txt"
            with open(device_file, 'w') as f:
                f.write(device_id)
            
            self.device_id = device_id
            self.user_name = user_name
            
            self.logger.info(f"Created new device ID: {device_id}")
            
        except Exception as e:
            self.logger.error(f"Error creating device info: {e}")
            sys.exit(1)
    
    def generate_device_fingerprint(self) -> str:
        """Generate device fingerprint for additional security"""
        try:
            system_info = [
                platform.system(),
                platform.release(),
                platform.version(),
                platform.machine(),
                platform.processor(),
                str(os.cpu_count()),
            ]
            
            # Try to get additional hardware info
            try:
                # Get disk info
                import shutil
                total, used, free = shutil.disk_usage("/")
                system_info.append(str(total))
            except:
                pass
            
            fingerprint_string = "|".join(system_info)
            fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
            
            return fingerprint_hash[:16]  # Use first 16 chars
            
        except Exception as e:
            self.logger.warning(f"Error generating device fingerprint: {e}")
            return "unknown_device"
    
    def generate_request_signature(self, device_id: str, timestamp: str, nonce: str, data: str = "") -> str:
        """Generate HMAC signature for request validation"""
        try:
            import hmac
            message = f"{device_id}:{timestamp}:{nonce}:{data}"
            signature = hmac.new(
                self.SECRET_KEY.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            return signature
        except Exception as e:
            self.logger.error(f"Error generating signature: {e}")
            return ""
    
    def make_secure_request(self, method: str, endpoint: str, data: Optional[Dict] = None, 
                          params: Optional[Dict] = None) -> requests.Response:
        """Make a secure request with all required headers"""
        try:
            url = f"{self.SERVER_URL}{endpoint}"
            
            # Base headers
            headers = {
                'X-Loader-Request': self.SECRET_KEY,
                'User-Agent': 'OCHOxDARK-Loader/2.0',
                'X-Client-Version': '2.0'
            }
            
            # Add device token if available
            if self.device_token:
                headers['X-Device-Token'] = self.device_token
            
            # Add request signature if enabled
            if self.ENABLE_REQUEST_SIGNATURES:
                timestamp = datetime.utcnow().isoformat()
                nonce = secrets.token_hex(16)
                
                signature = self.generate_request_signature(
                    self.device_id, timestamp, nonce, json.dumps(data or {})
                )
                
                headers.update({
                    'X-Request-Signature': signature,
                    'X-Request-Timestamp': timestamp,
                    'X-Request-Nonce': nonce
                })
            
            # Make request
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=self.REQUEST_TIMEOUT)
            elif method.upper() == 'POST':
                headers['Content-Type'] = 'application/json'
                response = requests.post(url, headers=headers, json=data, params=params, timeout=self.REQUEST_TIMEOUT)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error making secure request: {e}")
            raise
    
    def authenticate_device(self) -> bool:
        """Authenticate device and get access token"""
        try:
            self.logger.info(f"Authenticating device: {self.device_id}")
            
            # Prepare authentication data
            auth_data = {
                'device_id': self.device_id,
                'user_name': self.user_name,
                'device_fingerprint': self.generate_device_fingerprint()
            }
            
            # Make authentication request
            response = self.make_secure_request('POST', '/auth/token', data=auth_data)
            
            if response.status_code == 200:
                auth_result = response.json()
                if auth_result.get('success'):
                    self.device_token = auth_result['token']
                    self.session_id = auth_result['session_id']
                    
                    self.logger.info(f"{Fore.GREEN}✅ Device authenticated successfully!{Style.RESET_ALL}")
                    self.logger.info(f"Session ID: {self.session_id}")
                    return True
                else:
                    self.logger.error(f"Authentication failed: {auth_result.get('error', 'Unknown error')}")
                    return False
            else:
                self.logger.error(f"Authentication request failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error during authentication: {e}")
            return False
    
    def download_ocho_file(self) -> Optional[str]:
        """Download ocho.py file from server"""
        try:
            self.logger.info("Requesting ocho.py file...")
            
            # Prepare request parameters
            params = {
                'device_id': self.device_id,
                'user_name': self.user_name
            }
            
            # Make request for ocho.py file
            response = self.make_secure_request('GET', '/ocho.py', params=params)
            
            if response.status_code == 200:
                content = response.text
                
                # Verify content looks like Python code
                if content.strip().startswith('import ') or 'def ' in content:
                    self.logger.info(f"{Fore.GREEN}✅ ocho.py downloaded successfully!{Style.RESET_ALL}")
                    
                    # Log security headers received
                    security_level = response.headers.get('X-Security-Level', 'unknown')
                    served_at = response.headers.get('X-Served-At', 'unknown')
                    
                    self.logger.info(f"Security Level: {security_level}")
                    self.logger.info(f"Content served at: {served_at}")
                    
                    return content
                else:
                    self.logger.error("Downloaded content doesn't appear to be valid Python code")
                    return None
            else:
                error_data = {}
                try:
                    error_data = response.json()
                except:
                    pass
                
                error_message = error_data.get('error', response.text)
                self.logger.error(f"Failed to download ocho.py: {response.status_code} - {error_message}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error downloading ocho.py: {e}")
            return None
    
    def save_and_execute_ocho(self, content: str) -> bool:
        """Save ocho.py content and execute it"""
        try:
            # Save to temporary file
            temp_file = Path("ocho_temp.py")
            
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.logger.info(f"Saved ocho.py to {temp_file}")
            
            # Execute the file
            self.logger.info(f"{Fore.CYAN}🚀 Executing ocho.py...{Style.RESET_ALL}")
            print("=" * 70)
            
            # Execute with current Python interpreter
            result = subprocess.run([sys.executable, str(temp_file)], 
                                  capture_output=False, 
                                  text=True)
            
            print("=" * 70)
            
            # Clean up temporary file
            try:
                temp_file.unlink()
                self.logger.info("Cleaned up temporary file")
            except Exception as e:
                self.logger.warning(f"Could not clean up temporary file: {e}")
            
            if result.returncode == 0:
                self.logger.info(f"{Fore.GREEN}✅ ocho.py executed successfully!{Style.RESET_ALL}")
                return True
            else:
                self.logger.error(f"ocho.py execution failed with return code: {result.returncode}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error saving/executing ocho.py: {e}")
            return False
    
    def check_server_status(self) -> bool:
        """Check if server is accessible"""
        try:
            self.logger.info("Checking server status...")
            response = requests.get(f"{self.SERVER_URL}/", timeout=10)
            
            if response.status_code == 200:
                self.logger.info(f"{Fore.GREEN}✅ Server is accessible{Style.RESET_ALL}")
                return True
            else:
                self.logger.error(f"Server returned status code: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Cannot reach server: {e}")
            return False
    
    def run(self) -> bool:
        """Main execution flow"""
        try:
            print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}🔒 OCHOxDARK Secure Loader v2.0{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
            
            # Check server accessibility
            if not self.check_server_status():
                self.logger.error("Cannot connect to server. Please check your connection and server URL.")
                return False
            
            # Authentication with retry logic
            auth_success = False
            for attempt in range(self.MAX_RETRY_ATTEMPTS):
                self.logger.info(f"Authentication attempt {attempt + 1}/{self.MAX_RETRY_ATTEMPTS}")
                
                if self.authenticate_device():
                    auth_success = True
                    break
                else:
                    if attempt < self.MAX_RETRY_ATTEMPTS - 1:
                        wait_time = (attempt + 1) * 2  # Exponential backoff
                        self.logger.info(f"Waiting {wait_time} seconds before retry...")
                        time.sleep(wait_time)
            
            if not auth_success:
                self.logger.error("Authentication failed after all attempts")
                return False
            
            # Download ocho.py file
            ocho_content = self.download_ocho_file()
            if not ocho_content:
                self.logger.error("Failed to download ocho.py")
                return False
            
            # Execute ocho.py
            if not self.save_and_execute_ocho(ocho_content):
                self.logger.error("Failed to execute ocho.py")
                return False
            
            return True
            
        except KeyboardInterrupt:
            self.logger.info(f"{Fore.YELLOW}Operation cancelled by user{Style.RESET_ALL}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            return False

def main():
    """Main entry point"""
    try:
        client = SecurityClient()
        
        # Display configuration
        print(f"{Fore.YELLOW}Configuration:{Style.RESET_ALL}")
        print(f"  Server URL: {client.SERVER_URL}")
        print(f"  Device ID: {client.device_id}")
        print(f"  Request Signatures: {client.ENABLE_REQUEST_SIGNATURES}")
        print(f"  Max Retries: {client.MAX_RETRY_ATTEMPTS}")
        print()
        
        # Run the client
        success = client.run()
        
        if success:
            print(f"{Fore.GREEN}{'=' * 70}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}✅ Operation completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'=' * 70}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}{'=' * 70}{Style.RESET_ALL}")
            print(f"{Fore.RED}❌ Operation failed!{Style.RESET_ALL}")
            print(f"{Fore.RED}{'=' * 70}{Style.RESET_ALL}")
            sys.exit(1)
            
    except Exception as e:
        print(f"{Fore.RED}Critical error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()