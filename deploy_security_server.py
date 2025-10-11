"""
Deployment script for DARKxStorms Security Server
Automated setup and deployment with security hardening
"""

import os
import sys
import subprocess
import shutil
import secrets
import argparse
from pathlib import Path

class SecurityServerDeployer:
    def __init__(self, environment='production'):
        self.environment = environment
        self.base_dir = Path(__file__).parent
        self.server_dir = self.base_dir / 'secure_server'
        self.requirements_file = self.base_dir / 'requirements.txt'
        
    def print_status(self, message, status_type="info"):
        """Print deployment status"""
        colors = {
            'info': '\033[94m',
            'success': '\033[92m',
            'warning': '\033[93m',
            'error': '\033[91m',
            'reset': '\033[0m'
        }
        
        color = colors.get(status_type, colors['info'])
        print(f"{color}[DEPLOY] {message}{colors['reset']}")
    
    def check_requirements(self):
        """Check system requirements"""
        self.print_status("Checking system requirements...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            self.print_status("Python 3.8+ required", "error")
            return False
        
        # Check required files
        required_files = [
            'secure_server/app.py',
            'secure_server/auth_manager.py',
            'secure_server/code_protector.py',
            'secure_server/device_manager.py',
            'secure_server/security_monitor.py',
            'secure_server/config.py',
            'ocho.py',
            'requirements.txt'
        ]
        
        missing_files = []
        for file_path in required_files:
            if not (self.base_dir / file_path).exists():
                missing_files.append(file_path)
        
        if missing_files:
            self.print_status(f"Missing required files: {', '.join(missing_files)}", "error")
            return False
        
        self.print_status("System requirements check passed", "success")
        return True
    
    def install_dependencies(self):
        """Install Python dependencies"""
        self.print_status("Installing dependencies...")
        
        try:
            subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', str(self.requirements_file)
            ], check=True, capture_output=True, text=True)
            
            self.print_status("Dependencies installed successfully", "success")
            return True
            
        except subprocess.CalledProcessError as e:
            self.print_status(f"Failed to install dependencies: {e}", "error")
            return False
    
    def generate_security_keys(self):
        """Generate secure keys and configuration"""
        self.print_status("Generating security keys...")
        
        # Generate environment file
        env_file = self.base_dir / '.env'
        
        env_content = f"""# DARKxStorms Security Server Configuration
ENVIRONMENT={self.environment}
SECRET_KEY={secrets.token_hex(32)}
JWT_SECRET_KEY={secrets.token_hex(32)}
DEBUG={'True' if self.environment == 'development' else 'False'}
SSL_ENABLED={'False' if self.environment == 'development' else 'True'}
PORT=8000

# Security Settings
MAX_REQUESTS_PER_HOUR={'100' if self.environment == 'development' else '30'}
LOCKOUT_DURATION={'60' if self.environment == 'development' else '600'}
THREAT_SCORE_THRESHOLD={'50' if self.environment == 'development' else '30'}

# Logging
LOG_LEVEL=INFO
LOG_FILE=security.log

# Optional: Database URL for session storage
# DATABASE_URL=sqlite:///security.db

# Optional: SSL Certificate paths (for production)
# SSL_CERT_PATH=/path/to/cert.pem
# SSL_KEY_PATH=/path/to/key.pem

# Optional: Allowed CORS origins
# ALLOWED_ORIGINS=https://yourdomain.com,https://api.yourdomain.com
"""
        
        try:
            with open(env_file, 'w') as f:
                f.write(env_content)
            
            # Set restrictive permissions
            os.chmod(env_file, 0o600)
            
            self.print_status("Security keys generated", "success")
            return True
            
        except Exception as e:
            self.print_status(f"Failed to generate keys: {e}", "error")
            return False
    
    def setup_directories(self):
        """Setup required directories with proper permissions"""
        self.print_status("Setting up directories...")
        
        directories = [
            'logs',
            'data',
            'backups',
            'temp'
        ]
        
        for directory in directories:
            dir_path = self.base_dir / directory
            dir_path.mkdir(exist_ok=True, mode=0o750)
        
        self.print_status("Directories setup completed", "success")
        return True
    
    def create_startup_script(self):
        """Create startup script for the security server"""
        self.print_status("Creating startup script...")
        
        if os.name == 'nt':  # Windows
            script_name = 'start_security_server.bat'
            script_content = f"""@echo off
echo Starting DARKxStorms Security Server...
cd /d "{self.base_dir}"
set PYTHONPATH={self.base_dir}
python -m secure_server.app
pause
"""
        else:  # Unix/Linux
            script_name = 'start_security_server.sh'
            script_content = f"""#!/bin/bash
echo "Starting DARKxStorms Security Server..."
cd "{self.base_dir}"
export PYTHONPATH="{self.base_dir}"

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Start server
python -m secure_server.app
"""
        
        script_path = self.base_dir / script_name
        
        try:
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            if os.name != 'nt':
                os.chmod(script_path, 0o755)
            
            self.print_status(f"Startup script created: {script_name}", "success")
            return True
            
        except Exception as e:
            self.print_status(f"Failed to create startup script: {e}", "error")
            return False
    
    def create_systemd_service(self):
        """Create systemd service file for Linux"""
        if os.name == 'nt':
            return True  # Skip on Windows
        
        self.print_status("Creating systemd service file...")
        
        service_content = f"""[Unit]
Description=DARKxStorms Security Server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory={self.base_dir}
Environment=PYTHONPATH={self.base_dir}
EnvironmentFile={self.base_dir}/.env
ExecStart=/usr/bin/python3 -m secure_server.app
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
        
        service_file = self.base_dir / 'darkxstorms-security.service'
        
        try:
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            self.print_status("Systemd service file created: darkxstorms-security.service", "success")
            self.print_status("To install: sudo cp darkxstorms-security.service /etc/systemd/system/", "info")
            self.print_status("Then run: sudo systemctl enable darkxstorms-security", "info")
            self.print_status("Start with: sudo systemctl start darkxstorms-security", "info")
            return True
            
        except Exception as e:
            self.print_status(f"Failed to create systemd service: {e}", "error")
            return False
    
    def create_nginx_config(self):
        """Create nginx reverse proxy configuration"""
        self.print_status("Creating nginx configuration...")
        
        nginx_config = f"""# DARKxStorms Security Server - Nginx Configuration
server {{
    listen 80;
    listen [::]:80;
    server_name your-domain.com;  # Replace with your domain
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}}

server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name your-domain.com;  # Replace with your domain
    
    # SSL Configuration
    ssl_certificate /path/to/your/certificate.pem;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header Content-Security-Policy "default-src 'self'";
    
    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;
    limit_req zone=api burst=5 nodelay;
    
    # Proxy to Security Server
    location / {{
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Security
        proxy_hide_header X-Powered-By;
        proxy_set_header X-Forwarded-Proto https;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }}
    
    # Block common attack vectors
    location ~ /\\.ht {{
        deny all;
    }}
    
    location ~ /\\. {{
        deny all;
    }}
}}
"""
        
        nginx_file = self.base_dir / 'darkxstorms-nginx.conf'
        
        try:
            with open(nginx_file, 'w') as f:
                f.write(nginx_config)
            
            self.print_status("Nginx configuration created: darkxstorms-nginx.conf", "success")
            self.print_status("Copy to /etc/nginx/sites-available/ and enable", "info")
            return True
            
        except Exception as e:
            self.print_status(f"Failed to create nginx config: {e}", "error")
            return False
    
    def run_security_tests(self):
        """Run basic security tests"""
        self.print_status("Running security tests...")
        
        try:
            # Test imports
            sys.path.insert(0, str(self.base_dir))
            
            from secure_server.config import SecurityConfig
            from secure_server.auth_manager import AuthManager
            from secure_server.code_protector import CodeProtector
            from secure_server.device_manager import DeviceManager
            from secure_server.security_monitor import SecurityMonitor
            
            # Validate configuration
            config_issues = SecurityConfig.validate_config()
            if config_issues:
                for issue in config_issues:
                    self.print_status(f"Config warning: {issue}", "warning")
            
            self.print_status("Security tests passed", "success")
            return True
            
        except Exception as e:
            self.print_status(f"Security tests failed: {e}", "error")
            return False
    
    def deploy(self):
        """Run full deployment process"""
        self.print_status(f"Starting deployment for {self.environment} environment", "info")
        print("=" * 60)
        
        steps = [
            ("Check requirements", self.check_requirements),
            ("Install dependencies", self.install_dependencies),
            ("Generate security keys", self.generate_security_keys),
            ("Setup directories", self.setup_directories),
            ("Create startup script", self.create_startup_script),
            ("Create systemd service", self.create_systemd_service),
            ("Create nginx config", self.create_nginx_config),
            ("Run security tests", self.run_security_tests)
        ]
        
        failed_steps = []
        
        for step_name, step_func in steps:
            self.print_status(f"Executing: {step_name}...")
            if not step_func():
                failed_steps.append(step_name)
                if step_name in ["Check requirements", "Install dependencies", "Run security tests"]:
                    self.print_status(f"Critical step failed: {step_name}", "error")
                    break
        
        print("=" * 60)
        
        if not failed_steps:
            self.print_status("🎉 Deployment completed successfully!", "success")
            self.print_deployment_summary()
            return True
        else:
            self.print_status(f"⚠️  Deployment completed with issues: {', '.join(failed_steps)}", "warning")
            self.print_deployment_summary()
            return False
    
    def print_deployment_summary(self):
        """Print deployment summary"""
        print("\\n" + "=" * 60)
        print("DEPLOYMENT SUMMARY")
        print("=" * 60)
        print(f"Environment: {self.environment}")
        print(f"Base directory: {self.base_dir}")
        print(f"Configuration file: {self.base_dir}/.env")
        print(f"Startup script: {self.base_dir}/start_security_server.*")
        
        print("\\nNEXT STEPS:")
        print("1. Review and modify .env file as needed")
        print("2. Update domain names in nginx configuration")
        print("3. Install SSL certificates for production")
        print("4. Run the startup script to test the server")
        print("5. For production: install systemd service and nginx config")
        
        print("\\nSTARTING THE SERVER:")
        if os.name == 'nt':
            print("  Windows: run start_security_server.bat")
        else:
            print("  Linux/Mac: ./start_security_server.sh")
        
        print("\\nSECURITY NOTES:")
        print("- Keep the .env file secure (already set to 600 permissions)")
        print("- Use HTTPS in production")
        print("- Monitor security logs regularly")
        print("- Update dependencies regularly")
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description="Deploy DARKxStorms Security Server")
    parser.add_argument(
        '--environment', 
        choices=['development', 'production', 'testing'], 
        default='production',
        help='Deployment environment'
    )
    
    args = parser.parse_args()
    
    deployer = SecurityServerDeployer(args.environment)
    success = deployer.deploy()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()