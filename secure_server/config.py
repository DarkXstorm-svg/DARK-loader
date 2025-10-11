"""
Security Configuration for DARKxStorms Protection System
Centralized security settings and constants
"""

import os
import secrets
from datetime import timedelta

class SecurityConfig:
    """Security configuration class"""
    
    # Server Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)
    
    # Rate Limiting
    MAX_REQUESTS_PER_HOUR = 50
    MAX_REQUESTS_PER_MINUTE = 10
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = 300  # 5 minutes
    
    # Device Management
    MAX_DEVICES_PER_IP = 5
    MAX_SESSIONS_PER_DEVICE = 3
    DEVICE_FINGERPRINT_CACHE_TIME = 3600  # 1 hour
    
    # Code Protection
    CODE_ENCRYPTION_KEY_ROTATION = 3600  # 1 hour
    OBFUSCATION_CACHE_TIME = 300  # 5 minutes
    MAX_CODE_SIZE = 10 * 1024 * 1024  # 10MB
    
    # Security Thresholds
    THREAT_SCORE_THRESHOLD = 50
    SUSPICIOUS_REQUEST_THRESHOLD = 3
    RAPID_REQUEST_THRESHOLD = 0.5  # seconds
    
    # Monitoring
    SECURITY_LOG_RETENTION = 86400 * 7  # 7 days
    EVENT_BUFFER_SIZE = 10000
    CLEANUP_INTERVAL = 3600  # 1 hour
    
    # External APIs
    SUBSCRIPTION_API_URL = "https://darkxdeath.onrender.com/api.php"
    SUBSCRIPTION_API_TIMEOUT = 15
    SUBSCRIPTION_CACHE_TIME = 300  # 5 minutes
    
    # SSL/TLS Configuration
    SSL_ENABLED = os.environ.get('SSL_ENABLED', 'False').lower() == 'true'
    SSL_CERT_PATH = os.environ.get('SSL_CERT_PATH')
    SSL_KEY_PATH = os.environ.get('SSL_KEY_PATH')
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
    
    # Allowed User Agents
    ALLOWED_USER_AGENT_PATTERNS = [
        r'Mozilla/5\.0.*Chrome.*Safari',
        r'DARKxStorms-.*Loader',
        r'DARKxStorms-Enhanced-Loader'
    ]
    
    # Attack Signatures
    ATTACK_PATTERNS = {
        'sql_injection': r'(union|select|insert|update|delete|drop|create|alter).*(\s|\/\*|\*\/|--)',
        'xss_attempt': r'<script|javascript:|onload=|onerror=|onmouseover=',
        'path_traversal': r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)',
        'command_injection': r'(;|\||\&|\$\(|\`)\s*(ls|cat|wget|curl|nc|telnet|ssh)',
        'automated_tool': r'(sqlmap|nmap|nikto|dirb|gobuster|burp|metasploit)',
        'scanner_bot': r'(bot|crawler|spider|scanner|python-requests|curl|wget)'
    }
    
    # Threat Scoring
    THREAT_SCORES = {
        'AUTH_FAILED': 10,
        'RATE_LIMIT_EXCEEDED': 15,
        'INVALID_HEADERS': 8,
        'SUSPICIOUS_REQUEST': 20,
        'DEVICE_VERIFICATION_FAILED': 25,
        'IP_LOCKOUT': 30,
        'ACCESS_BLOCKED': 35,
        'SYSTEM_ERROR': 5,
        'SQL_INJECTION': 30,
        'XSS_ATTEMPT': 20,
        'PATH_TRAVERSAL': 25,
        'COMMAND_INJECTION': 40,
        'AUTOMATED_TOOL': 35,
        'SCANNER_BOT': 15
    }
    
    @classmethod
    def get_database_url(cls):
        """Get database URL for session storage (if needed)"""
        return os.environ.get('DATABASE_URL', 'sqlite:///security.db')
    
    @classmethod
    def is_debug_mode(cls):
        """Check if debug mode is enabled"""
        return os.environ.get('DEBUG', 'False').lower() == 'true'
    
    @classmethod
    def get_allowed_origins(cls):
        """Get allowed CORS origins"""
        origins = os.environ.get('ALLOWED_ORIGINS', '')
        return [origin.strip() for origin in origins.split(',') if origin.strip()]
    
    @classmethod
    def validate_config(cls):
        """Validate security configuration"""
        issues = []
        
        # Check critical security settings
        if len(cls.SECRET_KEY) < 32:
            issues.append("SECRET_KEY is too short (minimum 32 characters)")
        
        if len(cls.JWT_SECRET_KEY) < 32:
            issues.append("JWT_SECRET_KEY is too short (minimum 32 characters)")
        
        if cls.MAX_REQUESTS_PER_HOUR > 100:
            issues.append("MAX_REQUESTS_PER_HOUR is too high (security risk)")
        
        if cls.LOCKOUT_DURATION < 60:
            issues.append("LOCKOUT_DURATION is too short (minimum 60 seconds)")
        
        if cls.THREAT_SCORE_THRESHOLD > 80:
            issues.append("THREAT_SCORE_THRESHOLD is too high")
        
        # SSL checks for production
        if not cls.is_debug_mode() and not cls.SSL_ENABLED:
            issues.append("SSL should be enabled in production")
        
        return issues

# Environment-specific configurations
class DevelopmentConfig(SecurityConfig):
    """Development environment configuration"""
    MAX_REQUESTS_PER_HOUR = 100
    LOCKOUT_DURATION = 60
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=4)

class ProductionConfig(SecurityConfig):
    """Production environment configuration"""
    MAX_REQUESTS_PER_HOUR = 30
    LOCKOUT_DURATION = 600  # 10 minutes
    THREAT_SCORE_THRESHOLD = 30
    MAX_FAILED_ATTEMPTS = 3

class TestingConfig(SecurityConfig):
    """Testing environment configuration"""
    MAX_REQUESTS_PER_HOUR = 200
    LOCKOUT_DURATION = 30
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)

# Configuration factory
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': SecurityConfig
}

def get_config(environment=None):
    """Get configuration for specific environment"""
    if environment is None:
        environment = os.environ.get('ENVIRONMENT', 'default')
    
    return config_map.get(environment, SecurityConfig)