"""
Security Monitoring and Threat Detection System
Real-time monitoring, anomaly detection, and automated response
"""

import time
import json
import hashlib
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging
import statistics
import re

logger = logging.getLogger(__name__)

class SecurityMonitor:
    def __init__(self):
        self.security_events = deque(maxlen=10000)  # Keep last 10k events
        self.threat_patterns = {}
        self.ip_reputation = defaultdict(lambda: {'score': 0, 'events': []})
        self.attack_signatures = []
        self.monitoring_thread = None
        self.is_monitoring = False
        
        # Threat detection thresholds
        self.thresholds = {
            'failed_auth_per_ip': 10,
            'requests_per_minute': 60,
            'suspicious_ua_patterns': 5,
            'device_inconsistency': 3,
            'rapid_requests': 0.5,  # seconds between requests
            'threat_score_threshold': 50
        }
        
        # Initialize attack signatures
        self._initialize_attack_signatures()
        
    def initialize(self):
        """Initialize security monitor"""
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("Security Monitor initialized - Real-time threat detection active")
        
    def _initialize_attack_signatures(self):
        """Initialize known attack signatures"""
        self.attack_signatures = [
            {
                'name': 'SQL Injection Attempt',
                'pattern': r'(union|select|insert|update|delete|drop|create|alter).*(\s|\/\*|\*\/|--)',
                'severity': 'high',
                'score': 30
            },
            {
                'name': 'XSS Attempt',
                'pattern': r'<script|javascript:|onload=|onerror=|onmouseover=',
                'severity': 'medium',
                'score': 20
            },
            {
                'name': 'Path Traversal',
                'pattern': r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)',
                'severity': 'high',
                'score': 25
            },
            {
                'name': 'Command Injection',
                'pattern': r'(;|\||\&|\$\(|\`)\s*(ls|cat|wget|curl|nc|telnet|ssh)',
                'severity': 'critical',
                'score': 40
            },
            {
                'name': 'Automated Tool',
                'pattern': r'(sqlmap|nmap|nikto|dirb|gobuster|burp|metasploit)',
                'severity': 'high',
                'score': 35
            },
            {
                'name': 'Scanner Bot',
                'pattern': r'(bot|crawler|spider|scanner|python-requests|curl|wget)',
                'severity': 'medium',
                'score': 15
            }
        ]
    
    def log_event(self, event):
        """Log security event for analysis"""
        event['threat_score'] = self._calculate_threat_score(event)
        self.security_events.append(event)
        
        # Update IP reputation
        ip_address = event.get('ip_address')
        if ip_address:
            self.ip_reputation[ip_address]['events'].append(event)
            self.ip_reputation[ip_address]['score'] += event['threat_score']
            
            # Keep only recent events for IP reputation
            cutoff_time = time.time() - 3600  # 1 hour
            self.ip_reputation[ip_address]['events'] = [
                e for e in self.ip_reputation[ip_address]['events']
                if e.get('timestamp') and 
                datetime.fromisoformat(e['timestamp']).timestamp() > cutoff_time
            ]
        
        # Trigger real-time threat detection
        self._analyze_threat_patterns(event)
        
    def _calculate_threat_score(self, event):
        """Calculate threat score for an event"""
        score = 0
        event_type = event.get('event_type', '')
        details = event.get('details', '')
        user_agent = event.get('user_agent', '')
        
        # Base scores for event types
        base_scores = {
            'AUTH_FAILED': 10,
            'RATE_LIMIT_EXCEEDED': 15,
            'INVALID_HEADERS': 8,
            'SUSPICIOUS_REQUEST': 20,
            'DEVICE_VERIFICATION_FAILED': 25,
            'IP_LOCKOUT': 30,
            'ACCESS_BLOCKED': 35,
            'SYSTEM_ERROR': 5
        }
        
        score += base_scores.get(event_type, 5)
        
        # Check for attack signatures in details and user agent
        for signature in self.attack_signatures:
            pattern = signature['pattern']
            text_to_check = f"{details} {user_agent}".lower()
            
            if re.search(pattern, text_to_check, re.IGNORECASE):
                score += signature['score']
                logger.warning(f"Attack signature detected: {signature['name']} - Score: {signature['score']}")
        
        return min(score, 100)  # Cap at 100
    
    def _analyze_threat_patterns(self, event):
        """Analyze event for threat patterns"""
        ip_address = event.get('ip_address')
        event_type = event.get('event_type')
        
        if not ip_address:
            return
        
        # Check for rapid successive events from same IP
        recent_events = [
            e for e in self.security_events
            if e.get('ip_address') == ip_address and
            e.get('timestamp') and
            (datetime.utcnow() - datetime.fromisoformat(e['timestamp'])).total_seconds() < 60
        ]
        
        if len(recent_events) > self.thresholds['requests_per_minute']:
            self._trigger_threat_response('RAPID_REQUESTS', ip_address, {
                'event_count': len(recent_events),
                'time_window': '60 seconds'
            })
        
        # Check for repeated failed authentications
        failed_auth_events = [
            e for e in recent_events
            if e.get('event_type') in ['AUTH_FAILED', 'DEVICE_VERIFICATION_FAILED']
        ]
        
        if len(failed_auth_events) > self.thresholds['failed_auth_per_ip']:
            self._trigger_threat_response('BRUTE_FORCE_ATTACK', ip_address, {
                'failed_attempts': len(failed_auth_events),
                'time_window': '60 seconds'
            })
        
        # Check for suspicious user agent patterns
        suspicious_ua_events = [
            e for e in recent_events
            if any(pattern in e.get('user_agent', '').lower() 
                  for pattern in ['bot', 'crawler', 'python', 'curl', 'wget'])
        ]
        
        if len(suspicious_ua_events) > self.thresholds['suspicious_ua_patterns']:
            self._trigger_threat_response('SUSPICIOUS_USER_AGENT', ip_address, {
                'suspicious_requests': len(suspicious_ua_events)
            })
    
    def _trigger_threat_response(self, threat_type, ip_address, details):
        """Trigger automated threat response"""
        threat_event = {
            'timestamp': datetime.utcnow().isoformat(),
            'threat_type': threat_type,
            'ip_address': ip_address,
            'details': details,
            'auto_generated': True
        }
        
        logger.critical(f"THREAT DETECTED: {threat_type} from {ip_address} - {details}")
        
        # Log the threat event
        self.security_events.append(threat_event)
        
        # Update threat patterns
        if threat_type not in self.threat_patterns:
            self.threat_patterns[threat_type] = []
        
        self.threat_patterns[threat_type].append({
            'timestamp': time.time(),
            'ip_address': ip_address,
            'details': details
        })
        
        # Implement automated response (could include IP blocking, etc.)
        self._execute_threat_response(threat_type, ip_address, details)
    
    def _execute_threat_response(self, threat_type, ip_address, details):
        """Execute automated response to threats"""
        # This could be extended to implement actual blocking mechanisms
        # For now, we'll just log and update reputation scores
        
        if threat_type in ['BRUTE_FORCE_ATTACK', 'RAPID_REQUESTS']:
            self.ip_reputation[ip_address]['score'] += 50
            logger.warning(f"Increased threat score for {ip_address} due to {threat_type}")
        
        elif threat_type == 'SUSPICIOUS_USER_AGENT':
            self.ip_reputation[ip_address]['score'] += 25
        
        # Could implement actual blocking here:
        # - Add IP to firewall rules
        # - Update load balancer to block IP
        # - Send alerts to administrators
        # - Implement CAPTCHA challenges
    
    def is_suspicious_request(self, request, ip_address):
        """Check if request exhibits suspicious patterns"""
        # Check IP reputation
        ip_score = self.ip_reputation[ip_address]['score']
        if ip_score > self.thresholds['threat_score_threshold']:
            return True
        
        # Check user agent
        user_agent = request.headers.get('User-Agent', '').lower()
        suspicious_ua_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'python-requests',
            'curl', 'wget', 'java', 'go-http', 'scanner', 'nikto'
        ]
        
        if any(pattern in user_agent for pattern in suspicious_ua_patterns):
            return True
        
        # Check for missing standard headers
        expected_headers = ['User-Agent', 'Accept', 'Accept-Encoding']
        missing_headers = [h for h in expected_headers if not request.headers.get(h)]
        
        if len(missing_headers) > 1:
            return True
        
        # Check for attack signatures in headers
        for header_name, header_value in request.headers.items():
            for signature in self.attack_signatures:
                if re.search(signature['pattern'], header_value, re.IGNORECASE):
                    logger.warning(f"Attack signature in header {header_name}: {signature['name']}")
                    return True
        
        # Check request timing patterns
        recent_requests = [
            e for e in self.security_events
            if e.get('ip_address') == ip_address and
            e.get('timestamp') and
            (datetime.utcnow() - datetime.fromisoformat(e['timestamp'])).total_seconds() < 60
        ]
        
        if len(recent_requests) >= 2:
            # Check if requests are too rapid
            timestamps = [
                datetime.fromisoformat(e['timestamp']).timestamp() 
                for e in recent_requests[-2:]
            ]
            if len(timestamps) >= 2 and timestamps[-1] - timestamps[-2] < self.thresholds['rapid_requests']:
                return True
        
        return False
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Perform periodic security checks
                self._cleanup_old_data()
                self._analyze_global_patterns()
                self._update_threat_intelligence()
                
                # Sleep for 30 seconds before next check
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)  # Short sleep on error
    
    def _cleanup_old_data(self):
        """Clean up old monitoring data"""
        current_time = time.time()
        cutoff_time = current_time - 86400  # 24 hours
        
        # Clean IP reputation events
        for ip in list(self.ip_reputation.keys()):
            ip_data = self.ip_reputation[ip]
            ip_data['events'] = [
                e for e in ip_data['events']
                if e.get('timestamp') and 
                datetime.fromisoformat(e['timestamp']).timestamp() > cutoff_time
            ]
            
            # Decay reputation score over time
            if not ip_data['events']:
                ip_data['score'] = max(0, ip_data['score'] - 1)
            
            # Remove IPs with no recent activity and low score
            if not ip_data['events'] and ip_data['score'] <= 0:
                del self.ip_reputation[ip]
        
        # Clean threat patterns
        for threat_type in list(self.threat_patterns.keys()):
            self.threat_patterns[threat_type] = [
                pattern for pattern in self.threat_patterns[threat_type]
                if current_time - pattern['timestamp'] < 86400
            ]
            
            if not self.threat_patterns[threat_type]:
                del self.threat_patterns[threat_type]
    
    def _analyze_global_patterns(self):
        """Analyze global attack patterns"""
        current_time = time.time()
        recent_events = [
            e for e in self.security_events
            if e.get('timestamp') and
            (current_time - datetime.fromisoformat(e['timestamp']).timestamp()) < 3600
        ]
        
        if not recent_events:
            return
        
        # Analyze event distribution
        event_types = defaultdict(int)
        threat_scores = []
        
        for event in recent_events:
            event_types[event.get('event_type', 'unknown')] += 1
            threat_scores.append(event.get('threat_score', 0))
        
        # Calculate statistics
        if threat_scores:
            avg_threat_score = statistics.mean(threat_scores)
            max_threat_score = max(threat_scores)
            
            # Alert on high average threat score
            if avg_threat_score > 20:
                logger.warning(f"High average threat score detected: {avg_threat_score:.2f}")
            
            # Alert on very high individual threat scores
            if max_threat_score > 80:
                logger.critical(f"Critical threat score detected: {max_threat_score}")
    
    def _update_threat_intelligence(self):
        """Update threat intelligence based on observed patterns"""
        # This could be extended to:
        # - Update attack signatures based on observed patterns
        # - Fetch external threat intelligence
        # - Update reputation databases
        # - Adjust detection thresholds
        pass
    
    def get_security_dashboard(self):
        """Get security dashboard data"""
        current_time = time.time()
        
        # Recent events (last hour)
        recent_events = [
            e for e in self.security_events
            if e.get('timestamp') and
            (current_time - datetime.fromisoformat(e['timestamp']).timestamp()) < 3600
        ]
        
        # Event type distribution
        event_distribution = defaultdict(int)
        threat_scores = []
        
        for event in recent_events:
            event_distribution[event.get('event_type', 'unknown')] += 1
            threat_scores.append(event.get('threat_score', 0))
        
        # Top threat IPs
        ip_scores = [
            (ip, data['score']) for ip, data in self.ip_reputation.items()
            if data['score'] > 0
        ]
        ip_scores.sort(key=lambda x: x[1], reverse=True)
        top_threat_ips = ip_scores[:10]
        
        return {
            'total_events': len(self.security_events),
            'recent_events_1h': len(recent_events),
            'event_distribution': dict(event_distribution),
            'average_threat_score': statistics.mean(threat_scores) if threat_scores else 0,
            'max_threat_score': max(threat_scores) if threat_scores else 0,
            'top_threat_ips': top_threat_ips,
            'active_threat_patterns': len(self.threat_patterns),
            'monitored_ips': len(self.ip_reputation),
            'monitoring_status': 'active' if self.is_monitoring else 'inactive'
        }
    
    def get_ip_reputation(self, ip_address):
        """Get reputation information for specific IP"""
        if ip_address not in self.ip_reputation:
            return {'score': 0, 'events': [], 'threat_level': 'clean'}
        
        ip_data = self.ip_reputation[ip_address]
        score = ip_data['score']
        
        # Determine threat level
        if score <= 10:
            threat_level = 'clean'
        elif score <= 30:
            threat_level = 'low'
        elif score <= 50:
            threat_level = 'medium'
        elif score <= 80:
            threat_level = 'high'
        else:
            threat_level = 'critical'
        
        return {
            'ip_address': ip_address,
            'score': score,
            'threat_level': threat_level,
            'event_count': len(ip_data['events']),
            'recent_events': ip_data['events'][-5:] if ip_data['events'] else []
        }
    
    def stop_monitoring(self):
        """Stop security monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        logger.info("Security monitoring stopped")
    
    def export_security_logs(self, time_range_hours=24):
        """Export security logs for analysis"""
        cutoff_time = time.time() - (time_range_hours * 3600)
        
        filtered_events = [
            e for e in self.security_events
            if e.get('timestamp') and
            datetime.fromisoformat(e['timestamp']).timestamp() > cutoff_time
        ]
        
        return {
            'export_timestamp': datetime.utcnow().isoformat(),
            'time_range_hours': time_range_hours,
            'event_count': len(filtered_events),
            'events': filtered_events,
            'threat_patterns': dict(self.threat_patterns),
            'ip_reputation': dict(self.ip_reputation)
        }