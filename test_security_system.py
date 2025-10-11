#!/usr/bin/env python3
"""
Security System Test Suite
Basic functionality testing for the DARKxStorms protection system
"""

import os
import sys
import time
import json
import hashlib
from pathlib import Path

def test_file_integrity():
    """Test that all security files are present and valid"""
    print("🔍 Testing file integrity...")
    
    required_files = {
        'secure_server/app.py': 'Main security server',
        'secure_server/auth_manager.py': 'Authentication system',
        'secure_server/code_protector.py': 'Code protection system',
        'secure_server/device_manager.py': 'Device management',
        'secure_server/security_monitor.py': 'Security monitoring',
        'secure_server/config.py': 'Security configuration',
        'enhanced_loader.py': 'Enhanced loader',
        'deploy_security_server.py': 'Deployment script',
        'ocho.py': 'Original protected code'
    }
    
    results = {}
    
    for file_path, description in required_files.items():
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Calculate hash
            file_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
            
            results[file_path] = {
                'exists': True,
                'size': file_size,
                'hash': file_hash,
                'description': description
            }
            print(f"  ✅ {file_path} - {file_size} bytes - {description}")
        else:
            results[file_path] = {
                'exists': False,
                'description': description
            }
            print(f"  ❌ {file_path} - MISSING - {description}")
    
    return results

def test_security_imports():
    """Test that security modules can be imported"""
    print("\\n🔐 Testing security module imports...")
    
    modules = {
        'hashlib': 'Cryptographic hashing',
        'secrets': 'Secure random generation',
        'base64': 'Base64 encoding/decoding',
        'json': 'JSON processing',
        'threading': 'Multi-threading support',
        'time': 'Time utilities',
        'os': 'Operating system interface',
        'sys': 'System utilities',
        're': 'Regular expressions'
    }
    
    results = {}
    
    for module_name, description in modules.items():
        try:
            __import__(module_name)
            results[module_name] = {'success': True, 'error': None}
            print(f"  ✅ {module_name} - {description}")
        except ImportError as e:
            results[module_name] = {'success': False, 'error': str(e)}
            print(f"  ❌ {module_name} - FAILED: {e}")
    
    return results

def test_security_configuration():
    """Test security configuration"""
    print("\\n⚙️  Testing security configuration...")
    
    # Try to import and test security config
    try:
        sys.path.insert(0, '.')
        from secure_server.config import SecurityConfig, get_config
        
        config = SecurityConfig()
        
        # Test configuration validation
        issues = config.validate_config()
        
        print(f"  ✅ Security configuration loaded")
        print(f"  📊 JWT expiration: {config.JWT_ACCESS_TOKEN_EXPIRES}")
        print(f"  🚦 Rate limit: {config.MAX_REQUESTS_PER_HOUR} requests/hour")
        print(f"  🔒 Lockout duration: {config.LOCKOUT_DURATION} seconds")
        print(f"  ⚠️  Threat threshold: {config.THREAT_SCORE_THRESHOLD}")
        
        if issues:
            print(f"  ⚠️  Configuration warnings:")
            for issue in issues:
                print(f"    - {issue}")
        
        return {'success': True, 'config': config, 'issues': issues}
        
    except Exception as e:
        print(f"  ❌ Configuration test failed: {e}")
        return {'success': False, 'error': str(e)}

def test_device_fingerprinting():
    """Test device fingerprinting functionality"""
    print("\\n🖥️  Testing device fingerprinting...")
    
    try:
        import platform
        import uuid
        
        # Basic system info
        system_info = {
            'system': platform.system(),
            'release': platform.release(),
            'machine': platform.machine(),
            'processor': platform.processor()
        }
        
        # Generate device fingerprint
        fingerprint_string = json.dumps(system_info, sort_keys=True)
        device_fingerprint = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        
        print(f"  ✅ System: {system_info['system']}")
        print(f"  ✅ Machine: {system_info['machine']}")
        print(f"  ✅ Fingerprint: {device_fingerprint[:16]}...")
        
        return {
            'success': True,
            'fingerprint': device_fingerprint,
            'system_info': system_info
        }
        
    except Exception as e:
        print(f"  ❌ Device fingerprinting failed: {e}")
        return {'success': False, 'error': str(e)}

def test_encryption_capabilities():
    """Test encryption functionality"""
    print("\\n🔐 Testing encryption capabilities...")
    
    try:
        import secrets
        import base64
        
        # Test key generation
        test_key = secrets.token_hex(32)
        print(f"  ✅ Key generation: {test_key[:16]}...")
        
        # Test base64 encoding
        test_data = "DARKxStorms Security Test"
        encoded = base64.b64encode(test_data.encode()).decode()
        decoded = base64.b64decode(encoded.encode()).decode()
        
        print(f"  ✅ Base64 encoding/decoding: {encoded[:20]}...")
        
        if decoded == test_data:
            print(f"  ✅ Encoding verification successful")
        else:
            print(f"  ❌ Encoding verification failed")
            return {'success': False, 'error': 'Encoding mismatch'}
        
        # Test hashing
        test_hash = hashlib.sha256(test_data.encode()).hexdigest()
        print(f"  ✅ SHA256 hashing: {test_hash[:16]}...")
        
        return {
            'success': True,
            'key': test_key,
            'encoded': encoded,
            'hash': test_hash
        }
        
    except Exception as e:
        print(f"  ❌ Encryption test failed: {e}")
        return {'success': False, 'error': str(e)}

def test_loader_security_features():
    """Test enhanced loader security features"""
    print("\\n🚀 Testing loader security features...")
    
    try:
        # Check loader file
        loader_path = 'enhanced_loader.py'
        if not os.path.exists(loader_path):
            return {'success': False, 'error': 'Enhanced loader not found'}
        
        with open(loader_path, 'r', encoding='utf-8') as f:
            loader_content = f.read()
        
        # Check for security features
        security_features = {
            'device_fingerprinting': 'generate_device_fingerprint',
            'server_verification': 'verify_server_response',
            'code_integrity': 'verify_code_integrity',
            'session_management': 'save_session_data',
            'security_headers': 'EXPECTED_SERVER_HEADERS',
            'anti_tampering': 'SecurityError'
        }
        
        results = {}
        
        for feature, marker in security_features.items():
            if marker in loader_content:
                results[feature] = True
                print(f"  ✅ {feature.replace('_', ' ').title()}")
            else:
                results[feature] = False
                print(f"  ❌ {feature.replace('_', ' ').title()} - MISSING")
        
        success_count = sum(results.values())
        total_features = len(security_features)
        
        print(f"  📊 Security features: {success_count}/{total_features}")
        
        return {
            'success': success_count >= total_features * 0.8,  # 80% threshold
            'features': results,
            'score': f"{success_count}/{total_features}"
        }
        
    except Exception as e:
        print(f"  ❌ Loader security test failed: {e}")
        return {'success': False, 'error': str(e)}

def generate_test_report(results):
    """Generate comprehensive test report"""
    print("\\n" + "="*60)
    print("🛡️  DARKXSTORMS SECURITY SYSTEM TEST REPORT")
    print("="*60)
    
    # Summary
    total_tests = len(results)
    successful_tests = sum(1 for result in results.values() if result.get('success', False))
    
    print(f"\\n📊 SUMMARY:")
    print(f"  Total tests: {total_tests}")
    print(f"  Successful: {successful_tests}")
    print(f"  Failed: {total_tests - successful_tests}")
    print(f"  Success rate: {(successful_tests/total_tests)*100:.1f}%")
    
    # Detailed results
    print(f"\\n📋 DETAILED RESULTS:")
    
    for test_name, result in results.items():
        status = "✅ PASS" if result.get('success', False) else "❌ FAIL"
        print(f"  {status} {test_name.replace('_', ' ').title()}")
        
        if not result.get('success', False) and 'error' in result:
            print(f"    Error: {result['error']}")
    
    # Security status
    print(f"\\n🔐 SECURITY STATUS:")
    
    security_score = (successful_tests / total_tests) * 100
    
    if security_score >= 90:
        security_level = "🟢 EXCELLENT"
    elif security_score >= 70:
        security_level = "🟡 GOOD"
    elif security_score >= 50:
        security_level = "🟠 FAIR"
    else:
        security_level = "🔴 POOR"
    
    print(f"  Security Level: {security_level}")
    print(f"  Security Score: {security_score:.1f}%")
    
    # Recommendations
    print(f"\\n💡 RECOMMENDATIONS:")
    
    if security_score < 100:
        print(f"  - Address failed tests to improve security")
        print(f"  - Ensure all dependencies are properly installed")
        print(f"  - Review security configuration settings")
    
    if successful_tests >= total_tests * 0.8:
        print(f"  - System is ready for deployment")
        print(f"  - Consider running additional stress tests")
    else:
        print(f"  - Fix critical issues before deployment")
        print(f"  - Review system requirements and setup")
    
    print("="*60)
    
    return {
        'total_tests': total_tests,
        'successful_tests': successful_tests,
        'security_score': security_score,
        'security_level': security_level,
        'ready_for_deployment': successful_tests >= total_tests * 0.8
    }

def main():
    """Main test function"""
    print("🛡️  DARKxStorms Security System Test Suite")
    print("="*60)
    print("Testing security implementation and protection layers...")
    print()
    
    # Run all tests
    test_results = {}
    
    # Test 1: File integrity
    test_results['file_integrity'] = test_file_integrity()
    
    # Test 2: Security imports
    test_results['security_imports'] = test_security_imports()
    
    # Test 3: Security configuration
    test_results['security_configuration'] = test_security_configuration()
    
    # Test 4: Device fingerprinting
    test_results['device_fingerprinting'] = test_device_fingerprinting()
    
    # Test 5: Encryption capabilities
    test_results['encryption_capabilities'] = test_encryption_capabilities()
    
    # Test 6: Loader security features
    test_results['loader_security_features'] = test_loader_security_features()
    
    # Generate report
    report = generate_test_report(test_results)
    
    # Return appropriate exit code
    return 0 if report['ready_for_deployment'] else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)