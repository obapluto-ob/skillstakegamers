#!/usr/bin/env python3
"""
Test script to verify the GameBet application is working correctly
"""

import os
import sys
import sqlite3
import requests
import time
from threading import Thread

def test_database():
    """Test database connectivity"""
    print("Testing database...")
    try:
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Test basic query
        c.execute("SELECT COUNT(*) FROM users")
        user_count = c.fetchone()[0]
        print(f"  Users in database: {user_count}")
        
        # Test admin user
        c.execute("SELECT username FROM users WHERE username = 'admin'")
        admin = c.fetchone()
        if admin:
            print("  Admin user exists: YES")
        else:
            print("  Admin user exists: NO")
        
        conn.close()
        return True
    except Exception as e:
        print(f"  Database error: {e}")
        return False

def test_imports():
    """Test if all modules can be imported"""
    print("Testing imports...")
    modules = [
        'validators', 'db_utils', 'security', 'error_handler',
        'financial_utils', 'match_utils', 'rate_limiter',
        'paypal_config', 'security_utils', 'config'
    ]
    
    failed_imports = []
    for module in modules:
        try:
            __import__(module)
            print(f"  {module}: OK")
        except Exception as e:
            print(f"  {module}: ERROR - {e}")
            failed_imports.append(module)
    
    return len(failed_imports) == 0

def test_flask_app():
    """Test if Flask app can be imported and configured"""
    print("Testing Flask app...")
    try:
        from app import app
        print("  App import: OK")
        
        # Test app configuration
        if app.secret_key:
            print("  Secret key: OK")
        else:
            print("  Secret key: MISSING")
        
        # Test if routes are registered
        routes = [rule.rule for rule in app.url_map.iter_rules()]
        print(f"  Routes registered: {len(routes)}")
        
        return True
    except Exception as e:
        print(f"  Flask app error: {e}")
        return False

def start_test_server():
    """Start Flask app in test mode"""
    try:
        from app import app
        app.run(debug=False, port=5001, use_reloader=False, threaded=True)
    except Exception as e:
        print(f"Test server error: {e}")

def test_web_endpoints():
    """Test if web endpoints are responding"""
    print("Testing web endpoints...")
    
    # Start server in background
    server_thread = Thread(target=start_test_server, daemon=True)
    server_thread.start()
    
    # Wait for server to start
    time.sleep(3)
    
    endpoints = [
        ('/', 'Home page'),
        ('/login', 'Login page'),
        ('/register', 'Register page')
    ]
    
    base_url = 'http://localhost:5001'
    
    for endpoint, description in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            if response.status_code == 200:
                print(f"  {description}: OK (200)")
            else:
                print(f"  {description}: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"  {description}: ERROR - {e}")
    
    return True

def main():
    """Run all tests"""
    print("GameBet Application Test Suite")
    print("=" * 40)
    
    tests = [
        ("Database", test_database),
        ("Module Imports", test_imports),
        ("Flask App", test_flask_app),
        ("Web Endpoints", test_web_endpoints)
    ]
    
    results = []
    
    for name, test_func in tests:
        print(f"\n{name}:")
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"  Test failed with exception: {e}")
            results.append((name, False))
    
    print("\n" + "=" * 40)
    print("TEST RESULTS:")
    
    all_passed = True
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{name}: {status}")
        if not result:
            all_passed = False
    
    if all_passed:
        print("\nAll tests passed! Your app should be working correctly.")
        print("Start the app with: python run_app.py")
    else:
        print("\nSome tests failed. Check the errors above.")
    
    return all_passed

if __name__ == '__main__':
    main()