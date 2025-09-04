#!/usr/bin/env python3
"""
Setup verification script for GameBet application
Run this to check if everything is properly configured
"""

import os
import sys
import sqlite3
from pathlib import Path

def check_files():
    """Check if all required files exist"""
    required_files = [
        'app.py',
        'config.py',
        'db_utils.py',
        'error_handler.py',
        'financial_utils.py',
        'match_utils.py',
        'paypal_config.py',
        'rate_limiter.py',
        'security.py',
        'security_utils.py',
        'validators.py',
        'requirements.txt',
        '.env'
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print("❌ Missing required files:")
        for file in missing_files:
            print(f"   - {file}")
        return False
    else:
        print("✅ All required files present")
        return True

def check_python_packages():
    """Check if required Python packages are installed"""
    required_packages = {
        'flask': 'Flask',
        'werkzeug': 'Werkzeug', 
        'requests': 'requests',
        'dotenv': 'python-dotenv',
        'PIL': 'Pillow',
        'cv2': 'opencv-python',
        'numpy': 'numpy'
    }
    
    missing_packages = []
    installed_packages = []
    
    for import_name, package_name in required_packages.items():
        try:
            __import__(import_name)
            installed_packages.append(package_name)
        except ImportError:
            missing_packages.append(package_name)
    
    if installed_packages:
        print("✅ Installed packages:")
        for package in installed_packages:
            print(f"   - {package}")
    
    if missing_packages:
        print("❌ Missing packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print(f"\nInstall with: pip install {' '.join(missing_packages)}")
        return False
    else:
        print("✅ All required packages installed")
        return True

def check_database():
    """Check database status"""
    if not os.path.exists('gamebet.db'):
        print("❌ Database file not found")
        print("   Run: python init_db.py")
        return False
    
    try:
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Check if main tables exist
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in c.fetchall()]
        
        required_tables = ['users', 'matches', 'transactions', 'streams']
        missing_tables = [table for table in required_tables if table not in tables]
        
        if missing_tables:
            print("❌ Missing database tables:")
            for table in missing_tables:
                print(f"   - {table}")
            print("   Run: python init_db.py")
            conn.close()
            return False
        
        # Check if admin user exists
        c.execute("SELECT username FROM users WHERE username = 'admin'")
        admin_exists = c.fetchone() is not None
        
        conn.close()
        
        if not admin_exists:
            print("❌ Admin user not found")
            print("   Run: python init_db.py")
            return False
        
        print("✅ Database properly configured")
        print(f"   Tables found: {len(tables)}")
        print("   Admin user exists")
        return True
        
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

def check_environment():
    """Check environment configuration"""
    if not os.path.exists('.env'):
        print("❌ .env file not found")
        return False
    
    required_vars = [
        'SECRET_KEY',
        'PAYPAL_CLIENT_ID', 
        'PAYPAL_CLIENT_SECRET',
        'NOWPAYMENTS_API_KEY'
    ]
    
    from dotenv import load_dotenv
    load_dotenv()
    
    missing_vars = []
    configured_vars = []
    
    for var in required_vars:
        value = os.getenv(var)
        if not value or value.startswith('your_') or value == 'your-webhook-secret-here':
            missing_vars.append(var)
        else:
            configured_vars.append(var)
    
    if configured_vars:
        print("✅ Configured environment variables:")
        for var in configured_vars:
            print(f"   - {var}")
    
    if missing_vars:
        print("⚠️  Environment variables need configuration:")
        for var in missing_vars:
            print(f"   - {var}")
        print("   Update values in .env file")
        return False
    else:
        print("✅ All environment variables configured")
        return True

def check_templates():
    """Check if templates directory exists"""
    if not os.path.exists('templates'):
        print("❌ Templates directory not found")
        return False
    
    template_files = list(Path('templates').glob('*.html'))
    if len(template_files) == 0:
        print("❌ No HTML templates found")
        return False
    
    print(f"✅ Templates directory found ({len(template_files)} files)")
    return True

def check_static():
    """Check if static directory exists"""
    if not os.path.exists('static'):
        print("❌ Static directory not found")
        return False
    
    print("✅ Static directory found")
    return True

def main():
    """Run all checks"""
    print("GameBet Setup Verification")
    print("=" * 40)
    
    checks = [
        ("Files", check_files),
        ("Python Packages", check_python_packages),
        ("Database", check_database),
        ("Environment", check_environment),
        ("Templates", check_templates),
        ("Static Files", check_static)
    ]
    
    results = []
    
    for name, check_func in checks:
        print(f"\n{name}:")
        result = check_func()
        results.append((name, result))
    
    print("\n" + "=" * 40)
    print("SUMMARY:")
    
    all_passed = True
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{name}: {status}")
        if not result:
            all_passed = False
    
    if all_passed:
        print("\n🎉 All checks passed! You can start the app with:")
        print("   python run_app.py")
    else:
        print("\n⚠️  Some checks failed. Fix the issues above before starting the app.")
    
    return all_passed

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)