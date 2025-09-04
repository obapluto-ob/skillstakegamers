#!/usr/bin/env python3
"""
Security Fixes Installation Script
Run this to apply all security updates
"""

import os
import subprocess
import sys

def install_requirements():
    """Install new Python packages"""
    print("Installing new requirements...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("Requirements installed successfully")
    except subprocess.CalledProcessError:
        print("Failed to install requirements")
        return False
    return True

def check_env_file():
    """Check if .env file exists"""
    if not os.path.exists('.env'):
        print(".env file not found!")
        print("Please create .env file with your API keys")
        return False
    print(".env file found")
    return True

def create_database_backup():
    """Backup existing database"""
    if os.path.exists('gamebet.db'):
        import shutil
        import time
        backup_name = f'gamebet_backup_{int(time.time())}.db'
        shutil.copy2('gamebet.db', backup_name)
        print(f"Database backed up as {backup_name}")
    else:
        print("No existing database to backup")

def main():
    print("Installing Security Fixes...")
    print("=" * 40)
    
    # Check environment
    if not check_env_file():
        return
    
    # Backup database
    create_database_backup()
    
    # Install requirements
    if not install_requirements():
        return
    
    # Create log file
    if not os.path.exists('app.log'):
        open('app.log', 'a').close()
        print("Created app.log file")
    
    print("\nAll security fixes installed successfully!")
    print("\nNext steps:")
    print("1. Run 'python monitor.py' to check system health")
    print("2. Test all functionality (login, deposits, matches)")
    print("3. Monitor app.log for security events")
    print("4. Your .env file is already configured")
    
    # Run monitor
    print("\nRunning initial system check...")
    try:
        import monitor
        monitor.main()
    except ImportError:
        print("Monitor script not found, run manually: python monitor.py")

if __name__ == "__main__":
    import time
    main()