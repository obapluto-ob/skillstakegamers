#!/usr/bin/env python3
"""
Safe startup script for GameBet application
This script initializes the database and starts the Flask app
"""

import os
import sys
import subprocess
from pathlib import Path

def check_dependencies():
    """Check if all required dependencies are installed"""
    required_packages = [
        'flask', 'werkzeug', 'requests', 'python-dotenv', 
        'pillow', 'opencv-python', 'numpy'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("Missing required packages:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\nInstall missing packages with:")
        print(f"pip install {' '.join(missing_packages)}")
        return False
    
    return True

def initialize_database():
    """Initialize the database if it doesn't exist"""
    if not os.path.exists('gamebet.db'):
        print("Database not found. Initializing...")
        try:
            from init_db import init_database
            init_database()
            print("Database initialized successfully!")
        except Exception as e:
            print(f"Error initializing database: {e}")
            return False
    else:
        print("Database found.")
    
    return True

def check_environment():
    """Check if environment variables are properly set"""
    env_file = Path('.env')
    if not env_file.exists():
        print("Warning: .env file not found. Creating default...")
        with open('.env', 'w') as f:
            f.write("""# PayPal Configuration
PAYPAL_CLIENT_ID=your_paypal_client_id
PAYPAL_CLIENT_SECRET=your_paypal_client_secret
PAYPAL_BASE_URL=https://api-m.sandbox.paypal.com

# NOWPayments Configuration
NOWPAYMENTS_API_KEY=your_nowpayments_api_key
NOWPAYMENTS_WEBHOOK_SECRET=your-webhook-secret-here

# Security
SECRET_KEY=your_secret_key_here_change_in_production
""")
        print("Please update .env file with your actual API keys")
    
    return True

def start_app():
    """Start the Flask application"""
    try:
        print("Starting GameBet application...")
        print("Access the app at: http://localhost:5000")
        print("Admin login: username=admin, password=admin123")
        print("Press Ctrl+C to stop the server")
        
        # Import and run the app
        from app import app
        app.run(debug=True, host='0.0.0.0', port=5000)
        
    except ImportError as e:
        print(f"Error importing app: {e}")
        print("Make sure app.py is in the current directory")
        return False
    except Exception as e:
        print(f"Error starting app: {e}")
        return False
    
    return True

def main():
    """Main startup function"""
    print("=" * 50)
    print("GameBet Application Startup")
    print("=" * 50)
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    print(f"Working directory: {os.getcwd()}")
    
    # Check dependencies
    print("\n1. Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    
    # Check environment
    print("\n2. Checking environment...")
    if not check_environment():
        sys.exit(1)
    
    # Initialize database
    print("\n3. Checking database...")
    if not initialize_database():
        sys.exit(1)
    
    # Start the application
    print("\n4. Starting application...")
    if not start_app():
        sys.exit(1)

if __name__ == '__main__':
    main()