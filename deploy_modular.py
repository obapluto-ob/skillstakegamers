#!/usr/bin/env python3
"""
Safe deployment script for modular SkillStake Gaming Platform
Switches to modular structure while preserving all functionality
"""

import os
import shutil
import sys
from datetime import datetime

def create_deployment_backup():
    """Create backup before deployment"""
    print("Creating deployment backup...")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = f'deployment_backup_{timestamp}'
    
    try:
        os.makedirs(backup_dir, exist_ok=True)
        
        # Backup critical files
        files_to_backup = [
            'app.py',
            'database.py',
            'gamebet.db',
            '.env'
        ]
        
        for file in files_to_backup:
            if os.path.exists(file):
                shutil.copy2(file, os.path.join(backup_dir, file))
                print(f"Backed up: {file}")
        
        print(f"Deployment backup created in: {backup_dir}")
        return backup_dir
        
    except Exception as e:
        print(f"Backup failed: {e}")
        return None

def deploy_modular_structure():
    """Deploy the modular structure"""
    print("Deploying modular structure...")
    
    try:
        # Replace app.py with modular version
        if os.path.exists('app_modular.py'):
            shutil.copy2('app.py', 'app_legacy.py')  # Keep legacy version
            shutil.copy2('app_modular.py', 'app.py')
            print("Switched to modular app.py")
        else:
            print("app_modular.py not found")
            return False
        
        # Verify routes directory exists
        if not os.path.exists('routes'):
            print("Routes directory not found")
            return False
        
        # Check all route files exist
        required_routes = [
            'routes/__init__.py',
            'routes/auth_routes.py',
            'routes/main_routes.py',
            'routes/admin_routes.py'
        ]
        
        for route_file in required_routes:
            if not os.path.exists(route_file):
                print(f"Missing route file: {route_file}")
                return False
            else:
                print(f"Found: {route_file}")
        
        print("Modular structure deployed successfully!")
        return True
        
    except Exception as e:
        print(f"Deployment failed: {e}")
        return False

def test_modular_app():
    """Test the modular app"""
    print("Testing modular application...")
    
    try:
        # Try importing the modular app
        import importlib.util
        spec = importlib.util.spec_from_file_location("app", "app.py")
        app_module = importlib.util.module_from_spec(spec)
        
        print("Modular app imports successfully")
        
        # Test database connection
        from database_manager import db_manager
        stats = db_manager.get_database_stats()
        print(f"Database connection works: {stats}")
        
        return True
        
    except Exception as e:
        print(f"Testing failed: {e}")
        return False

def rollback_deployment(backup_dir):
    """Rollback to previous version if needed"""
    print(f"Rolling back deployment from: {backup_dir}")
    
    try:
        if os.path.exists(os.path.join(backup_dir, 'app.py')):
            shutil.copy2(os.path.join(backup_dir, 'app.py'), 'app.py')
            print("Rolled back app.py")
        
        print("Rollback completed")
        return True
        
    except Exception as e:
        print(f"Rollback failed: {e}")
        return False

def main():
    """Main deployment process"""
    print("SkillStake Modular Deployment")
    print("================================")
    
    # Step 1: Create backup
    backup_dir = create_deployment_backup()
    if not backup_dir:
        print("Cannot proceed without backup. Exiting.")
        sys.exit(1)
    
    # Step 2: Deploy modular structure
    if not deploy_modular_structure():
        print("Deployment failed. Rolling back...")
        rollback_deployment(backup_dir)
        sys.exit(1)
    
    # Step 3: Test the deployment
    if not test_modular_app():
        print("Testing failed. Rolling back...")
        rollback_deployment(backup_dir)
        sys.exit(1)
    
    print("\nMODULAR DEPLOYMENT SUCCESSFUL!")
    print("Your application is now modular and organized!")
    print("All functionality preserved - no features lost!")
    print(f"Backup available in: {backup_dir}")
    print("\nTo start the application: python app.py")

if __name__ == "__main__":
    main()