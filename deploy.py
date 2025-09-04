#!/usr/bin/env python3
"""
Deployment script for SkillStake Gaming Platform
"""
import os
import subprocess
import sys

def run_command(command):
    """Run shell command"""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {command}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {command}")
        print(f"Error: {e.stderr}")
        return False

def main():
    print("🚀 Deploying SkillStake Gaming Platform...")
    
    # Check if git is initialized
    if not os.path.exists('.git'):
        print("📁 Initializing git repository...")
        run_command("git init")
        run_command("git add .")
        run_command('git commit -m "Initial commit"')
    
    print("\n📋 Deployment checklist:")
    print("1. ✅ Created requirements.txt")
    print("2. ✅ Created render.yaml")
    print("3. ✅ Created environment variables")
    print("4. ✅ Added security fixes")
    print("5. ✅ Created utility modules")
    
    print("\n🔧 Next steps:")
    print("1. Push to GitHub:")
    print("   git remote add origin https://github.com/yourusername/skillstake-gaming.git")
    print("   git push -u origin main")
    print("\n2. Deploy on Render:")
    print("   - Go to render.com")
    print("   - Connect your GitHub repo")
    print("   - Set environment variables")
    print("   - Deploy!")
    
    print("\n🔐 Don't forget to set these environment variables on Render:")
    print("   - SECRET_KEY (auto-generated)")
    print("   - ADMIN_PASSWORD (your secure password)")
    print("   - NOWPAYMENTS_API_KEY")
    print("   - PAYPAL_CLIENT_ID")
    print("   - PAYPAL_CLIENT_SECRET")

if __name__ == "__main__":
    main()