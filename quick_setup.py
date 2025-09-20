#!/usr/bin/env python3
"""Quick setup script for Render deployment"""

import os
import subprocess

def setup_render():
    print("🚀 Setting up SkillStake for Render...")
    
    # Check if git is initialized
    if not os.path.exists('.git'):
        print("❌ Git not initialized. Run: git init")
        return
    
    # Add all files
    subprocess.run(['git', 'add', '.'])
    
    # Commit changes
    subprocess.run(['git', 'commit', '-m', 'Revenue optimization + PostgreSQL setup'])
    
    # Push to main
    subprocess.run(['git', 'push', 'origin', 'main'])
    
    print("✅ Code pushed to GitHub")
    print("✅ Render will auto-deploy in 2-3 minutes")
    print("\n📋 Next steps:")
    print("1. Add PostgreSQL database in Render dashboard")
    print("2. Copy DATABASE_URL to environment variables")
    print("3. Visit your app URL to test")

if __name__ == "__main__":
    setup_render()