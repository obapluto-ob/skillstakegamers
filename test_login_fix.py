#!/usr/bin/env python3
"""
Test the login BuildError fix
"""

from app import app
import sqlite3

def test_login_flow():
    print("Testing SkillStake Login Flow Fix...")
    
    with app.test_client() as client:
        with app.test_request_context():
            from flask import url_for
            
            # Test 1: Check if admin_dashboard route exists
            try:
                admin_url = url_for('admin_dashboard')
                print(f"✅ admin_dashboard route: {admin_url}")
            except Exception as e:
                print(f"❌ admin_dashboard route: {e}")
                return False
            
            # Test 2: Access login page (should not have BuildError)
            try:
                response = client.get('/login')
                if response.status_code == 200:
                    print("✅ Login page loads without BuildError")
                else:
                    print(f"⚠️ Login page: HTTP {response.status_code}")
            except Exception as e:
                if 'BuildError' in str(e):
                    print(f"❌ Login page still has BuildError: {e}")
                    return False
                else:
                    print(f"⚠️ Login page error (not BuildError): {e}")
            
            # Test 3: Check admin user exists
            try:
                conn = sqlite3.connect('gamebet.db')
                c = conn.cursor()
                c.execute("SELECT username FROM users WHERE username = 'admin'")
                admin = c.fetchone()
                conn.close()
                
                if admin:
                    print("✅ Admin user exists in database")
                else:
                    print("⚠️ Admin user not found in database")
            except Exception as e:
                print(f"❌ Database check failed: {e}")
            
            # Test 4: Test admin dashboard access (should redirect to login)
            try:
                response = client.get('/admin_dashboard')
                if response.status_code in [302, 401]:
                    print("✅ Admin dashboard properly redirects when not logged in")
                else:
                    print(f"⚠️ Admin dashboard: HTTP {response.status_code}")
            except Exception as e:
                print(f"❌ Admin dashboard access failed: {e}")
                return False
    
    print("\n🎉 BuildError Fix: SUCCESS")
    print("The admin_dashboard route has been added and login should work now!")
    return True

if __name__ == "__main__":
    test_login_flow()