#!/usr/bin/env python3
"""
SkillStake System Test - Windows Compatible
"""

import sqlite3
import requests
import json
import os
from datetime import datetime

def test_database():
    print("Testing Database...")
    try:
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Check tables
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in c.fetchall()]
        print(f"  Tables found: {len(tables)}")
        
        # Check users
        c.execute("SELECT COUNT(*) FROM users WHERE username != 'admin'")
        users = c.fetchone()[0]
        print(f"  Regular users: {users}")
        
        # Check transactions
        c.execute("SELECT COUNT(*) FROM transactions")
        transactions = c.fetchone()[0]
        print(f"  Total transactions: {transactions}")
        
        # Check balances
        c.execute("SELECT SUM(balance) FROM users WHERE username != 'admin'")
        total_balance = c.fetchone()[0] or 0
        print(f"  Total user balance: {total_balance} KSh")
        
        conn.close()
        print("  Database: WORKING")
        return True
    except Exception as e:
        print(f"  Database: FAILED - {e}")
        return False

def test_fpl_api():
    print("Testing FPL API...")
    try:
        response = requests.get('https://fantasy.premierleague.com/api/bootstrap-static/', timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"  FPL API: WORKING - {len(data.get('teams', []))} teams")
            return True
        else:
            print(f"  FPL API: FAILED - HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"  FPL API: FAILED - {e}")
        return False

def test_payment_apis():
    print("Testing Payment APIs...")
    
    # NOWPayments
    api_key = os.getenv('NOWPAYMENTS_API_KEY')
    if api_key:
        try:
            headers = {'x-api-key': api_key}
            response = requests.get('https://api.nowpayments.io/v1/status', headers=headers, timeout=10)
            if response.status_code == 200:
                print("  NOWPayments: WORKING")
            else:
                print(f"  NOWPayments: FAILED - HTTP {response.status_code}")
        except Exception as e:
            print(f"  NOWPayments: FAILED - {e}")
    else:
        print("  NOWPayments: NOT CONFIGURED")
    
    # PayPal
    paypal_id = os.getenv('PAYPAL_CLIENT_ID')
    if paypal_id:
        print(f"  PayPal: CONFIGURED")
    else:
        print("  PayPal: NOT CONFIGURED")

def test_ai_libraries():
    print("Testing AI Libraries...")
    
    libraries = [
        ('opencv-python', 'cv2'),
        ('pytesseract', 'pytesseract'),
        ('pillow', 'PIL'),
        ('numpy', 'numpy')
    ]
    
    working = 0
    for lib_name, import_name in libraries:
        try:
            __import__(import_name)
            print(f"  {lib_name}: WORKING")
            working += 1
        except ImportError:
            print(f"  {lib_name}: MISSING")
    
    print(f"  AI System: {working}/{len(libraries)} libraries working")
    return working > 2

def test_security_logs():
    print("Testing Security System...")
    try:
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Admin logs
        c.execute("SELECT COUNT(*) FROM admin_audit_log")
        admin_logs = c.fetchone()[0]
        print(f"  Admin audit logs: {admin_logs}")
        
        # System alerts
        c.execute("SELECT COUNT(*) FROM system_alerts")
        alerts = c.fetchone()[0]
        print(f"  System alerts: {alerts}")
        
        # Screenshots
        c.execute("SELECT COUNT(*) FROM match_screenshots")
        screenshots = c.fetchone()[0]
        print(f"  Match screenshots: {screenshots}")
        
        conn.close()
        print("  Security System: WORKING")
        return True
    except Exception as e:
        print(f"  Security System: FAILED - {e}")
        return False

def test_game_system():
    print("Testing Game System...")
    try:
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Game matches
        c.execute("SELECT COUNT(*) FROM game_matches")
        game_matches = c.fetchone()[0]
        print(f"  Game matches: {game_matches}")
        
        # FPL battles
        c.execute("SELECT COUNT(*) FROM fpl_battles")
        fpl_battles = c.fetchone()[0]
        print(f"  FPL battles: {fpl_battles}")
        
        # Match statuses
        c.execute("SELECT status, COUNT(*) FROM game_matches GROUP BY status")
        statuses = c.fetchall()
        for status, count in statuses:
            print(f"    {status}: {count}")
        
        conn.close()
        print("  Game System: WORKING")
        return True
    except Exception as e:
        print(f"  Game System: FAILED - {e}")
        return False

def test_revenue_system():
    print("Testing Revenue System...")
    try:
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Commissions
        c.execute("SELECT SUM(commission) FROM game_matches WHERE commission IS NOT NULL")
        game_comm = c.fetchone()[0] or 0
        
        c.execute("SELECT SUM(commission) FROM fpl_battles WHERE commission IS NOT NULL")
        fpl_comm = c.fetchone()[0] or 0
        
        total_comm = game_comm + fpl_comm
        print(f"  Total commissions: {total_comm} KSh")
        
        # Platform fees
        c.execute("SELECT SUM(amount) FROM transactions WHERE type = 'platform_fee'")
        fees = c.fetchone()[0] or 0
        print(f"  Platform fees: {fees} KSh")
        
        # Deposits
        c.execute("SELECT SUM(amount) FROM transactions WHERE type LIKE '%deposit%' AND amount > 0")
        deposits = c.fetchone()[0] or 0
        print(f"  Total deposits: {deposits} KSh")
        
        conn.close()
        print("  Revenue System: WORKING")
        return True
    except Exception as e:
        print(f"  Revenue System: FAILED - {e}")
        return False

def test_user_engagement():
    print("Testing User Engagement...")
    try:
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Daily bonuses
        c.execute("SELECT COUNT(*) FROM transactions WHERE type = 'daily_bonus'")
        bonuses = c.fetchone()[0]
        print(f"  Daily bonuses claimed: {bonuses}")
        
        # Recent activity
        c.execute("SELECT COUNT(DISTINCT user_id) FROM transactions WHERE created_at >= date('now', '-7 days')")
        active_users = c.fetchone()[0]
        print(f"  Active users (7 days): {active_users}")
        
        # Referrals
        c.execute("SELECT COUNT(*) FROM users WHERE referred_by IS NOT NULL")
        referrals = c.fetchone()[0]
        print(f"  Referred users: {referrals}")
        
        conn.close()
        print("  User Engagement: WORKING")
        return True
    except Exception as e:
        print(f"  User Engagement: FAILED - {e}")
        return False

def main():
    print("SkillStake System Test Starting...")
    print("=" * 50)
    
    results = []
    
    # Run all tests
    results.append(("Database", test_database()))
    results.append(("FPL API", test_fpl_api()))
    results.append(("Payment APIs", test_payment_apis()))
    results.append(("AI Libraries", test_ai_libraries()))
    results.append(("Security System", test_security_logs()))
    results.append(("Game System", test_game_system()))
    results.append(("Revenue System", test_revenue_system()))
    results.append(("User Engagement", test_user_engagement()))
    
    # Summary
    print("\n" + "=" * 50)
    print("SYSTEM TEST SUMMARY")
    print("=" * 50)
    
    passed = 0
    failed = 0
    
    for component, status in results:
        if status:
            print(f"PASS: {component}")
            passed += 1
        else:
            print(f"FAIL: {component}")
            failed += 1
    
    total = passed + failed
    health_score = (passed / total * 100) if total > 0 else 0
    
    print(f"\nResults: {passed}/{total} components working")
    print(f"System Health: {health_score:.1f}%")
    
    if failed == 0:
        print("STATUS: ALL SYSTEMS OPERATIONAL")
    else:
        print(f"STATUS: {failed} ISSUES DETECTED")

if __name__ == "__main__":
    main()