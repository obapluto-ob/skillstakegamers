#!/usr/bin/env python3
"""
Security and Performance Monitor
"""

import os
import sqlite3
from datetime import datetime, timedelta

def check_log_file():
    """Check if app.log exists and show recent entries"""
    log_file = 'app.log'
    if os.path.exists(log_file):
        print(f"Log file found: {log_file}")
        
        # Show last 10 lines
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if lines:
                print("\nRecent log entries:")
                for line in lines[-10:]:
                    print(f"  {line.strip()}")
            else:
                print("Log file is empty")
    else:
        print(f"Log file not found: {log_file}")
        # Create empty log file
        open(log_file, 'a').close()
        print(f"Created empty log file: {log_file}")

def check_database_health():
    """Check database health and recent activity"""
    try:
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Check recent transactions
        c.execute('SELECT COUNT(*) FROM transactions WHERE created_at > datetime("now", "-1 hour")')
        recent_transactions = c.fetchone()[0]
        
        # Check active matches
        c.execute('SELECT COUNT(*) FROM matches WHERE status = "active"')
        active_matches = c.fetchone()[0]
        
        # Check user count
        c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
        total_users = c.fetchone()[0]
        
        print(f"Database Health:")
        print(f"  Recent transactions (1h): {recent_transactions}")
        print(f"  Active matches: {active_matches}")
        print(f"  Total users: {total_users}")
        
        conn.close()
        return True
    except Exception as e:
        print(f"Database error: {e}")
        return False

def check_security_events():
    """Check for security-related events"""
    log_file = 'app.log'
    if not os.path.exists(log_file):
        return
    
    security_keywords = ['WARNING', 'ERROR', 'Security Event', 'rate limit', 'blocked']
    security_events = []
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                if any(keyword in line for keyword in security_keywords):
                    security_events.append(line.strip())
        
        if security_events:
            print(f"\nSecurity Events Found ({len(security_events)}):")
            for event in security_events[-5:]:  # Show last 5
                print(f"  {event}")
        else:
            print("\nNo security events found")
    except Exception as e:
        print(f"Error reading log file: {e}")

def main():
    print("System Monitor - SkillStake")
    print("=" * 40)
    
    check_log_file()
    print()
    
    if check_database_health():
        print("Database is healthy")
    
    check_security_events()
    
    print("\nMonitoring complete!")
    print("Run this script regularly to monitor system health")

if __name__ == "__main__":
    main()