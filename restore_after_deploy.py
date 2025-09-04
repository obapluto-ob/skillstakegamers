#!/usr/bin/env python3
"""
Simple restore script - run this after deployment
"""

import os
import json

def restore_users():
    """Restore users to PostgreSQL after deployment"""
    
    # User data from backup
    users_data = [
        ("kaleb", "0797656882@gamebet.local", "scrypt:32768:8:1$KsdwaDMVCoQPXAa4$10fe08447b12b1457637c28152309114e164302490fca27287df82844703b60a5f4f9674d746d2d0b8ff9663b73532aa572d863458a314eefe6ba8735f081734", 1242.5, "0797656882", "KAL9279"),
        ("kasongo", "0729237050@gamebet.local", "scrypt:32768:8:1$AtQaOoLEpqbc0ed6$30fbedea87ae2ae9ccdb4ef34e13573536cb13051c7256ea40f156c87de77319fe66444320f43abd81f175546de29f0acf8ac7f5db82cb18e29691c42a297cec", 335.0, "0729237050", "KAS0643"),
        ("kasongomustgo", "0729237053@gamebet.local", "pbkdf2:sha256:600000$DY6uh1tA9DnIdIQh$88db9b7f40273fdf1125dc395401b6255765d72686917891cdc0b1e46437dc1c", 523.5, "0729237053", "KAS6408"),
        ("kolu", "0789187291@gamebet.local", "pbkdf2:sha256:600000$DY6uh1tA9DnIdIQh$88db9b7f40273fdf1125dc395401b6255765d72686917891cdc0b1e46437dc1c", 3099.24, "0789187291", "KOL1700"),
        ("obapluto", "0729237059@gamebet.local", "scrypt:32768:8:1$aTXJ5Yc76CWzY2rx$94998528896e1372c0d063df51d2ec52e173a701812be0020bc42625b124944b5c13564ece33c6a520510862fe5fe26987627908a86a372229452edcc7a39971", 79.5, "0729237059", "OBA8222"),
        ("pluto", "obedemoni153@gmail.com", "scrypt:32768:8:1$Wa1X8x8bcd7q1bw1$c14e52044bd256e2244598d1c4c0ab217c05eecad6e33e6716050070b2ffb8070ee51c4d19259010deeadc63c78a9bc2dfc92777577fbaa92b0067d012883d0e", 150.0, "+254729237050", "PLU001"),
        ("plutomania", "obedemoni@gmail.com", "scrypt:32768:8:1$3MPlwuhXmnjKo0C9$d675bb08404f0381919d0c46480b0612c759817f6ae70726f2d008eea6cf94aa9a8d34b068aee2b6e5c4050be368a56ed7d48e3a7022824a91817e641f27ae6c", 4391.16, "+254729237059", "PLU0325"),
        ("plutot", "0729237055@gamebet.local", "scrypt:32768:8:1$9q5WPp5UZ3NnTZWB$11c88ee484a2cd1c2ca4cc62850a94464a50d1c6af681b62de3834b43aede3cf45714d18a04c6196ea49cf73aabb55b4efcf55859b2c134a18713a563f31e1fe", 0.0, "0729237055", "PLU1615"),
        ("test_deposit_user", "test_deposit_user@test.com", "test123", 970.0, "0700000000", "TES001"),
        ("test_withdrawal_user", "test_withdrawal_user@test.com", "test123", 0.0, "0700000001", "TES002")
    ]
    
    try:
        import psycopg2
        from urllib.parse import urlparse
        
        # Connect to PostgreSQL
        database_url = os.getenv('DATABASE_URL')
        if not database_url:
            print("[ERROR] DATABASE_URL not found")
            return False
            
        url = urlparse(database_url)
        conn = psycopg2.connect(
            database=url.path[1:],
            user=url.username,
            password=url.password,
            host=url.hostname,
            port=url.port
        )
        
        c = conn.cursor()
        
        print("[OK] Connected to PostgreSQL")
        print(f"[OK] Restoring {len(users_data)} users...")
        
        restored = 0
        for user in users_data:
            try:
                c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code, wins, losses, total_earnings)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (username) DO NOTHING''', 
                         (*user, 0, 0, 0))
                restored += 1
            except Exception as e:
                print(f"[ERROR] Failed to restore {user[0]}: {e}")
        
        conn.commit()
        conn.close()
        
        print(f"[OK] Restored {restored} users")
        print(f"[OK] Total balance: KSh 10,790.90")
        print("[OK] Users are now safe in PostgreSQL!")
        
        return True
        
    except ImportError:
        print("[ERROR] psycopg2 not installed")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False

if __name__ == "__main__":
    restore_users()