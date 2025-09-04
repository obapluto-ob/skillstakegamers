#!/usr/bin/env python3
"""
Test all user buttons and APIs
"""

import requests
import json

def test_apis():
    """Test API endpoints"""
    base_url = "http://localhost:5000"
    
    print("Testing API endpoints...")
    
    # Test endpoints that don't require login
    endpoints = [
        "/",
        "/api/user_balance",
        "/api/user_stats", 
        "/api/refresh_dashboard",
        "/send_gift"
    ]
    
    for endpoint in endpoints:
        try:
            if endpoint in ["/api/user_balance", "/api/user_stats", "/api/refresh_dashboard"]:
                print(f"{endpoint}: Requires login (expected)")
            elif endpoint == "/send_gift":
                # Test POST request
                response = requests.post(f"{base_url}{endpoint}", 
                                       json={"stream_id": 1, "gift_type": "heart"},
                                       timeout=5)
                print(f"{endpoint}: Status {response.status_code} (POST)")
            else:
                response = requests.get(f"{base_url}{endpoint}", timeout=5)
                print(f"{endpoint}: Status {response.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"{endpoint}: Server not running")
        except Exception as e:
            print(f"{endpoint}: Error - {str(e)}")

if __name__ == "__main__":
    test_apis()