#!/usr/bin/env python3
"""
Test script for gaming application API endpoints.
Run this to check if your APIs are working correctly.
"""

import requests
import json

def test_api_endpoint(url, method='GET', data=None, headers=None):
    """Test a single API endpoint."""
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=10)
        elif method == 'POST':
            response = requests.post(url, json=data, headers=headers, timeout=10)
        
        print(f"{method} {url}: Status {response.status_code}")
        
        if response.status_code >= 400:
            print(f"  Error: {response.text[:200]}")
        
        return response.status_code < 400
        
    except requests.exceptions.RequestException as e:
        print(f"{method} {url}: Connection Error - {e}")
        return False

def main():
    """Test main API endpoints."""
    
    base_url = 'http://localhost:5000'  # Adjust if different
    
    # Test endpoints that don't require authentication
    public_endpoints = [
        ('GET', '/'),
        ('GET', '/login'),
        ('GET', '/register'),
    ]
    
    print("Testing public endpoints...")
    for method, endpoint in public_endpoints:
        test_api_endpoint(f"{base_url}{endpoint}", method)
    
    print("\nTo test authenticated endpoints, you need to:")
    print("1. Login to get a session")
    print("2. Use session cookies for subsequent requests")
    print("3. Test your specific API endpoints")
    
    # Test if server is running
    try:
        response = requests.get(base_url, timeout=5)
        print(f"\nServer is running: {response.status_code}")
    except:
        print(f"\nServer not accessible at {base_url}")
        print("Make sure your Flask app is running!")

if __name__ == "__main__":
    main()
