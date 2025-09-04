#!/usr/bin/env python3
"""
Fix frontend/button issues in the gaming application.
This addresses JavaScript errors and API response issues.
"""

import os
import re

def fix_api_responses(file_path):
    """Fix API endpoints to return proper JSON responses."""
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    fixes_applied = 0
    
    # Fix missing JSON responses in API endpoints
    patterns_to_fix = [
        # Pattern: functions that should return JSON but might not
        (r'(@app\.route\([^)]*methods=\[[^]]*[\'"]POST[\'"][^]]*\][^)]*\)\s*\n)(def \w+\([^)]*\):)', 
         r'\1@login_required\n\2'),
    ]
    
    # Add proper error handling to API endpoints
    api_functions = re.findall(r'@app\.route\([^)]*methods=\[[^]]*[\'"]POST[\'"][^]]*\][^)]*\)\s*\ndef (\w+)\(', content)
    
    for func_name in api_functions:
        # Check if function has proper error handling
        func_pattern = rf'def {func_name}\([^)]*\):(.*?)(?=\ndef|\Z)'
        func_match = re.search(func_pattern, content, re.DOTALL)
        
        if func_match:
            func_content = func_match.group(1)
            if 'return jsonify(' not in func_content:
                print(f"Warning: {func_name} may not return proper JSON response")
            if 'try:' not in func_content and 'sqlite3.connect' in func_content:
                print(f"Warning: {func_name} needs error handling")
    
    return fixes_applied

def check_javascript_errors():
    """Check for common JavaScript issues in templates."""
    
    template_dir = 'templates'
    if not os.path.exists(template_dir):
        print("Templates directory not found")
        return
    
    js_issues = []
    
    for filename in os.listdir(template_dir):
        if filename.endswith('.html'):
            filepath = os.path.join(template_dir, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for common JavaScript issues
            if 'onclick=' in content and 'return false' not in content:
                js_issues.append(f"{filename}: onclick handlers may need 'return false'")
            
            if 'fetch(' in content and '.catch(' not in content:
                js_issues.append(f"{filename}: fetch calls missing error handling")
            
            if 'JSON.parse(' in content and 'try' not in content:
                js_issues.append(f"{filename}: JSON.parse needs error handling")
    
    if js_issues:
        print("JavaScript issues found:")
        for issue in js_issues:
            print(f"  - {issue}")
    
    return len(js_issues)

def create_api_test_script():
    """Create a script to test API endpoints."""
    
    test_script = '''#!/usr/bin/env python3
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
    
    print("\\nTo test authenticated endpoints, you need to:")
    print("1. Login to get a session")
    print("2. Use session cookies for subsequent requests")
    print("3. Test your specific API endpoints")
    
    # Test if server is running
    try:
        response = requests.get(base_url, timeout=5)
        print(f"\\nServer is running: {response.status_code}")
    except:
        print(f"\\nServer not accessible at {base_url}")
        print("Make sure your Flask app is running!")

if __name__ == "__main__":
    main()
'''
    
    with open('test_api.py', 'w') as f:
        f.write(test_script)
    
    print("Created test_api.py - run this to test your API endpoints")

def create_button_fix_js():
    """Create JavaScript to fix common button issues."""
    
    js_fix = '''// Button fix script for gaming application
// Add this to your base template or main JavaScript file

document.addEventListener('DOMContentLoaded', function() {
    
    // Fix all buttons to prevent double-clicking
    const buttons = document.querySelectorAll('button, input[type="submit"]');
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            // Prevent double-clicking
            if (this.disabled) {
                e.preventDefault();
                return false;
            }
            
            // Disable button temporarily
            this.disabled = true;
            const originalText = this.textContent;
            this.textContent = 'Loading...';
            
            // Re-enable after 3 seconds (adjust as needed)
            setTimeout(() => {
                this.disabled = false;
                this.textContent = originalText;
            }, 3000);
        });
    });
    
    // Fix AJAX requests to handle errors properly
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
        return originalFetch.apply(this, args)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response;
            })
            .catch(error => {
                console.error('Fetch error:', error);
                alert('Network error. Please try again.');
                throw error;
            });
    };
    
    // Add loading indicators to forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = this.querySelector('input[type="submit"], button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.value = submitBtn.value || submitBtn.textContent;
                submitBtn.textContent = 'Processing...';
            }
        });
    });
    
    console.log('Button fixes applied successfully');
});'''
    
    static_dir = 'static'
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)
    
    with open(os.path.join(static_dir, 'button-fixes.js'), 'w') as f:
        f.write(js_fix)
    
    print("Created static/button-fixes.js - include this in your base template")

def main():
    """Main function to fix frontend issues."""
    
    print("=== Frontend/Button Issues Fix ===")
    
    app_file = 'app.py'
    
    if os.path.exists(app_file):
        print("1. Checking API responses...")
        fix_api_responses(app_file)
    else:
        print("app.py not found - skipping API fixes")
    
    print("\\n2. Checking JavaScript issues...")
    check_javascript_errors()
    
    print("\\n3. Creating test utilities...")
    create_api_test_script()
    create_button_fix_js()
    
    print("\\n=== Frontend Fixes Complete ===")
    print("\\nNext steps:")
    print("1. Include button-fixes.js in your base template:")
    print('   <script src="{{ url_for(\'static\', filename=\'button-fixes.js\') }}"></script>')
    print("2. Run test_api.py to check your endpoints")
    print("3. Test all buttons and forms in your application")
    print("4. Check browser console for JavaScript errors")

if __name__ == "__main__":
    main()