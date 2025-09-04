#!/usr/bin/env python3
"""
Quick fix script for critical database resource leaks in the gaming application.
This script addresses the most critical database connection issues.
"""

import re
import os

def fix_database_connections(file_path):
    """Fix database connection resource leaks by adding proper context managers."""
    
    if not os.path.exists(file_path):
        print(f"File {file_path} not found!")
        return False
    
    # Read the original file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Create backup
    backup_path = file_path + '.backup'
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Backup created: {backup_path}")
    
    # Fix patterns
    fixes_applied = 0
    
    # Pattern 1: Simple connection pattern
    pattern1 = r'(\s+)conn = sqlite3\.connect\([\'"]gamebet\.db[\'"]\)\s*\n(\s+)c = conn\.cursor\(\)'
    replacement1 = r'\1with sqlite3.connect("gamebet.db") as conn:\2    c = conn.cursor()'
    
    if re.search(pattern1, content):
        content = re.sub(pattern1, replacement1, content)
        fixes_applied += 1
        print("Fixed simple connection patterns")
    
    # Pattern 2: Remove manual conn.close() calls that are now redundant
    pattern2 = r'\s+conn\.close\(\)\s*\n'
    content = re.sub(pattern2, '\n', content)
    
    # Pattern 3: Fix indentation for code inside with blocks
    lines = content.split('\n')
    fixed_lines = []
    in_with_block = False
    with_indent = 0
    
    for i, line in enumerate(lines):
        if 'with sqlite3.connect(' in line:
            in_with_block = True
            with_indent = len(line) - len(line.lstrip())
            fixed_lines.append(line)
        elif in_with_block and line.strip() == '':
            fixed_lines.append(line)
        elif in_with_block and (line.strip().startswith('return ') or 
                               line.strip().startswith('flash(') or
                               line.strip().startswith('redirect(') or
                               (len(line) - len(line.lstrip())) <= with_indent and line.strip()):
            in_with_block = False
            fixed_lines.append(line)
        elif in_with_block:
            # Add extra indentation for code inside with block
            if line.strip():
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= with_indent + 4:
                    line = ' ' * (with_indent + 4) + line.lstrip()
            fixed_lines.append(line)
        else:
            fixed_lines.append(line)
    
    content = '\n'.join(fixed_lines)
    
    # Write the fixed content
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Applied {fixes_applied} database connection fixes to {file_path}")
    return True

def add_missing_decorators(file_path):
    """Add missing @login_required decorators to sensitive endpoints."""
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Endpoints that need @login_required
    endpoints_to_fix = [
        'create_paypal_payment',
        'create_crypto_payment',
        'payment_webhook',
        'admin_live_streams',
        'admin_stream_details'
    ]
    
    fixes_applied = 0
    
    for endpoint in endpoints_to_fix:
        # Look for route definitions without @login_required
        pattern = rf"@app\.route\([^)]+\)(\s*\n)def {endpoint}\("
        
        if re.search(pattern, content):
            # Check if @login_required is already present
            check_pattern = rf"@login_required\s*\n\s*@app\.route\([^)]+\)(\s*\n)def {endpoint}\("
            if not re.search(check_pattern, content):
                # Add @login_required decorator
                replacement = rf"@login_required\n@app.route([^)]+)\1def {endpoint}("
                content = re.sub(pattern, replacement, content)
                fixes_applied += 1
                print(f"Added @login_required to {endpoint}")
    
    if fixes_applied > 0:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Applied {fixes_applied} security fixes")
    
    return fixes_applied > 0

def add_error_handling(file_path):
    """Add basic error handling to database operations."""
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Add try-except around database operations that don't have them
    # This is a basic implementation - manual review still needed
    
    # Look for functions with database operations but no try-except
    functions_needing_fixes = []
    
    # Pattern to find functions with sqlite operations but no try-except
    pattern = r'def (\w+)\([^)]*\):[^}]*?sqlite3\.connect[^}]*?(?=def|\Z)'
    matches = re.finditer(pattern, content, re.DOTALL)
    
    for match in matches:
        func_content = match.group(0)
        if 'try:' not in func_content and 'except' not in func_content:
            functions_needing_fixes.append(match.group(1))
    
    if functions_needing_fixes:
        print(f"Functions needing error handling: {', '.join(functions_needing_fixes)}")
        print("Manual review required for proper error handling implementation.")
    
    return len(functions_needing_fixes) > 0

def main():
    """Main function to apply critical fixes."""
    
    app_file = 'app.py'
    
    print("=== Gaming Application Critical Fixes ===")
    print("Applying critical database and security fixes...")
    
    if not os.path.exists(app_file):
        print(f"Error: {app_file} not found in current directory!")
        return
    
    # Apply fixes
    print("\n1. Fixing database connection resource leaks...")
    fix_database_connections(app_file)
    
    print("\n2. Adding missing security decorators...")
    add_missing_decorators(app_file)
    
    print("\n3. Checking for error handling needs...")
    add_error_handling(app_file)
    
    print("\n=== Fixes Complete ===")
    print("IMPORTANT: Manual review and testing required!")
    print("Check the backup file if you need to revert changes.")
    print("\nNext steps:")
    print("1. Test the application thoroughly")
    print("2. Review the CRITICAL_FIXES.md file")
    print("3. Add proper error handling where indicated")
    print("4. Test all API endpoints and buttons")

if __name__ == "__main__":
    main()