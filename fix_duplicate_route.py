#!/usr/bin/env python3
"""
Fix duplicate route definition in app.py
This script removes the duplicate get_stream_url function
"""

import os
import re

def fix_duplicate_route():
    """Remove duplicate get_stream_url function from app.py"""
    
    app_file = 'app.py'
    
    if not os.path.exists(app_file):
        print(f"Error: {app_file} not found!")
        return False
    
    print("Reading app.py...")
    with open(app_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find all occurrences of the get_stream_url function
    pattern = r"@app\.route\('/get_stream_url/<int:stream_id>'\)\s*\ndef get_stream_url\(stream_id\):"
    matches = list(re.finditer(pattern, content))
    
    print(f"Found {len(matches)} occurrences of get_stream_url function")
    
    if len(matches) <= 1:
        print("No duplicate found or only one occurrence exists.")
        return True
    
    # Find the second occurrence and remove it along with its function body
    second_match = matches[1]
    start_pos = second_match.start()
    
    # Find the end of the second function by looking for the next @app.route or end of file
    next_route_pattern = r"\n@app\.route\("
    next_route_match = re.search(next_route_pattern, content[start_pos + 1:])
    
    if next_route_match:
        end_pos = start_pos + 1 + next_route_match.start()
    else:
        # If no next route found, look for the next function definition
        next_func_pattern = r"\ndef \w+\("
        next_func_match = re.search(next_func_pattern, content[start_pos + 1:])
        if next_func_match:
            end_pos = start_pos + 1 + next_func_match.start()
        else:
            # If nothing found, remove to end of file
            end_pos = len(content)
    
    # Extract the duplicate function for verification
    duplicate_function = content[start_pos:end_pos]
    print(f"Removing duplicate function (lines around {start_pos}):")
    print("=" * 50)
    print(duplicate_function[:200] + "..." if len(duplicate_function) > 200 else duplicate_function)
    print("=" * 50)
    
    # Remove the duplicate function
    new_content = content[:start_pos] + content[end_pos:]
    
    # Create backup
    backup_file = 'app_backup_fixed.py'
    print(f"Creating backup: {backup_file}")
    with open(backup_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    # Write the fixed content
    print("Writing fixed app.py...")
    with open(app_file, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print("✅ Duplicate function removed successfully!")
    print(f"Backup saved as: {backup_file}")
    
    return True

def verify_fix():
    """Verify that the fix worked"""
    print("\nVerifying fix...")
    
    try:
        # Try to compile the fixed app.py
        import py_compile
        py_compile.compile('app.py', doraise=True)
        print("✅ app.py compiles successfully!")
        
        # Check for remaining duplicates
        with open('app.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        pattern = r"@app\.route\('/get_stream_url/<int:stream_id>'\)"
        matches = re.findall(pattern, content)
        
        if len(matches) == 1:
            print("✅ Only one get_stream_url route remains!")
            return True
        else:
            print(f"❌ Still found {len(matches)} get_stream_url routes")
            return False
            
    except Exception as e:
        print(f"❌ Compilation error: {e}")
        return False

if __name__ == '__main__':
    print("GameBet App.py Duplicate Route Fixer")
    print("=" * 40)
    
    if fix_duplicate_route():
        if verify_fix():
            print("\n🎉 Fix completed successfully!")
            print("You can now run: python run_app.py")
        else:
            print("\n⚠️ Fix may not have worked completely. Check manually.")
    else:
        print("\n❌ Fix failed. Check the error messages above.")