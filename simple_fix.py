#!/usr/bin/env python3
"""
Simple fix for duplicate get_stream_url function in app.py
"""

import os
import shutil

def fix_app_py():
    """Remove duplicate code after if __name__ == '__main__'"""
    
    app_file = 'app.py'
    
    print("Reading app.py...")
    with open(app_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    print(f"File has {len(lines)} lines")
    
    # Find the if __name__ == '__main__': line
    main_block_line = None
    for i, line in enumerate(lines):
        if line.strip().startswith("if __name__ == '__main__':"):
            main_block_line = i
            print(f"Found main block at line {i + 1}")
            break
    
    if main_block_line is None:
        print("Could not find main block")
        return False
    
    # Find app.run line
    app_run_line = None
    for i in range(main_block_line, len(lines)):
        if 'app.run(' in lines[i]:
            app_run_line = i
            print(f"Found app.run() at line {i + 1}")
            break
    
    if app_run_line is None:
        print("Could not find app.run() line")
        return False
    
    # Remove everything after app.run()
    end_line = app_run_line + 1
    
    if end_line < len(lines):
        print(f"Removing {len(lines) - end_line} lines after app.run()")
    
    # Create backup
    backup_file = f'{app_file}.backup'
    print(f"Creating backup: {backup_file}")
    shutil.copy2(app_file, backup_file)
    
    # Keep only lines up to app.run()
    fixed_lines = lines[:end_line]
    
    # Write fixed content
    print("Writing fixed app.py...")
    with open(app_file, 'w', encoding='utf-8') as f:
        f.writelines(fixed_lines)
    
    print(f"SUCCESS! Removed {len(lines) - end_line} lines")
    print(f"New file has {len(fixed_lines)} lines (was {len(lines)})")
    
    return True

def verify_fix():
    """Verify the fix worked"""
    print("\nVerifying fix...")
    
    try:
        import py_compile
        py_compile.compile('app.py', doraise=True)
        print("SUCCESS: app.py compiles without errors!")
        return True
    except Exception as e:
        print(f"ERROR: {e}")
        return False

if __name__ == '__main__':
    print("GameBet App.py Duplicate Route Fixer")
    print("=" * 40)
    
    if fix_app_py():
        if verify_fix():
            print("\nFIX COMPLETED SUCCESSFULLY!")
            print("You can now run: python run_app.py")
        else:
            print("\nFix may have issues. Check manually.")
    else:
        print("\nFix failed.")