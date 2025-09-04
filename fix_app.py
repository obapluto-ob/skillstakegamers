#!/usr/bin/env python3
"""
Fix the duplicate get_stream_url function in app.py
The duplicate appears after the if __name__ == '__main__': block
"""

import os
import shutil

def fix_app_py():
    """Remove the duplicate get_stream_url function and any code after if __name__ == '__main__'"""
    
    app_file = 'app.py'
    
    if not os.path.exists(app_file):
        print(f"❌ Error: {app_file} not found!")
        return False
    
    print("📖 Reading app.py...")
    
    try:
        with open(app_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return False
    
    print(f"📄 File has {len(lines)} lines")
    
    # Find the if __name__ == '__main__': line
    main_block_line = None
    for i, line in enumerate(lines):
        if line.strip().startswith("if __name__ == '__main__':"):
            main_block_line = i
            print(f"🔍 Found if __name__ == '__main__': at line {i + 1}")
            break
    
    if main_block_line is None:
        print("❌ Could not find if __name__ == '__main__': block")
        return False
    
    # Find where the main block ends (look for the app.run line)
    app_run_line = None
    for i in range(main_block_line, len(lines)):
        if 'app.run(' in lines[i]:
            app_run_line = i
            print(f"🔍 Found app.run() at line {i + 1}")
            break
    
    if app_run_line is None:
        print("❌ Could not find app.run() line")
        return False
    
    # Everything after app.run() should be removed (that's where the duplicate is)
    end_line = app_run_line + 1
    
    # Check if there's content after the main block
    if end_line < len(lines):
        print(f"🗑️  Found {len(lines) - end_line} lines after app.run() that will be removed")
        print("📋 Content to be removed:")
        for i in range(end_line, min(end_line + 5, len(lines))):
            print(f"   Line {i + 1}: {lines[i].rstrip()}")
        if len(lines) - end_line > 5:
            print(f"   ... and {len(lines) - end_line - 5} more lines")
    
    # Create backup
    backup_file = f'{app_file}.backup'
    print(f"💾 Creating backup: {backup_file}")
    try:
        shutil.copy2(app_file, backup_file)
    except Exception as e:
        print(f"❌ Error creating backup: {e}")
        return False
    
    # Keep only lines up to and including app.run()
    fixed_lines = lines[:end_line]
    
    # Write the fixed content
    print("✏️  Writing fixed app.py...")
    try:
        with open(app_file, 'w', encoding='utf-8') as f:
            f.writelines(fixed_lines)
    except Exception as e:
        print(f"❌ Error writing file: {e}")
        return False
    
    print(f"✅ Fixed! Removed {len(lines) - end_line} lines after app.run()")
    print(f"📄 New file has {len(fixed_lines)} lines (was {len(lines)})")
    
    return True

def verify_fix():
    """Verify that the fix worked by checking for syntax errors"""
    print("\n🔍 Verifying fix...")
    
    try:
        # Try to compile the fixed app.py
        import py_compile
        py_compile.compile('app.py', doraise=True)
        print("✅ app.py compiles successfully!")
        
        # Check for duplicate routes
        with open('app.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        import re
        pattern = r"@app\.route\('/get_stream_url/<int:stream_id>'\)"
        matches = re.findall(pattern, content)
        
        if len(matches) == 1:
            print("✅ Only one get_stream_url route remains!")
            return True
        elif len(matches) == 0:
            print("⚠️  No get_stream_url route found (this might be okay)")
            return True
        else:
            print(f"❌ Still found {len(matches)} get_stream_url routes")
            return False
            
    except SyntaxError as e:
        print(f"❌ Syntax error in fixed file: {e}")
        return False
    except Exception as e:
        print(f"❌ Compilation error: {e}")
        return False

def main():
    print("🔧 GameBet App.py Duplicate Route Fixer")
    print("=" * 50)
    
    # Check if app.py exists
    if not os.path.exists('app.py'):
        print("❌ app.py not found in current directory!")
        print("📁 Current directory contents:")
        for item in os.listdir('.'):
            if item.endswith('.py'):
                print(f"   📄 {item}")
        return
    
    # Get file info
    file_size = os.path.getsize('app.py')
    print(f"📊 app.py size: {file_size:,} bytes")
    
    # Perform the fix
    if fix_app_py():
        if verify_fix():
            print("\n🎉 Fix completed successfully!")
            print("🚀 You can now run: python run_app.py")
            print("💾 Backup saved as: app.py.backup")
        else:
            print("\n⚠️  Fix may not have worked completely.")
            print("🔍 Please check the file manually.")
    else:
        print("\n❌ Fix failed. Check the error messages above.")
        print("💾 Original file is unchanged.")

if __name__ == '__main__':
    main()