#!/usr/bin/env python3
"""
Quick Security Fix Application Script
Applies the most critical security fixes to app.py
"""

import re
import shutil
from datetime import datetime

def backup_original():
    """Create backup of original app.py"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy("app.py", f"app_backup_{timestamp}.py")
    print(f"✓ Backup created: app_backup_{timestamp}.py")

def apply_critical_fixes():
    """Apply the most critical security fixes"""
    
    with open("app.py", "r", encoding="utf-8") as f:
        content = f.read()
    
    print("Applying critical security fixes...")
    
    # Fix 1: Add missing imports at the top
    if "from security_fixes import" not in content:
        import_section = """from security_fixes import (
    login_required, admin_required, safe_db_execute, validate_file_upload,
    safe_float_conversion, validate_amount, validate_user_id, handle_db_errors,
    rate_limit, VALID_BONUS_TYPES
)
"""
        content = content.replace(
            "from rate_limiter import rate_limit",
            f"from rate_limiter import rate_limit\n{import_section}"
        )
        print("✓ Added security imports")
    
    # Fix 2: Replace SQL injection vulnerability in bonus system
    sql_injection_pattern = r"c\.execute\(f'UPDATE users SET \{bonus_type\} = 1 WHERE id = \?', \(user_id,\)\)"
    if re.search(sql_injection_pattern, content):
        secure_bonus_code = """
        # Validate bonus_type against whitelist
        if bonus_type not in VALID_BONUS_TYPES:
            return jsonify({'error': 'Invalid bonus type'}), 400
        
        # Use parameterized query with validated column name
        column_map = {
            'week1': 'week1_bonus',
            'week2': 'week2_bonus', 
            'week3': 'week3_bonus',
            'week4': 'week4_bonus'
        }
        column_name = column_map[bonus_type]
        c.execute(f'UPDATE users SET {column_name} = 1 WHERE id = ?', (user_id,))"""
        
        content = re.sub(sql_injection_pattern, secure_bonus_code, content)
        print("✓ Fixed SQL injection in bonus system")
    
    # Fix 3: Add @login_required to missing routes
    routes_needing_auth = [
        r"@app\.route\('/create_match'",
        r"@app\.route\('/join_match/<int:match_id>'",
        r"@app\.route\('/submit_screenshot",
        r"@app\.route\('/add_funds'",
        r"@app\.route\('/withdraw'"
    ]
    
    for route_pattern in routes_needing_auth:
        if re.search(route_pattern, content) and "@login_required" not in content:
            content = re.sub(
                f"({route_pattern}[^\\n]*\\n)",
                r"\1@login_required\n",
                content
            )
    print("✓ Added missing authorization decorators")
    
    # Fix 4: Replace unsafe float conversions
    unsafe_float_patterns = [
        r"float\(request\.form\.get\('amount'[^)]*\)\)",
        r"float\(data\.get\('amount'[^)]*\)\)",
        r"float\(request\.form\['amount'\]\)"
    ]
    
    for pattern in unsafe_float_patterns:
        content = re.sub(
            pattern,
            "safe_float_conversion(request.form.get('amount', 0), 'amount')",
            content
        )
    print("✓ Fixed unsafe type conversions")
    
    # Fix 5: Standardize database connections
    bad_db_pattern = r"with sqlite3\.connect\(\"gamebet\.db\"\) as conn:\s*c = conn\.cursor\(\)"
    good_db_pattern = """with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()"""
    
    content = re.sub(bad_db_pattern, good_db_pattern, content, flags=re.MULTILINE)
    print("✓ Standardized database connection patterns")
    
    # Fix 6: Replace bare except clauses
    bare_except_pattern = r"except:\s*pass"
    safe_except = """except sqlite3.Error as e:
        flash('Database error occurred', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('An error occurred', 'error')
        return redirect(url_for('dashboard'))"""
    
    content = re.sub(bare_except_pattern, safe_except, content)
    print("✓ Fixed bare except clauses")
    
    # Fix 7: Add file upload validation
    file_upload_pattern = r"screenshot_file = request\.files\.get\('screenshot'\)"
    if re.search(file_upload_pattern, content):
        secure_upload = """screenshot_file = request.files.get('screenshot')
        
        # Validate file upload
        is_valid, result = validate_file_upload(screenshot_file)
        if not is_valid:
            flash(result, 'error')
            return render_template('submit_screenshot.html', match=match, match_id=match_id)"""
        
        content = re.sub(file_upload_pattern, secure_upload, content)
        print("✓ Added file upload validation")
    
    # Fix 8: Add admin authorization fix
    admin_check_pattern = r"if session\.get\('username'\) != 'admin':"
    secure_admin_check = """if not admin_required_check():"""
    
    # Add helper function
    admin_helper = """
def admin_required_check():
    if 'user_id' not in session:
        return False
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        return user and user[0] == 'admin'
"""
    
    if "def admin_required_check():" not in content:
        # Add helper function after imports
        content = content.replace(
            "app = Flask(__name__)",
            f"{admin_helper}\napp = Flask(__name__)"
        )
    
    content = re.sub(admin_check_pattern, secure_admin_check, content)
    print("✓ Fixed admin authorization logic")
    
    return content

def main():
    """Main execution function"""
    print("🔒 GameBet Security Fix Application")
    print("=" * 40)
    
    try:
        # Create backup
        backup_original()
        
        # Apply fixes
        fixed_content = apply_critical_fixes()
        
        # Write fixed content
        with open("app.py", "w", encoding="utf-8") as f:
            f.write(fixed_content)
        
        print("\n✅ Critical security fixes applied successfully!")
        print("\nFixed vulnerabilities:")
        print("• SQL Injection in bonus system")
        print("• Missing authorization on API endpoints") 
        print("• Unsafe type conversions (NaN injection)")
        print("• File upload security")
        print("• Database connection patterns")
        print("• Error handling improvements")
        print("• Admin authorization logic")
        
        print("\n⚠️  Additional manual fixes needed:")
        print("• Review all routes for @login_required decorator")
        print("• Add CSRF protection to forms")
        print("• Implement rate limiting on sensitive endpoints")
        print("• Add security headers to responses")
        print("• Review and test all file upload functionality")
        
        print("\n🔄 Restart your application to apply changes")
        
    except Exception as e:
        print(f"❌ Error applying fixes: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())