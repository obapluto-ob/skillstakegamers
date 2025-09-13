#!/usr/bin/env python3
"""
Clean up duplicate files in the SkillStake project
Removes old/duplicate templates and keeps only the main working versions
"""

import os
import shutil

def cleanup_duplicates():
    """Remove duplicate files and keep only the main working versions"""
    
    # Files to remove (duplicates/old versions)
    files_to_remove = [
        'templates/login.html',
        'templates/register.html', 
        'templates/forgot_password.html',
        'templates/admin_users.html',
        'templates/login_secure.html',
        'templates/register_new.html',
        'templates/dashboard_simple.html',
        'templates/match_lobby_simple.html',
        'templates/base_simple.html',
        'templates/enhanced_home.html',
        'templates/admin_dashboard_new.html'
    ]
    
    # Backup files to remove
    backup_files = [
        'app_backup.py',
        'app_backup_20250903_140758.py',
        'app_cleaned.py',
        'app_fixed.py',
        'app_fixes.py',
        'app.py.backup',
        'complete_app_end.py',
        'deploy_safe.py',
        'fix_app.py',
        'simple_deploy.py',
        'simple_fix.py',
        'simple_test.py'
    ]
    
    # Database backup files (keep only latest)
    db_backups = [
        'gamebet_backup_1756682444.db',
        'gamebet_backup_1756683169.db',
        'gamebet_backup_1756683349.db'
    ]
    
    # Documentation files to remove (outdated)
    old_docs = [
        'ADMIN_USERS_FIX.md',
        'AI_TESTING_GUIDE.md',
        'CRITICAL_FIXES.md',
        'DEPLOYMENT_GUIDE.md',
        'DEPLOYMENT_INSTRUCTIONS.md',
        'EMAIL_VERIFICATION_COMPLETE.md',
        'FIX_INSTRUCTIONS.md',
        'FIX_SUMMARY.md',
        'FIXES_SUMMARY.md',
        'GMAIL_SETUP.md',
        'INSTALLATION_GUIDE.md',
        'PLATFORM_REVENUE_EXPLAINED.md',
        'QUICK_FIX.md',
        'README_SECURITY.md',
        'RECOVERY_INSTRUCTIONS.md',
        'REFERRAL_AND_REVENUE_ANALYSIS.md',
        'SECURITY_COMPLETE.md',
        'SECURITY_FIXES_SUMMARY.md',
        'SECURITY_UPGRADE.md',
        'SETUP_POSTGRESQL.md',
        'TESTING_GUIDE.md',
        'WALLET_IMPROVEMENTS.md'
    ]
    
    # Utility scripts to remove (no longer needed)
    old_scripts = [
        'admin_clear_limits.py',
        'apply_security_fixes.py',
        'backup_users.py',
        'check_lost_users.py',
        'check_setup.py',
        'check_users_table.py',
        'clear_rate_limits.py',
        'create_real_backup.py',
        'critical_security_patches.py',
        'database_migration.py',
        'db_utils.py',
        'email_auth.py',
        'email_validator.py',
        'email_verification.py',
        'error_handler.py',
        'final_security_enhancements.py',
        'financial_utils.py',
        'find_lost_users.py',
        'fix_all_indents.py',
        'fix_api_endpoints.py',
        'fix_chat_utf8.py',
        'fix_chat.py',
        'fix_create_match.py',
        'fix_duplicate_route.py',
        'fix_frontend_issues.py',
        'fix_indentation.py',
        'fix_real_users.py',
        'fix_user_buttons.py',
        'fix_user_stats.py',
        'improved_error_handler.py',
        'init_db.py',
        'install_ai_dependencies.py',
        'install_security_fixes.py',
        'login_fix.py',
        'manual_user_recovery.py',
        'match_utils.py',
        'memory_sms.py',
        'migrate_to_postgresql.py',
        'missing_imports.py',
        'monitor.py',
        'paypal_config.py',
        'performance_utils.py',
        'quick_fix_database.py',
        'rate_limiter.py',
        'recover_users.py',
        'restore_after_deploy.py',
        'restore_users.py',
        'run_app.py',
        'safe_backup.py',
        'security_enhancements.py',
        'security_fixes.py',
        'security_utils.py',
        'security.py',
        'session_manager.py',
        'setup_ai_system.bat',
        'setup_ai_system.sh',
        'setup_persistent_db.py',
        'smart_rate_limiting.py',
        'smart_verification.py',
        'start_production.py',
        'update_database_connections.py',
        'validation.py',
        'validators.py'
    ]
    
    # Test files to remove
    test_files = [
        'test_api.py',
        'test_apis.py',
        'test_app.py',
        'test_buttons.py',
        'test_crypto.py',
        'test_email_debug.py',
        'test_email_direct.py',
        'test_email_simple_debug.py',
        'test_email_simple_final.py',
        'test_email_simple.py',
        'test_email_system.py',
        'test_email_verification.py',
        'test_final_email.py',
        'test_final_system.py',
        'test_fix.py',
        'test_fund_flow.py',
        'test_gmail_direct.py',
        'test_live_email.py',
        'test_real_email.py',
        'test_registration_email.py',
        'test_registration_flow.py',
        'test_registration.py',
        'test_security.py'
    ]
    
    # Combine all files to remove
    all_files_to_remove = (
        files_to_remove + 
        backup_files + 
        db_backups + 
        old_docs + 
        old_scripts + 
        test_files
    )
    
    removed_count = 0
    errors = []
    
    print("🧹 Cleaning up duplicate and unnecessary files...")
    
    for file_path in all_files_to_remove:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"✅ Removed: {file_path}")
                removed_count += 1
            except Exception as e:
                error_msg = f"❌ Error removing {file_path}: {e}"
                print(error_msg)
                errors.append(error_msg)
        else:
            print(f"⚠️  Not found: {file_path}")
    
    # Clean up empty directories
    empty_dirs = []
    for root, dirs, files in os.walk('.'):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            try:
                if not os.listdir(dir_path):  # Directory is empty
                    empty_dirs.append(dir_path)
            except:
                pass
    
    for empty_dir in empty_dirs:
        try:
            os.rmdir(empty_dir)
            print(f"✅ Removed empty directory: {empty_dir}")
            removed_count += 1
        except:
            pass
    
    print(f"\n🎉 Cleanup complete!")
    print(f"📊 Files removed: {removed_count}")
    print(f"❌ Errors: {len(errors)}")
    
    if errors:
        print("\n❌ Errors encountered:")
        for error in errors:
            print(f"  {error}")
    
    # Show remaining important files
    important_files = [
        'app.py',
        'requirements.txt',
        '.env',
        'README.md',
        'gamebet.db'
    ]
    
    print(f"\n📁 Important files kept:")
    for file_path in important_files:
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            print(f"  ✅ {file_path} ({size:,} bytes)")
        else:
            print(f"  ❌ {file_path} (missing)")
    
    # Show template files kept
    template_files = [
        'templates/login_fixed.html',
        'templates/register_fixed.html',
        'templates/forgot_password_fixed.html',
        'templates/admin_users_fixed.html',
        'templates/dashboard.html',
        'templates/wallet.html',
        'templates/base.html'
    ]
    
    print(f"\n📄 Template files kept:")
    for file_path in template_files:
        if os.path.exists(file_path):
            print(f"  ✅ {file_path}")
        else:
            print(f"  ❌ {file_path} (missing)")

if __name__ == "__main__":
    cleanup_duplicates()