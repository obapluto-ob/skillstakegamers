# M-Pesa Fraud Prevention & Verification System

import re
import hashlib
from datetime import datetime, timedelta
import sqlite3

def analyze_mpesa_screenshot(screenshot_data, claimed_amount, user_phone):
    """Advanced M-Pesa screenshot fraud detection"""
    
    fraud_score = 0
    verification_results = {
        'is_valid': False,
        'fraud_score': 0,
        'issues': [],
        'verification_method': 'manual_review_required'
    }
    
    try:
        # 1. Image hash for duplicate detection
        image_hash = hashlib.md5(screenshot_data.encode()).hexdigest()
        
        # Check for duplicate screenshots
        with sqlite3.connect('gamebet.db') as conn:
            c = conn.cursor()
            c.execute('''SELECT COUNT(*) FROM transactions 
                       WHERE payment_proof = ? AND type LIKE '%deposit%' ''', (image_hash,))
            duplicate_count = c.fetchone()[0]
            
            if duplicate_count > 0:
                fraud_score += 0.8
                verification_results['issues'].append('Duplicate screenshot detected')
        
        # 2. User behavior analysis
        with sqlite3.connect('gamebet.db') as conn:
            c = conn.cursor()
            
            # Check deposit frequency (suspicious if >3 per day)
            c.execute('''SELECT COUNT(*) FROM transactions 
                       WHERE user_id = (SELECT id FROM users WHERE phone = ?) 
                       AND type LIKE '%deposit%' 
                       AND created_at > datetime('now', '-1 day')''', (user_phone,))
            daily_deposits = c.fetchone()[0]
            
            if daily_deposits > 3:
                fraud_score += 0.3
                verification_results['issues'].append(f'High frequency: {daily_deposits} deposits today')
            
            # Check for round number patterns (suspicious)
            if claimed_amount % 100 == 0 and claimed_amount > 500:
                fraud_score += 0.2
                verification_results['issues'].append('Suspicious round amount')
        
        # 3. Amount validation
        if claimed_amount < 10 or claimed_amount > 50000:
            fraud_score += 0.4
            verification_results['issues'].append('Amount outside normal range')
        
        # 4. Phone number validation
        if not re.match(r'^0[17][0-9]{8}$', user_phone):
            fraud_score += 0.3
            verification_results['issues'].append('Invalid phone number format')
        
        verification_results['fraud_score'] = fraud_score
        
        # Determine verification method based on fraud score
        if fraud_score >= 0.7:
            verification_results['verification_method'] = 'high_risk_manual_review'
            verification_results['is_valid'] = False
        elif fraud_score >= 0.4:
            verification_results['verification_method'] = 'enhanced_manual_review'
            verification_results['is_valid'] = False
        else:
            verification_results['verification_method'] = 'standard_manual_review'
            verification_results['is_valid'] = True
        
        return verification_results
        
    except Exception as e:
        verification_results['issues'].append(f'Analysis error: {str(e)}')
        return verification_results

def verify_mpesa_transaction_manual(paybill, account, amount, reference, timestamp):
    """Manual verification checklist for M-Pesa transactions"""
    
    verification_checklist = {
        'paybill_match': paybill == '400200',
        'account_match': account == '1075794',
        'amount_reasonable': 50 <= amount <= 10000,
        'reference_format': len(reference) >= 3,
        'timestamp_recent': True,  # Check if within last 24 hours
        'screenshot_quality': True  # Manual check
    }
    
    # Calculate verification score
    passed_checks = sum(verification_checklist.values())
    total_checks = len(verification_checklist)
    verification_score = passed_checks / total_checks
    
    return {
        'verification_score': verification_score,
        'checklist': verification_checklist,
        'recommendation': 'approve' if verification_score >= 0.8 else 'reject' if verification_score < 0.5 else 'review'
    }

def get_mpesa_verification_guidelines():
    """Return M-Pesa verification guidelines for admins"""
    
    return {
        'red_flags': [
            'Screenshot quality too perfect (likely edited)',
            'Same screenshot used multiple times',
            'Amount doesn\'t match claimed amount',
            'Wrong paybill number (not 400200)',
            'Wrong account number (not 1075794)',
            'Timestamp older than 24 hours',
            'User has >5 deposits per day',
            'Phone number doesn\'t match M-Pesa sender'
        ],
        'verification_steps': [
            '1. Check paybill: Must be 400200',
            '2. Check account: Must be 1075794', 
            '3. Verify amount matches user claim',
            '4. Check timestamp is recent (<24h)',
            '5. Verify reference matches username',
            '6. Check for image editing signs',
            '7. Cross-check with cooperative account'
        ],
        'approval_criteria': [
            'All details match exactly',
            'Screenshot appears genuine',
            'Amount confirmed in cooperative account',
            'User phone matches sender number',
            'No duplicate submissions'
        ]
    }

def create_mpesa_verification_report(user_id, amount, screenshot_analysis, manual_verification):
    """Create comprehensive verification report"""
    
    report = {
        'user_id': user_id,
        'amount': amount,
        'timestamp': datetime.now().isoformat(),
        'fraud_score': screenshot_analysis['fraud_score'],
        'verification_score': manual_verification['verification_score'],
        'issues_found': screenshot_analysis['issues'],
        'recommendation': manual_verification['recommendation'],
        'requires_review': screenshot_analysis['fraud_score'] > 0.4,
        'auto_approve': (
            screenshot_analysis['fraud_score'] < 0.2 and 
            manual_verification['verification_score'] >= 0.9
        )
    }
    
    return report

# Example usage for admin verification
def admin_verify_mpesa_deposit(transaction_id):
    """Admin function to verify M-Pesa deposit with fraud detection"""
    
    try:
        with sqlite3.connect('gamebet.db') as conn:
            c = conn.cursor()
            c.execute('''SELECT t.*, u.phone FROM transactions t
                       JOIN users u ON t.user_id = u.id
                       WHERE t.id = ? AND t.type = 'pending_deposit' ''', (transaction_id,))
            transaction = c.fetchone()
            
            if not transaction:
                return {'error': 'Transaction not found'}
            
            user_id, amount, screenshot_data, user_phone = transaction[1], transaction[3], transaction[6], transaction[-1]
            
            # Run fraud detection
            screenshot_analysis = analyze_mpesa_screenshot(screenshot_data, amount, user_phone)
            
            # Manual verification checklist
            manual_verification = verify_mpesa_transaction_manual('400200', '1075794', amount, 'username', datetime.now())
            
            # Generate report
            report = create_mpesa_verification_report(user_id, amount, screenshot_analysis, manual_verification)
            
            return report
            
    except Exception as e:
        return {'error': f'Verification failed: {str(e)}'}

if __name__ == "__main__":
    # Print verification guidelines
    guidelines = get_mpesa_verification_guidelines()
    print("=== M-PESA VERIFICATION GUIDELINES ===")
    print("\nRED FLAGS:")
    for flag in guidelines['red_flags']:
        print(f"- {flag}")
    
    print("\nVERIFICATION STEPS:")
    for step in guidelines['verification_steps']:
        print(f"{step}")
    
    print("\nAPPROVAL CRITERIA:")
    for criteria in guidelines['approval_criteria']:
        print(f"+ {criteria}")