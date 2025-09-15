from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
from datetime import timedelta, datetime
from dotenv import load_dotenv
import requests
import json
import threading
import time
import schedule
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Import database components
from database_manager import db_manager
from database import init_database, get_db_connection

# Import route blueprints
from routes.auth_routes import auth_bp
from routes.main_routes import main_bp
from routes.admin_routes import admin_bp

# Store verification codes temporarily
verification_codes = {}
reset_codes = {}

load_dotenv()

# Simple fallback functions
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-key-change-in-production')
app.permanent_session_lifetime = timedelta(hours=24)

# Rate limiting configuration - Very generous limits
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["5000 per day", "1000 per hour"]
)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(admin_bp)

# Initialize database
init_db()

# GAMING ROUTES - Keep all existing gaming functionality
@app.route('/games')
@login_required
def games():
    return render_template('games_hub.html')

@app.route('/games_hub')
@login_required
def games_hub():
    return render_template('games_hub.html')

@app.route('/quick_matches')
@login_required
def quick_matches():
    # Update user balance in session
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
            user_balance = c.fetchone()
            if user_balance:
                session['balance'] = user_balance[0]
    except:
        pass
    
    games_list = [
        {
            'id': 'fifa_mobile',
            'name': 'FIFA Mobile',
            'min_bet': 50,
            'max_bet': 1000,
            'image': 'https://cdn.cloudflare.steamstatic.com/steam/apps/1811260/header.jpg',
            'modes': [
                {'id': 'h2h', 'name': 'Head to Head', 'description': '11v11 online matches'},
                {'id': 'vsa', 'name': 'VS Attack', 'description': 'Turn-based attacking gameplay'}
            ]
        },
        {
            'id': 'efootball',
            'name': 'eFootball',
            'min_bet': 50,
            'max_bet': 1000,
            'image': 'https://shared.akamai.steamstatic.com/store_item_assets/steam/apps/1665460/header.jpg',
            'modes': [
                {'id': 'quick_match', 'name': 'Quick Match', 'description': 'Fast 1v1 online matches'},
                {'id': 'online_match', 'name': 'Online Match', 'description': '1v1 competitive matches'}
            ]
        }
    ]
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            c.execute('''SELECT gm.*, u.username as creator_name
                       FROM game_matches gm
                       JOIN users u ON gm.creator_id = u.id
                       WHERE gm.status = "open" AND gm.creator_id != ?
                       ORDER BY gm.created_at DESC LIMIT 10''', (user_id,))
            open_matches = c.fetchall()
    except:
        open_matches = []
    
    return render_template('quick_matches.html', games=games_list, open_matches=open_matches)

@app.route('/create_game_match', methods=['POST'])
@login_required
def create_game_match():
    try:
        # Get form data
        game_type = request.form.get('game_type', '').strip()
        game_mode = request.form.get('game_mode', '').strip()
        stake_amount = request.form.get('stake_amount', '').strip()
        game_username = request.form.get('game_username', '').strip()
        
        # Validation
        if not all([game_type, game_mode, stake_amount, game_username]):
            return jsonify({'success': False, 'message': 'Please fill in all fields'})
        
        try:
            stake = float(stake_amount)
            if not (50 <= stake <= 1000):
                return jsonify({'success': False, 'message': 'Stake must be between 50 and 1000 KSh'})
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid stake amount'})
        
        if session.get('balance', 0) < stake:
            return jsonify({'success': False, 'message': 'Insufficient balance. Please deposit funds'})
        
        # Create match
        with get_db_connection() as conn:
            c = conn.cursor()
            
            commission = stake * 0.08
            total_pot = (stake * 2) - commission
            
            # Update user balance
            new_balance = session['balance'] - stake
            c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
            session['balance'] = new_balance
            
            # Insert match
            c.execute('''INSERT INTO game_matches 
                       (game_type, game_mode, creator_id, creator_game_username, stake_amount, total_pot, commission) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (game_type, game_mode, session['user_id'], game_username, stake, total_pot, commission))
            
            # Add transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                       VALUES (?, ?, ?, ?)''',
                     (session['user_id'], 'match_stake', -stake, f'{game_type.title()} {game_mode} match - KSh {stake}'))
            
            conn.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Match created successfully! Game: {game_type.title()} | Mode: {game_mode.replace("_", " ").title()} | Stake: KSh {stake}'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error creating match. Please try again'})

@app.route('/join_game_match/<int:match_id>', methods=['POST'])
@login_required
def join_game_match(match_id):
    try:
        game_username = request.form.get('game_username', '').strip()
        
        if not game_username:
            return jsonify({'success': False, 'message': 'Game username is required'})
        
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get match details
            c.execute('SELECT * FROM game_matches WHERE id = ? AND status = "open"', (match_id,))
            match = c.fetchone()
            
            if not match:
                return jsonify({'success': False, 'message': 'Match not found or already started'})
            
            if match[3] == session['user_id']:  # creator_id
                return jsonify({'success': False, 'message': 'Cannot join your own match'})
            
            stake_amount = match[7]  # stake_amount
            if session.get('balance', 0) < stake_amount:
                return jsonify({'success': False, 'message': 'Insufficient balance'})
            
            # Update match and user balance
            new_balance = session['balance'] - stake_amount
            c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
            c.execute('UPDATE game_matches SET opponent_id = ?, opponent_game_username = ?, status = "active" WHERE id = ?', 
                     (session['user_id'], game_username, match_id))
            
            # Add transaction
            c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                     (session['user_id'], 'match_stake', -stake_amount, f'Joined {match[1]} {match[2]} match'))
            
            conn.commit()
            session['balance'] = new_balance
            
        return jsonify({'success': True, 'message': 'Successfully joined match! Match is now active.'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error joining match. Please try again.'})

# WALLET ROUTES - Keep all existing wallet functionality
@app.route('/wallet')
@login_required
def wallet():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            user_balance = c.fetchone()
            if user_balance:
                session['balance'] = user_balance[0]
            
            c.execute('''SELECT id, user_id, type, amount, description, created_at 
                       FROM transactions 
                       WHERE user_id = ? 
                       ORDER BY created_at DESC LIMIT 20''', (user_id,))
            transactions = c.fetchall()
            
            c.execute('''SELECT id, type, amount, description, created_at 
                       FROM transactions 
                       WHERE user_id = ? AND type IN ('pending_withdrawal', 'withdrawal', 'rejected_withdrawal')
                       ORDER BY created_at DESC LIMIT 10''', (user_id,))
            withdrawals = c.fetchall()
            
            return render_template('wallet.html', transactions=transactions, withdrawals=withdrawals)
    except Exception as e:
        return render_template('wallet.html', transactions=[], withdrawals=[])

# Keep all existing payment routes (M-Pesa, PayPal, Crypto)
@app.route('/smart_mpesa_deposit', methods=['POST'])
@login_required
def smart_mpesa_deposit():
    """🚀 POWERFUL M-Pesa deposit with smart validation and instant admin alerts"""
    try:
        data = request.get_json()
        amount = float(data.get('amount', 0))
        phone = data.get('phone', '').strip()
        transaction_code = data.get('transaction_code', '').strip().upper()
        sender_name = data.get('sender_name', '').strip()
        receipt_text = data.get('receipt_text', '').strip()
        
        if amount < 100:
            return jsonify({'success': False, 'error': 'Minimum deposit: KSh 100'})
        
        if not all([phone, transaction_code, sender_name]):
            return jsonify({'success': False, 'error': 'All fields required'})
        
        # 🧠 SYSTEM VALIDATION ENGINE
        validation_result = validate_mpesa_transaction(transaction_code, amount, phone, sender_name, receipt_text)
        
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Check for duplicate transaction codes
            c.execute('SELECT id FROM transactions WHERE description LIKE ?', (f'%{transaction_code}%',))
            if c.fetchone():
                return jsonify({'success': False, 'error': 'Transaction code already used'})
            
            # Create system deposit record
            description = f'SYSTEM M-Pesa deposit - {sender_name} ({phone}) - Code: {transaction_code} - KSh {amount} - Confidence: {validation_result["confidence"]}% - Status: {validation_result["status"]}'
            
            c.execute('''INSERT INTO transactions (user_id, type, amount, description, payment_proof) 
                       VALUES (?, ?, ?, ?, ?)''',
                     (session['user_id'], 'smart_pending_deposit', amount, description, receipt_text))
            
            transaction_id = c.lastrowid
            
            # 📧 INSTANT ADMIN ALERT
            send_admin_deposit_alert({
                'transaction_id': transaction_id,
                'user_id': session['user_id'],
                'username': session.get('username', 'Unknown'),
                'amount': amount,
                'phone': phone,
                'transaction_code': transaction_code,
                'sender_name': sender_name,
                'confidence': validation_result['confidence'],
                'status': validation_result['status'],
                'flags': validation_result['flags']
            })
            
            conn.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Deposit submitted! Confidence: {validation_result["confidence"]}% | Status: {validation_result["status"]} | Admin alerted instantly!',
            'transaction_id': transaction_id,
            'confidence': validation_result['confidence']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': 'Smart deposit failed'})

def validate_mpesa_transaction(code, amount, phone, sender_name, receipt_text):
    """🔍 POWERFUL M-Pesa validation engine"""
    confidence = 0
    flags = []
    
    # Transaction code validation (40 points max)
    if len(code) == 10 and code.isalnum():
        confidence += 25
        flags.append('✅ Valid code format')
    else:
        flags.append('⚠️ Invalid code format')
    
    import re
    if re.match(r'^[A-Z]{2}[0-9]{8}$', code) or re.match(r'^[0-9]{10}$', code):
        confidence += 15
        flags.append('✅ M-Pesa pattern match')
    else:
        flags.append('⚠️ Unusual code pattern')
    
    # Phone validation (20 points max)
    if phone.startswith('07') and len(phone) == 10 and phone[2:].isdigit():
        confidence += 15
        flags.append('✅ Valid Kenyan number')
    elif phone.startswith('254') and len(phone) == 12:
        confidence += 10
        flags.append('✅ International format')
    else:
        flags.append('⚠️ Invalid phone format')
    
    # Amount validation (15 points max)
    if amount in [100, 200, 500, 1000, 1500, 2000, 2500, 3000, 5000, 10000]:
        confidence += 10
        flags.append('✅ Common amount')
    elif amount % 50 == 0:
        confidence += 5
        flags.append('✅ Round amount')
    
    # Name validation (10 points max)
    if len(sender_name) >= 3 and sender_name.replace(' ', '').isalpha():
        confidence += 8
        flags.append('✅ Valid name format')
    else:
        flags.append('⚠️ Suspicious name')
    
    # Receipt text analysis (15 points max)
    if receipt_text:
        mpesa_keywords = ['confirmed', 'received', 'ksh', 'mpesa', 'paybill', 'till', 'balance']
        keyword_count = sum(1 for keyword in mpesa_keywords if keyword.lower() in receipt_text.lower())
        confidence += min(keyword_count * 2, 10)
        
        if str(amount) in receipt_text or str(int(amount)) in receipt_text:
            confidence += 5
            flags.append('✅ Amount matches receipt')
        
        if code in receipt_text:
            confidence += 5
            flags.append('✅ Code found in receipt')
    
    # Time-based validation (bonus points)
    import time
    current_hour = int(time.strftime('%H'))
    if 6 <= current_hour <= 22:  # Normal hours
        confidence += 5
        flags.append('✅ Normal transaction time')
    
    # Determine status
    if confidence >= 85:
        status = 'HIGH CONFIDENCE'
    elif confidence >= 65:
        status = 'MEDIUM CONFIDENCE'
    elif confidence >= 45:
        status = 'LOW CONFIDENCE'
    else:
        status = 'SUSPICIOUS'
    
    return {
        'confidence': min(confidence, 100),
        'status': status,
        'flags': flags
    }

def send_admin_deposit_alert(deposit_data):
    """📧 INSTANT admin email alert for deposits"""
    try:
        gmail_user = os.getenv('GMAIL_USER')
        gmail_pass = os.getenv('GMAIL_PASS')
        
        if not gmail_user or not gmail_pass:
            return False
        
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = gmail_user  # Send to admin email
        msg['Subject'] = f'🚨 URGENT: New M-Pesa Deposit - KSh {deposit_data["amount"]} ({deposit_data["status"]})'
        
        # Create rich HTML email
        confidence_color = '#28a745' if deposit_data['confidence'] >= 85 else '#ffc107' if deposit_data['confidence'] >= 65 else '#dc3545'
        
        body = f'''
        <html>
        <body style="font-family: Arial, sans-serif; background: #f8f9fa; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 15px; padding: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #667eea; margin: 0;">🎮 SkillStake Gaming</h1>
                    <h2 style="color: #dc3545; margin: 10px 0;">🚨 NEW M-PESA DEPOSIT ALERT</h2>
                </div>
                
                <div style="background: linear-gradient(135deg, {confidence_color}, {confidence_color}aa); color: white; padding: 20px; border-radius: 10px; margin: 20px 0; text-align: center;">
                    <h3 style="margin: 0;">💰 KSh {deposit_data['amount']:,.0f}</h3>
                    <p style="margin: 5px 0; font-size: 18px;">Confidence: {deposit_data['confidence']}%</p>
                    <p style="margin: 5px 0; font-weight: bold;">{deposit_data['status']}</p>
                </div>
                
                <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
                    <h4 style="color: #495057; margin-top: 0;">📋 Transaction Details</h4>
                    <p><strong>User:</strong> {deposit_data['username']} (ID: {deposit_data['user_id']})</p>
                    <p><strong>Phone:</strong> {deposit_data['phone']}</p>
                    <p><strong>Transaction Code:</strong> <code style="background: #e9ecef; padding: 5px; border-radius: 5px;">{deposit_data['transaction_code']}</code></p>
                    <p><strong>Sender Name:</strong> {deposit_data['sender_name']}</p>
                    <p><strong>Transaction ID:</strong> #{deposit_data['transaction_id']}</p>
                </div>
                
                <div style="background: #e3f2fd; padding: 20px; border-radius: 10px; margin: 20px 0;">
                    <h4 style="color: #1976d2; margin-top: 0;">🔍 Smart Analysis</h4>
                    {''.join([f'<p style="margin: 5px 0;">• {flag}</p>' for flag in deposit_data['flags']])}</div>
                
                <div style="text-align: center; color: #6c757d; font-size: 14px; margin-top: 30px;">
                    <p>⚡ Instant alert powered by SkillStake System Validation Engine</p>
                    <p>🕒 {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        '''
        
        msg.attach(MIMEText(body, 'html'))
        
        # Send email
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_user, gmail_pass)
        text = msg.as_string()
        server.sendmail(gmail_user, gmail_user, text)
        server.quit()
        
        return True
        
    except Exception as e:
        print(f'Admin alert failed: {e}')
        return False

# Keep all other existing routes...
@app.route('/matches')
@login_required
def matches():
    return redirect(url_for('quick_matches'))

@app.route('/my_battles')
@login_required
def my_battles():
    return redirect(url_for('my_fpl_battles'))

@app.errorhandler(404)
def not_found(error):
    return redirect(url_for('main.home'))

@app.errorhandler(500)
def internal_error(error):
    return redirect(url_for('main.home'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)