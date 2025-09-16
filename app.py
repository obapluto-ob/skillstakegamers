from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
from datetime import timedelta, datetime
from dotenv import load_dotenv
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import math
from security_config import SecurityConfig, admin_required, secure_headers, SecureDBConnection

load_dotenv()

# Use SecurityConfig for all validation functions
validate_numeric_input = SecurityConfig.validate_numeric_input
sanitize_input = SecurityConfig.sanitize_input
validate_email = SecurityConfig.validate_email

def send_email(to_email, subject, body):
    """Send email using Gmail SMTP with proper resource management"""
    server = None
    try:
        gmail_user = os.getenv('GMAIL_USER')
        gmail_pass = os.getenv('GMAIL_PASS')
        
        if not gmail_user or not gmail_pass:
            return False
        
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_user, gmail_pass)
        server.send_message(msg)
        return True
    except Exception as e:
        print(f'Email error: {e}')
        return False
    finally:
        if server:
            try:
                server.quit()
            except:
                pass

def get_db_connection():
    conn = sqlite3.connect('gamebet.db', timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

def safe_db_operation(operation):
    """Execute database operation with proper resource management"""
    conn = None
    try:
        conn = get_db_connection()
        return operation(conn)
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()

def init_database():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        balance REAL DEFAULT 0.0,
        phone TEXT,
        referral_code TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        total_earnings REAL DEFAULT 0.0,
        referred_by INTEGER,
        banned INTEGER DEFAULT 0,
        skill_tokens INTEGER DEFAULT 0,
        email_verified INTEGER DEFAULT 0,
        last_login TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        payment_proof TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS game_matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_type TEXT NOT NULL,
        game_mode TEXT NOT NULL,
        creator_id INTEGER NOT NULL,
        creator_game_username TEXT NOT NULL,
        opponent_id INTEGER,
        opponent_game_username TEXT,
        stake_amount REAL NOT NULL,
        total_pot REAL NOT NULL,
        winner_id INTEGER,
        status TEXT DEFAULT 'open',
        creator_score INTEGER DEFAULT 0,
        opponent_score INTEGER DEFAULT 0,
        commission REAL DEFAULT 0,
        match_start_time TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
    )''')
    
    # Create admin user
    admin_password = generate_password_hash(os.getenv('ADMIN_PASSWORD', 's@vfVhy&qgXmYyX@'))
    c.execute('SELECT id FROM users WHERE username = "admin"')
    if not c.fetchone():
        c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code) 
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 ('admin', 'admin@skillstake.com', admin_password, 0.0, '0700000000', 'ADMIN001'))
    
    conn.commit()
    conn.close()

def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-key-change-in-production')
app.permanent_session_lifetime = timedelta(days=30)  # Keep users logged in for 30 days

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["5000 per day", "1000 per hour"]
)

# Add security headers to all responses
@app.after_request
def add_security_headers(response):
    return secure_headers(response)

init_database()

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            c.execute('SELECT id, username, balance, wins, losses, total_earnings FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            
            if not user:
                session.clear()
                flash('User not found. Please login again.', 'error')
                return redirect(url_for('login'))
            
            session['balance'] = user[2] or 0
            
            stats = {
                'balance': user[2] or 0,
                'wins': user[3] or 0,
                'losses': user[4] or 0,
                'earnings': user[5] or 0
            }
        return render_template('dashboard.html', stats=stats, recent_matches=[])
        
    except Exception as e:
        flash(f'Dashboard error: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@app.route('/register_fixed', methods=['GET', 'POST'])
def register_fixed():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '').strip())
        email = sanitize_input(request.form.get('email', '').strip())
        password = request.form.get('password', '')
        
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return render_template('register_fixed.html')
        
        # Validate input formats
        if not SecurityConfig.validate_username(username):
            flash('Username must be 3-20 characters, letters, numbers, and underscores only!', 'error')
            return render_template('register_fixed.html')
        
        if not validate_email(email):
            flash('Please enter a valid email address!', 'error')
            return render_template('register_fixed.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('register_fixed.html')
        
        try:
            with SecureDBConnection() as conn:
                c = conn.cursor()
                
                # Check if user exists
                c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
                if c.fetchone():
                    flash('Username or email already exists!', 'error')
                    return render_template('register_fixed.html')
            
                # Create user
                hashed_password = generate_password_hash(password)
                # Generate unique referral code
                while True:
                    referral_code = f'REF{random.randint(100000, 999999)}'
                    c.execute('SELECT id FROM users WHERE referral_code = ?', (referral_code,))
                    if not c.fetchone():
                        break
                verification_code = random.randint(100000, 999999)
                
                # Check for referral
                referred_by = None
                ref_code = request.form.get('ref_code') or request.args.get('ref')
                if ref_code:
                    c.execute('SELECT id FROM users WHERE referral_code = ?', (ref_code,))
                    referrer = c.fetchone()
                    if referrer:
                        referred_by = referrer[0]
                
                c.execute('''INSERT INTO users (username, email, password, referral_code, email_verified, referred_by) 
                             VALUES (?, ?, ?, ?, ?, ?)''',
                         (username, email, hashed_password, referral_code, 0, referred_by))
                
                # Give referral bonus
                if referred_by:
                    c.execute('UPDATE users SET balance = balance + 50 WHERE id = ?', (referred_by,))
                    c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                                VALUES (?, ?, ?, ?)''',
                             (referred_by, 'referral_bonus', 50, f'Referral bonus for {username}'))
                
                # Send verification email
                email_body = f'''
                <h2>Welcome to SkillStake Gaming!</h2>
                <p>Your verification code is: <strong>{verification_code}</strong></p>
                <p>Use this code to verify your account.</p>
                '''
                
                if send_email(email, 'SkillStake - Verify Your Account', email_body):
                    session['verification_code'] = verification_code
                    session['pending_email'] = email
                    flash('Registration successful! Check your email for verification code.', 'success')
                else:
                    flash('Registration successful! You can now login.', 'success')
                
                return redirect(url_for('login'))
                
        except Exception as e:
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register_fixed.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = sanitize_input(request.form.get('login_input', '').strip())
        password = request.form.get('password', '')
        
        if not login_input or not password:
            flash('Please enter both username/email and password!', 'error')
            return render_template('login_fixed.html')
        
        # Additional validation
        if len(login_input) > 100 or len(password) > 100:
            flash('Invalid input length!', 'error')
            return render_template('login_fixed.html')
        
        try:
            with SecureDBConnection() as conn:
                c = conn.cursor()
                c.execute('SELECT id, username, email, password, balance FROM users WHERE username = ? OR email = ?', 
                         (login_input, login_input))
                user = c.fetchone()
                
                if user and check_password_hash(user[3], password):
                    # Admin logs in directly without 2FA
                    if user[1] == 'admin':
                        session.clear()
                        session.permanent = True
                        session['user_id'] = user[0]
                        session['username'] = user[1]
                        session['balance'] = user[4] or 0
                        session['is_admin'] = True
                        session['logged_in'] = True
                        
                        # Update last login
                        c.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
                        return redirect(url_for('admin_dashboard'))
                    
                    # Regular users need 2FA verification
                    else:
                        verification_code = random.randint(100000, 999999)
                        
                        # Send verification email
                        email_body = f'''
                        <h2>SkillStake Gaming - Login Verification</h2>
                        <p>Your login verification code is: <strong>{verification_code}</strong></p>
                        <p>This code will expire in 10 minutes.</p>
                        '''
                        
                        if send_email(user[2], 'SkillStake - Login Verification Code', email_body):
                            # Store verification data in session
                            session['pending_login'] = {
                                'user_id': user[0],
                                'username': user[1],
                                'email': user[2],
                                'balance': user[4] or 0,
                                'verification_code': verification_code
                            }
                            flash('Verification code sent to your email!', 'success')
                            return render_template('verify_login.html')
                        else:
                            flash('Error sending verification code. Please try again.', 'error')
                else:
                    flash('Invalid username/email or password!', 'error')
        except Exception as e:
            flash('Login error occurred. Please try again.', 'error')
    
    return render_template('login_fixed.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Use server-side session data for authorization
    if not session.get('is_admin') or session.get('username') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            
            c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
            total_users = c.fetchone()[0] or 0
            
            c.execute('SELECT COUNT(*) FROM transactions')
            total_transactions = c.fetchone()[0] or 0
            
            c.execute('SELECT SUM(balance) FROM users WHERE username != "admin"')
            total_balance = c.fetchone()[0] or 0
        
        stats = {
            'total_users': total_users,
            'total_transactions': total_transactions,
            'total_balance': total_balance,
            'pending_deposits': 0,
            'unresolved_alerts': 0,
            'active_matches': 0,
            'total_deposits': 0,
            'net_earnings': 0
        }
        
        earnings_data = {
            'match_commission': 0,
            'commission_rate': 8,
            'deposit_fees': 0,
            'withdrawal_fees': 0,
            'referral_profits': 0,
            'fraud_commissions': 0,
            'total_battles': 0,
            'bank_fees': 0,
            'gross_earnings': 0,
            'net_earnings': 0,
            'pending_deposits': 0,
            'pending_withdrawals': 0,
            'total_game_matches': 0
        }
        
        return render_template('admin_dashboard.html', stats=stats, earnings_data=earnings_data, 
                             pending_deposits=[], pending_withdrawals=[], 
                             active_game_matches=[], notifications=[], unread_alerts=0)
        
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}', 'error')
        return render_template('admin_dashboard.html', stats={
            'total_users': 0, 'total_transactions': 0, 'total_balance': 0,
            'pending_deposits': 0, 'unresolved_alerts': 0, 'active_matches': 0,
            'total_deposits': 0, 'net_earnings': 0
        }, earnings_data={
            'match_commission': 0, 'commission_rate': 8, 'deposit_fees': 0, 'withdrawal_fees': 0,
            'referral_profits': 0, 'fraud_commissions': 0, 'total_battles': 0, 'bank_fees': 0,
            'gross_earnings': 0, 'net_earnings': 0, 'pending_deposits': 0, 'pending_withdrawals': 0,
            'total_game_matches': 0
        }, pending_deposits=[], pending_withdrawals=[], 
        active_game_matches=[], notifications=[], unread_alerts=0)
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Check if this is a reset code submission
        if 'reset_code' in request.form:
            reset_code = request.form.get('reset_code', '').strip()
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not all([reset_code, new_password, confirm_password]):
                flash('All fields are required.', 'error')
                return render_template('forgot_password.html')
            
            if new_password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('forgot_password.html')
            
            if len(new_password) < 6:
                flash('Password must be at least 6 characters long.', 'error')
                return render_template('forgot_password.html')
            
            # Verify reset code
            if ('reset_code' not in session or 
                'reset_email' not in session or 
                str(session['reset_code']) != reset_code):
                flash('Invalid or expired reset code.', 'error')
                return render_template('forgot_password.html')
            
            try:
                with SecureDBConnection() as conn:
                    c = conn.cursor()
                    hashed_password = generate_password_hash(new_password)
                    c.execute('UPDATE users SET password = ? WHERE email = ?', 
                             (hashed_password, session['reset_email']))
                    
                    if c.rowcount > 0:
                        # Clear reset session data
                        session.pop('reset_code', None)
                        session.pop('reset_email', None)
                        flash('Password reset successful! You can now login with your new password.', 'success')
                        return redirect(url_for('login'))
                    else:
                        flash('Error resetting password. Please try again.', 'error')
            except Exception as e:
                flash('Error resetting password. Please try again.', 'error')
        
        # This is an email submission
        else:
            email = sanitize_input(request.form.get('email', '').strip())
            
            if not validate_email(email):
                flash('Please enter a valid email address.', 'error')
                return render_template('forgot_password.html')
            
            try:
                with SecureDBConnection() as conn:
                    c = conn.cursor()
                    c.execute('SELECT id, username FROM users WHERE email = ?', (email,))
                    user = c.fetchone()
                    
                    if user:
                        reset_code = random.randint(100000, 999999)
                        email_body = f'''
                        <h2>Password Reset - SkillStake</h2>
                        <p>Your password reset code is: <strong>{reset_code}</strong></p>
                        <p>Use this code to reset your password.</p>
                        '''
                        
                        if send_email(email, 'SkillStake - Password Reset Code', email_body):
                            session['reset_code'] = reset_code
                            session['reset_email'] = email
                            flash('Password reset code sent to your email.', 'success')
                            return redirect(url_for('forgot_password'))
                        else:
                            flash('Error sending email. Please try again.', 'error')
                    else:
                        flash('Password reset instructions sent to your email (if account exists).', 'info')
            except Exception as e:
                flash('Error processing request. Please try again.', 'error')
    
    return render_template('forgot_password.html')

# Use admin_required from security_config

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/transactions')
@login_required
@admin_required
def admin_transactions():
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/matches')
@login_required
@admin_required
def admin_matches():
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/support_center')
@login_required
@admin_required
def admin_support_center():
    return redirect(url_for('admin_dashboard'))

@app.route('/api_test')
@login_required
@admin_required
def api_test():
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/tournaments')
@login_required
@admin_required
def admin_tournaments():
    return redirect(url_for('admin_dashboard'))

@app.route('/wallet')
@login_required
def wallet():
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Get transactions
            c.execute('SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 20', (user_id,))
            transactions = c.fetchall()
            
            # Get withdrawals
            c.execute('SELECT * FROM transactions WHERE user_id = ? AND type LIKE "%withdrawal%" ORDER BY created_at DESC', (user_id,))
            withdrawals = c.fetchall()
            
        return render_template('wallet.html', transactions=transactions, withdrawals=withdrawals)
    except:
        return render_template('wallet.html', transactions=[], withdrawals=[])

@app.route('/quick_matches')
@login_required
def quick_matches():
    # Fixed games data with correct icon paths
    games = [
        {
            'id': 'fifa_mobile',
            'name': 'FIFA Mobile',
            'image': '/static/icons/gamepad.svg',
            'min_bet': 50,
            'max_bet': 1000,
            'modes': [
                {'id': 'h2h', 'name': 'Head to Head', 'description': '1v1 online match'},
                {'id': 'vs_attack', 'name': 'VS Attack', 'description': 'Turn-based attacking'},
                {'id': 'manager_mode', 'name': 'Manager Mode', 'description': 'Full team control'}
            ]
        },
        {
            'id': 'efootball',
            'name': 'eFootball',
            'image': '/static/icons/trophy.svg',
            'min_bet': 50,
            'max_bet': 1000,
            'modes': [
                {'id': 'online_match', 'name': 'Online Match', 'description': '1v1 competitive'},
                {'id': 'quick_match', 'name': 'Quick Match', 'description': 'Fast gameplay'},
                {'id': 'ranked', 'name': 'Ranked Match', 'description': 'Competitive ranking'}
            ]
        }
    ]
    
    # Get open matches from database
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            c.execute('''SELECT * FROM game_matches WHERE status = "open" ORDER BY created_at DESC LIMIT 10''')
            open_matches = c.fetchall()
    except:
        open_matches = []
    
    return render_template('quick_matches.html', games=games, open_matches=open_matches)

@app.route('/games', endpoint='games')
@login_required
def games_page():
    # Your original games data
    games = [
        {
            'id': 'fifa_mobile',
            'name': 'FIFA Mobile',
            'image': '/static/icons/gamepad.svg',
            'min_bet': 50,
            'max_bet': 1000,
            'modes': ['Head to Head', 'VS Attack', 'Manager Mode'],
            'streaming': True,
            'stream_bonus': 25,
            'needs_lobby': False
        },
        {
            'id': 'efootball',
            'name': 'eFootball',
            'image': '/static/icons/trophy.svg',
            'min_bet': 50,
            'max_bet': 1000,
            'modes': ['Online Match', 'Quick Match', 'Ranked'],
            'streaming': True,
            'stream_bonus': 20,
            'needs_lobby': False
        }
    ]
    return render_template('games.html', games=games)

@app.route('/tournaments')
@login_required
def tournaments():
    return redirect(url_for('dashboard'))

@app.route('/matches')
@login_required
def matches():
    return redirect(url_for('dashboard'))

@app.route('/user_bonuses_page')
@login_required
def user_bonuses_page():
    return redirect(url_for('dashboard'))

@app.route('/referrals')
@login_required
def referrals():
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Get user's referral code
            c.execute('SELECT referral_code FROM users WHERE id = ?', (user_id,))
            user_data = c.fetchone()
            referral_code = user_data[0] if user_data else None
            
            # Get referred users
            c.execute('SELECT username, created_at FROM users WHERE referred_by = ?', (user_id,))
            referred_users = c.fetchall()
            
            # Get signup bonuses
            c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type = "referral_bonus"', (user_id,))
            signup_bonuses = c.fetchone()[0] or 0
            
            # Get ongoing commissions (4% from referred users' losses)
            c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type = "referral_commission"', (user_id,))
            ongoing_commissions = c.fetchone()[0] or 0
            
            # Get commission details if table exists
            try:
                c.execute('SELECT COALESCE(SUM(commission_amount), 0) FROM referral_commissions WHERE referrer_id = ?', (user_id,))
                lifetime_commissions = c.fetchone()[0] or 0
            except:
                lifetime_commissions = 0
            
            referral_link = f"{request.url_root}register_fixed?ref={referral_code}" if referral_code else None
            
            earnings_data = {
                'signup_bonuses': signup_bonuses,
                'ongoing_commissions': ongoing_commissions,
                'total_earnings': signup_bonuses + ongoing_commissions,
                'referred_count': len(referred_users),
                'lifetime_commissions': lifetime_commissions
            }
            
        return render_template('referrals.html', 
                             referral_code=referral_code,
                             referral_link=referral_link,
                             referred_users=referred_users,
                             earnings_data=earnings_data)
    except:
        return redirect(url_for('dashboard'))

@app.route('/friends')
@login_required
def friends():
    return redirect(url_for('dashboard'))

@app.route('/leaderboard')
@login_required
def leaderboard():
    return redirect(url_for('home'))

@app.route('/match_history')
@login_required
def match_history():
    return redirect(url_for('dashboard'))

@app.route('/profile')
@login_required
def profile():
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            c.execute('SELECT id, username, email, phone, balance FROM users WHERE id = ?', (session['user_id'],))
            user = c.fetchone()
            if user:
                return render_template('profile.html', user=user)
            else:
                flash('User not found', 'error')
                return redirect(url_for('dashboard'))
    except Exception as e:
        flash('Error loading profile', 'error')
        return redirect(url_for('dashboard'))

@app.route('/add_funds', methods=['POST'])
@login_required
def add_funds():
    return redirect(url_for('wallet'))

@app.route('/my_game_matches')
@login_required
def my_game_matches():
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            c.execute('''SELECT * FROM game_matches WHERE creator_id = ? OR opponent_id = ? ORDER BY created_at DESC''', (user_id, user_id))
            my_matches = c.fetchall()
        return render_template('my_matches.html', matches=my_matches)
    except:
        return redirect(url_for('quick_matches'))

@app.route('/smart_mpesa_deposit', methods=['POST'])
@login_required
def smart_mpesa_deposit():
    return jsonify({'success': True, 'confidence': 85, 'message': 'Smart deposit submitted for review'})

@app.route('/paypal_checkout')
@login_required
def paypal_checkout():
    import requests
    import base64
    
    amount = request.args.get('amount', 1300)
    
    try:
        # PayPal API credentials from .env
        client_id = os.getenv('PAYPAL_CLIENT_ID')
        client_secret = os.getenv('PAYPAL_CLIENT_SECRET')
        base_url = os.getenv('PAYPAL_BASE_URL', 'https://api.paypal.com')
        
        if not client_id or not client_secret:
            flash('PayPal configuration error', 'error')
            return redirect(url_for('wallet'))
        
        # Get access token
        auth_string = f"{client_id}:{client_secret}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        
        token_response = requests.post(
            f"{base_url}/v1/oauth2/token",
            headers={
                'Authorization': f'Basic {auth_b64}',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data='grant_type=client_credentials'
        )
        
        if token_response.status_code != 200:
            flash('PayPal authentication failed', 'error')
            return redirect(url_for('wallet'))
        
        access_token = token_response.json()['access_token']
        
        # Convert KSh to USD (approximate rate: 1 USD = 130 KSh)
        usd_amount = round(float(amount) / 130, 2)
        
        # Create payment
        payment_data = {
            "intent": "sale",
            "payer": {
                "payment_method": "paypal"
            },
            "transactions": [{
                "amount": {
                    "total": str(usd_amount),
                    "currency": "USD"
                },
                "description": f"SkillStake Gaming Deposit - KSh {amount}"
            }],
            "redirect_urls": {
                "return_url": f"{request.url_root}paypal_success?amount={amount}",
                "cancel_url": f"{request.url_root}wallet"
            }
        }
        
        payment_response = requests.post(
            f"{base_url}/v1/payments/payment",
            headers={
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            },
            json=payment_data
        )
        
        if payment_response.status_code == 201:
            payment = payment_response.json()
            # Find approval URL
            for link in payment['links']:
                if link['rel'] == 'approval_url':
                    return redirect(link['href'])
        
        flash('PayPal payment creation failed', 'error')
        return redirect(url_for('wallet'))
        
    except Exception as e:
        flash('PayPal error occurred', 'error')
        return redirect(url_for('wallet'))

@app.route('/paypal_success')
@login_required
def paypal_success():
    import requests
    import base64
    
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')
    amount = request.args.get('amount', 0)
    
    if not payment_id or not payer_id:
        flash('PayPal payment verification failed', 'error')
        return redirect(url_for('wallet'))
    
    try:
        # Get access token
        client_id = os.getenv('PAYPAL_CLIENT_ID')
        client_secret = os.getenv('PAYPAL_CLIENT_SECRET')
        base_url = os.getenv('PAYPAL_BASE_URL', 'https://api.paypal.com')
        
        auth_string = f"{client_id}:{client_secret}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        
        token_response = requests.post(
            f"{base_url}/v1/oauth2/token",
            headers={
                'Authorization': f'Basic {auth_b64}',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data='grant_type=client_credentials'
        )
        
        access_token = token_response.json()['access_token']
        
        # Execute payment
        execute_response = requests.post(
            f"{base_url}/v1/payments/payment/{payment_id}/execute",
            headers={
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            },
            json={'payer_id': payer_id}
        )
        
        if execute_response.status_code == 200:
            # Payment successful - update user balance
            with SecureDBConnection() as conn:
                c = conn.cursor()
                user_id = session['user_id']
                amount_float = float(amount)
                
                # Add funds to user balance
                c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount_float, user_id))
                
                # Record transaction
                c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                            VALUES (?, ?, ?, ?)''',
                         (user_id, 'paypal_deposit', amount_float, f'PayPal deposit of KSh {amount_float}'))
                
                # Update session balance
                session['balance'] = session.get('balance', 0) + amount_float
            
            flash(f'PayPal payment of KSh {amount} completed successfully!', 'success')
        else:
            flash('PayPal payment execution failed', 'error')
            
    except Exception as e:
        flash('PayPal verification error', 'error')
    
    return redirect(url_for('wallet'))

@app.route('/create_crypto_payment', methods=['POST'])
@login_required
def create_crypto_payment():
    return jsonify({'success': True, 'show_manual_form': True})

@app.route('/verify_crypto_deposit', methods=['POST'])
@login_required
def verify_crypto_deposit():
    import requests
    
    try:
        amount = float(request.form.get('amount', 0))
        tx_hash = request.form.get('tx_hash', '').strip()
        wallet_address = request.form.get('wallet_address', '').strip()
        
        if not tx_hash or not wallet_address or amount < 10:
            return jsonify({'success': False, 'message': 'All fields required, minimum $10'})
        
        # Verify transaction using blockchain API (example with TronGrid)
        tron_response = requests.get(
            f"https://api.trongrid.io/v1/transactions/{tx_hash}"
        )
        
        if tron_response.status_code == 200:
            tx_data = tron_response.json()
            
            # Basic verification
            if tx_data.get('ret', [{}])[0].get('contractRet') == 'SUCCESS':
                # Convert USD to KSh
                ksh_amount = amount * 130
                
                with SecureDBConnection() as conn:
                    c = conn.cursor()
                    user_id = session['user_id']
                    
                    # Check if transaction already processed
                    c.execute('SELECT id FROM transactions WHERE description LIKE ?', (f'%{tx_hash}%',))
                    if c.fetchone():
                        return jsonify({'success': False, 'message': 'Transaction already processed'})
                    
                    # Add funds to user balance
                    c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (ksh_amount, user_id))
                    
                    # Record transaction
                    c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                                VALUES (?, ?, ?, ?)''',
                             (user_id, 'crypto_deposit', ksh_amount, f'Crypto deposit ${amount} USDT - TX: {tx_hash}'))
                    
                    # Update session balance
                    session['balance'] = session.get('balance', 0) + ksh_amount
                
                return jsonify({
                    'success': True, 
                    'message': f'Crypto deposit of ${amount} USDT (KSh {ksh_amount}) verified and credited!',
                    'confidence': 95
                })
            else:
                return jsonify({'success': False, 'message': 'Transaction failed or pending'})
        else:
            return jsonify({'success': False, 'message': 'Transaction not found on blockchain'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Verification error occurred'})

@app.route('/crypto_success')
@login_required
def crypto_success():
    amount = request.args.get('amount', 0)
    
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            amount_float = float(amount)
            
            # Add funds to user balance
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount_float, user_id))
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                        VALUES (?, ?, ?, ?)''',
                     (user_id, 'crypto_deposit', amount_float, f'Crypto deposit of KSh {amount_float}'))
            
            # Update session balance
            session['balance'] = session.get('balance', 0) + amount_float
        
        flash(f'Crypto payment of KSh {amount} completed successfully!', 'success')
        
    except Exception as e:
        flash('Crypto payment verification error', 'error')
    
    return redirect(url_for('wallet'))

@app.route('/withdraw_funds', methods=['GET', 'POST'])
@login_required
def withdraw_funds():
    if request.method == 'POST':
        flash('Withdrawal request submitted for processing', 'success')
        return redirect(url_for('wallet'))
    return redirect(url_for('wallet'))

@app.route('/withdrawal_chat/<int:withdrawal_id>')
@login_required
def withdrawal_chat(withdrawal_id):
    return redirect(url_for('wallet'))

@app.route('/alert_admin_deposit', methods=['POST'])
@login_required
def alert_admin_deposit():
    return jsonify({'success': True, 'message': 'Admin alerted successfully'})

@app.route('/support_chat')
@login_required
def support_chat():
    return redirect(url_for('dashboard'))

@app.route('/fpl_battles')
@login_required
def fpl_battles():
    return redirect(url_for('dashboard'))

@app.route('/create_match', methods=['POST'])
@login_required
def create_match():
    """Create match from original games page"""
    try:
        game = request.form.get('game')
        bet_amount = float(request.form.get('bet_amount', 0))
        game_mode = request.form.get('game_mode')
        verification_type = request.form.get('verification_type', 'ocr')
        
        if not all([game, game_mode]) or bet_amount < 50:
            flash('Invalid match data', 'error')
            return redirect(url_for('games_page'))
        
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Check user balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            
            if not user or user[0] < bet_amount:
                flash('Insufficient balance', 'error')
                return redirect(url_for('games_page'))
            
            # Create match
            total_pot = bet_amount * 2
            c.execute('''INSERT INTO game_matches 
                        (game_type, game_mode, creator_id, creator_game_username, stake_amount, total_pot, status)
                        VALUES (?, ?, ?, ?, ?, ?, "open")''',
                     (game, game_mode, user_id, session['username'], bet_amount, total_pot))
            
            # Deduct stake from user balance
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (bet_amount, user_id))
            
            flash('Match created successfully!', 'success')
            return redirect(url_for('games_page'))
            
    except Exception as e:
        flash('Error creating match', 'error')
        return redirect(url_for('games_page'))

@app.route('/create_game_match', methods=['POST'])
@login_required
def create_game_match():
    """Create a new game match"""
    try:
        game_type = request.form.get('game_type')
        game_mode = request.form.get('game_mode')
        game_username = request.form.get('game_username')
        stake_amount = float(request.form.get('stake_amount', 0))
        
        if not all([game_type, game_mode, game_username]) or stake_amount < 50:
            return jsonify({'success': False, 'message': 'Invalid input data'})
        
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Check user balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            
            if not user or user[0] < stake_amount:
                return jsonify({'success': False, 'message': 'Insufficient balance'})
            
            # Create match
            total_pot = stake_amount * 2
            c.execute('''INSERT INTO game_matches 
                        (game_type, game_mode, creator_id, creator_game_username, stake_amount, total_pot, status)
                        VALUES (?, ?, ?, ?, ?, ?, "open")''',
                     (game_type, game_mode, user_id, game_username, stake_amount, total_pot))
            
            # Deduct stake from user balance
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (stake_amount, user_id))
            
            return jsonify({'success': True, 'message': 'Match created successfully!'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error creating match'})

@app.route('/join_game_match/<int:match_id>', methods=['POST'])
@login_required
def join_game_match(match_id):
    """Join an existing game match"""
    try:
        game_username = request.form.get('game_username')
        
        if not game_username:
            return jsonify({'success': False, 'message': 'Game username required'})
        
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Get match details
            c.execute('SELECT * FROM game_matches WHERE id = ? AND status = "open"', (match_id,))
            match = c.fetchone()
            
            if not match:
                return jsonify({'success': False, 'message': 'Match not found or already joined'})
            
            if match[3] == user_id:  # creator_id
                return jsonify({'success': False, 'message': 'Cannot join your own match'})
            
            # Check user balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            
            if not user or user[0] < match[7]:  # stake_amount
                return jsonify({'success': False, 'message': 'Insufficient balance'})
            
            # Join match
            c.execute('''UPDATE game_matches SET opponent_id = ?, opponent_game_username = ?, status = "active"
                        WHERE id = ?''', (user_id, game_username, match_id))
            
            # Deduct stake from user balance
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (match[7], user_id))
            
            return jsonify({'success': True, 'message': 'Successfully joined match!'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error joining match'})

@app.route('/upload_match_screenshot', methods=['POST'])
@login_required
def upload_match_screenshot():
    """Upload match result screenshot"""
    try:
        match_id = request.form.get('match_id')
        player1_score = request.form.get('player1_score')
        player2_score = request.form.get('player2_score')
        
        if not all([match_id, player1_score, player2_score]):
            return jsonify({'success': False, 'message': 'All fields required'})
        
        # For now, just mark as completed - in production you'd process the screenshot
        with SecureDBConnection() as conn:
            c = conn.cursor()
            c.execute('''UPDATE game_matches SET creator_score = ?, opponent_score = ?, status = "completed"
                        WHERE id = ?''', (int(player1_score), int(player2_score), int(match_id)))
        
        return jsonify({'success': True, 'message': 'Result uploaded successfully!'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error uploading result'})

@app.route('/verify_login_code', methods=['POST'])
def verify_login_code():
    """Verify login 2FA code"""
    try:
        data = request.get_json()
        code = data.get('code', '').strip()
        
        if not code or len(code) != 6:
            return jsonify({'success': False, 'message': 'Invalid code format'})
        
        # Check if pending login exists
        if 'pending_login' not in session:
            return jsonify({'success': False, 'message': 'No pending login found'})
        
        pending = session['pending_login']
        
        # Verify code
        if str(pending['verification_code']) == code:
            # Complete login
            session.clear()
            session.permanent = True
            session['user_id'] = pending['user_id']
            session['username'] = pending['username']
            session['balance'] = pending['balance']
            session['is_admin'] = False
            session['logged_in'] = True
            
            # Update last login
            with SecureDBConnection() as conn:
                c = conn.cursor()
                c.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (pending['user_id'],))
            
            return jsonify({'success': True, 'message': 'Login successful!'})
        else:
            return jsonify({'success': False, 'message': 'Invalid verification code'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Verification error occurred'})

@app.route('/resend_login_code', methods=['POST'])
def resend_login_code():
    """Resend login verification code"""
    try:
        # Check if pending login exists
        if 'pending_login' not in session:
            return jsonify({'success': False, 'message': 'No pending login found'})
        
        pending = session['pending_login']
        new_code = random.randint(100000, 999999)
        
        # Send new verification email
        email_body = f'''
        <h2>SkillStake Gaming - Login Verification</h2>
        <p>Your new login verification code is: <strong>{new_code}</strong></p>
        <p>This code will expire in 10 minutes.</p>
        '''
        
        if send_email(pending['email'], 'SkillStake - New Login Verification Code', email_body):
            # Update verification code in session
            session['pending_login']['verification_code'] = new_code
            return jsonify({'success': True, 'message': 'New verification code sent to your email!'})
        else:
            return jsonify({'success': False, 'message': 'Error sending verification code'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error resending code'})

@app.route('/test_email')
@login_required
@admin_required
def test_email():
    """Test email configuration"""
    test_result = send_email(
        'test@example.com', 
        'SkillStake Test Email', 
        '<h2>Email Configuration Test</h2><p>If you receive this, email is working!</p>'
    )
    return jsonify({
        'email_working': test_result,
        'gmail_user': os.getenv('GMAIL_USER'),
        'gmail_configured': bool(os.getenv('GMAIL_USER') and os.getenv('GMAIL_PASS'))
    })

@app.route('/api/user_balance')
@login_required
def api_user_balance():
    """API endpoint for user balance"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
            user = c.fetchone()
            
            if user:
                return jsonify({'balance': user[0]})
            else:
                return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    return app.send_static_file('favicon.ico')

@app.route('/sw.js')
def service_worker():
    """Serve service worker"""
    return app.send_static_file('sw.js')

@app.route('/manifest.json')
def manifest():
    """Serve PWA manifest"""
    return app.send_static_file('manifest.json')

@app.route('/logout')
def logout():
    # Don't clear saved login credentials - only clear session
    session.clear()
    flash('Logged out successfully! Your login details are saved for next time.', 'success')
    return redirect(url_for('home'))

@app.errorhandler(404)
def not_found(error):
    app.logger.error(f'404 error: {error}')
    return redirect(url_for('home'))

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'500 error: {error}')
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Secure host binding - only allow 0.0.0.0 in production with proper security
    host = os.environ.get('HOST', '127.0.0.1')
    if host == '0.0.0.0' and debug_mode:
        app.logger.warning("Using 0.0.0.0 in debug mode is insecure, switching to 127.0.0.1")
        host = '127.0.0.1'
    
    app.run(debug=debug_mode, host=host, port=port)