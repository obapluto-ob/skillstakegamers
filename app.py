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

# Store verification codes temporarily
verification_codes = {}
reset_codes = {}

load_dotenv()

# Simple fallback functions
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def get_db_connection():
    # Check for external database URL first (for production)
    database_url = os.getenv('DATABASE_URL')
    if database_url:
        # For PostgreSQL or other external databases
        # This would require additional setup, but for now use SQLite
        pass
    
    # Always use local gamebet.db for persistence
    # /tmp gets wiped on Render deployments, so avoid it
    db_path = 'gamebet.db'
    return sqlite3.connect(db_path)

def init_db():
    with get_db_connection() as conn:
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
        
        # Create admin user only if not exists
        admin_password = generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin123'))
        c.execute('SELECT id FROM users WHERE username = "admin"')
        if not c.fetchone():
            c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code) 
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     ('admin', 'admin@skillstake.com', admin_password, 0.0, '0700000000', 'ADMIN001'))
        conn.commit()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-key-change-in-production')
app.permanent_session_lifetime = timedelta(hours=24)

# Rate limiting configuration - Very generous limits
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["5000 per day", "1000 per hour"]
)

init_db()

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/send_verification', methods=['POST'])
@limiter.limit("20 per hour")
def send_verification():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'})
        
        # Generate 6-digit code
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        # Store code with expiration (10 minutes)
        verification_codes[email] = {
            'code': code,
            'expires': datetime.now() + timedelta(minutes=10)
        }
        
        # Send email
        gmail_user = os.getenv('GMAIL_USER')
        gmail_pass = os.getenv('GMAIL_PASS')
        
        if not gmail_user or not gmail_pass:
            return jsonify({'success': False, 'message': 'Email service not configured'})
        
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = email
        msg['Subject'] = 'SkillStake - Email Verification Code'
        
        body = f'''
Welcome to SkillStake Gaming Platform!

Your verification code is: {code}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Happy Gaming!
SkillStake Team
        '''
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_user, gmail_pass)
        text = msg.as_string()
        server.sendmail(gmail_user, email, text)
        server.quit()
        
        return jsonify({'success': True, 'message': 'Verification code sent'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to send email: {str(e)}'})

@app.route('/register_with_verification', methods=['POST'])
@limiter.limit("10 per hour")
def register_with_verification():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')
        code = data.get('code', '').strip()
        
        if not all([username, email, password, code]):
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        # Verify code
        if email not in verification_codes:
            return jsonify({'success': False, 'message': 'No verification code found'})
        
        stored_data = verification_codes[email]
        if datetime.now() > stored_data['expires']:
            del verification_codes[email]
            return jsonify({'success': False, 'message': 'Verification code expired'})
        
        if stored_data['code'] != code:
            return jsonify({'success': False, 'message': 'Invalid verification code'})
        
        # Create user
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Check if user exists
            c.execute('SELECT id FROM users WHERE username = ?', (username,))
            if c.fetchone():
                return jsonify({'success': False, 'message': 'Username already taken'})
                
            c.execute('SELECT id FROM users WHERE email = ?', (email,))
            if c.fetchone():
                return jsonify({'success': False, 'message': 'Email already registered'})
                
            if phone:
                c.execute('SELECT id FROM users WHERE phone = ?', (phone,))
                if c.fetchone():
                    return jsonify({'success': False, 'message': 'Phone number already registered'})
            
            hashed_password = generate_password_hash(password)
            referral_code = username[:3].upper() + ''.join([str(random.randint(0, 9)) for _ in range(4)])
            
            c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code) 
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     (username, email, hashed_password, 0.0, phone, referral_code))
            conn.commit()
        
        # Clean up verification code
        del verification_codes[email]
        
        return jsonify({'success': True, 'message': 'Registration successful'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'})

@app.route('/register_secure', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register_secure():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not all([username, email, password]):
            flash('Please fill in all fields!', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters!', 'error')
            return render_template('register.html')
        
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
                if c.fetchone():
                    flash('Username or email already exists!', 'error')
                    return render_template('register.html')
                
                hashed_password = generate_password_hash(password)
                referral_code = f"REF{random.randint(100000, 999999)}"
                
                c.execute('''INSERT INTO users (username, email, password, referral_code) 
                           VALUES (?, ?, ?, ?)''', (username, email, hashed_password, referral_code))
                conn.commit()
                
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
        except Exception as e:
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def login():
    if request.method == 'POST':
        login_input = request.form.get('login_input', '').strip()
        password = request.form.get('password', '')
        
        if not login_input or not password:
            flash('Please enter both username/email and password!', 'error')
            return render_template('login_fixed.html')
        
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute('SELECT id, username, email, password, balance FROM users WHERE username = ? OR email = ?', 
                         (login_input, login_input))
                user = c.fetchone()
                
                if user and check_password_hash(user[3], password):
                    # Admin can login directly
                    if user[1] == 'admin':
                        session.clear()
                        session.permanent = True
                        session['user_id'] = user[0]
                        session['username'] = user[1]
                        session['balance'] = user[4]
                        session['is_admin'] = True
                        session['logged_in'] = True
                        return redirect(url_for('admin_dashboard'))
                    
                    # Regular users need email verification
                    session['pending_login'] = {
                        'user_id': user[0],
                        'username': user[1],
                        'email': user[2],
                        'balance': user[4]
                    }
                    
                    # Send login verification code
                    code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                    
                    verification_codes[user[2]] = {
                        'code': code,
                        'expires': datetime.now() + timedelta(minutes=10),
                        'type': 'login'
                    }
                    
                    # Send email
                    gmail_user = os.getenv('GMAIL_USER')
                    gmail_pass = os.getenv('GMAIL_PASS')
                    
                    msg = MIMEMultipart()
                    msg['From'] = gmail_user
                    msg['To'] = user[2]
                    msg['Subject'] = 'SkillStake - Login Verification Code'
                    
                    body = f'''
Login Verification Required

Your login verification code is: {code}

This code will expire in 10 minutes.

If you didn't try to login, please secure your account.

SkillStake Team
                    '''
                    
                    msg.attach(MIMEText(body, 'plain'))
                    
                    server = smtplib.SMTP('smtp.gmail.com', 587)
                    server.starttls()
                    server.login(gmail_user, gmail_pass)
                    text = msg.as_string()
                    server.sendmail(gmail_user, user[2], text)
                    server.quit()
                    
                    return redirect(url_for('verify_login'))
                else:
                    flash('Invalid username/email or password!', 'error')
                    return render_template('login_fixed.html')
        except Exception as e:
            flash('Login error occurred. Please try again.', 'error')
    
    return render_template('login_fixed.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            c.execute('SELECT id, username, balance FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            
            if not user:
                session.clear()
                flash('User not found. Please login again.', 'error')
                return redirect(url_for('login'))
            
            # Update session balance
            session['balance'] = user[2] or 0
            
            # Get user stats
            c.execute('SELECT COUNT(*) FROM game_matches WHERE (creator_id = ? OR opponent_id = ?) AND winner_id = ?', 
                     (user_id, user_id, user_id))
            wins = c.fetchone()[0] or 0
            
            c.execute('SELECT COUNT(*) FROM game_matches WHERE (creator_id = ? OR opponent_id = ?) AND winner_id IS NOT NULL AND winner_id != ?', 
                     (user_id, user_id, user_id))
            losses = c.fetchone()[0] or 0
            
            c.execute('SELECT SUM(amount) FROM transactions WHERE user_id = ? AND type LIKE "%win%"', (user_id,))
            earnings = c.fetchone()[0] or 0
            
            stats = {
                'balance': user[2] or 0,
                'wins': wins,
                'losses': losses,
                'earnings': earnings
            }
            
            # Get recent matches
            c.execute('''SELECT gm.*, u.username as opponent_name 
                       FROM game_matches gm 
                       LEFT JOIN users u ON (CASE WHEN gm.creator_id = ? THEN gm.opponent_id ELSE gm.creator_id END) = u.id
                       WHERE gm.creator_id = ? OR gm.opponent_id = ? 
                       ORDER BY gm.created_at DESC LIMIT 5''', (user_id, user_id, user_id))
            recent_matches = c.fetchall()
            
            return render_template('dashboard.html', stats=stats, recent_matches=recent_matches)
            
    except Exception as e:
        flash(f'Dashboard error: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/my_battles')
@login_required
def my_battles():
    return redirect(url_for('my_fpl_battles'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    
    try:
        with get_db_connection() as conn:
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
            
            return render_template('admin_dashboard.html', 
                                 stats=stats, 
                                 earnings_data=earnings_data,
                                 pending_deposits=[],
                                 pending_withdrawals=[],
                                 active_game_matches=[],
                                 notifications=[],
                                 unread_alerts=0)
            
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}', 'error')
        return render_template('admin_dashboard.html', 
                             stats={'total_users': 0, 'total_transactions': 0, 'total_balance': 0, 'pending_deposits': 0, 'unresolved_alerts': 0, 'active_matches': 0, 'total_deposits': 0, 'net_earnings': 0},
                             earnings_data={'match_commission': 0, 'commission_rate': 8, 'deposit_fees': 0, 'withdrawal_fees': 0, 'referral_profits': 0, 'fraud_commissions': 0, 'total_battles': 0, 'bank_fees': 0, 'gross_earnings': 0, 'net_earnings': 0, 'pending_deposits': 0, 'pending_withdrawals': 0, 'total_game_matches': 0},
                             pending_deposits=[], pending_withdrawals=[], active_game_matches=[], notifications=[], unread_alerts=0)

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

@app.route('/verify_login')
def verify_login():
    if 'pending_login' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))
    return render_template('verify_login.html')

@app.route('/verify_login_code', methods=['POST'])
def verify_login_code():
    try:
        data = request.get_json()
        code = data.get('code', '').strip()
        
        if 'pending_login' not in session:
            return jsonify({'success': False, 'message': 'Login session expired'})
        
        user_data = session['pending_login']
        email = user_data['email']
        
        # Verify code
        if email not in verification_codes:
            return jsonify({'success': False, 'message': 'No verification code found'})
        
        stored_data = verification_codes[email]
        if datetime.now() > stored_data['expires']:
            del verification_codes[email]
            return jsonify({'success': False, 'message': 'Verification code expired'})
        
        if stored_data['code'] != code or stored_data.get('type') != 'login':
            return jsonify({'success': False, 'message': 'Invalid verification code'})
        
        # Complete login and update last login
        with get_db_connection() as conn:
            c = conn.cursor()
            # Add columns if they don't exist
            try:
                c.execute('ALTER TABLE users ADD COLUMN last_login TIMESTAMP')
            except:
                pass
            try:
                c.execute('ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0')
            except:
                pass
            
            c.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP, email_verified = 1 WHERE id = ?', 
                     (user_data['user_id'],))
            conn.commit()
        
        session.clear()
        session.permanent = True
        session['user_id'] = user_data['user_id']
        session['username'] = user_data['username']
        session['balance'] = user_data['balance']
        session['is_admin'] = False
        session['logged_in'] = True
        
        # Clean up verification code
        del verification_codes[email]
        
        return jsonify({'success': True, 'message': 'Login successful'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Verification failed: {str(e)}'})

@app.route('/resend_login_code', methods=['POST'])
def resend_login_code():
    try:
        if 'pending_login' not in session:
            return jsonify({'success': False, 'message': 'No login session found'})
        
        user_data = session['pending_login']
        email = user_data['email']
        
        # Generate new code
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        verification_codes[email] = {
            'code': code,
            'expires': datetime.now() + timedelta(minutes=10),
            'type': 'login'
        }
        
        # Send email
        gmail_user = os.getenv('GMAIL_USER')
        gmail_pass = os.getenv('GMAIL_PASS')
        
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = email
        msg['Subject'] = 'SkillStake - Login Verification Code'
        
        body = f'''
Login Verification Required

Your login verification code is: {code}

This code will expire in 10 minutes.

If you didn't try to login, please secure your account.

SkillStake Team
        '''
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_user, gmail_pass)
        text = msg.as_string()
        server.sendmail(gmail_user, email, text)
        server.quit()
        
        return jsonify({'success': True, 'message': 'New verification code sent'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to resend code: {str(e)}'})

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password_fixed.html')

@app.route('/send_reset_code', methods=['POST'])
@limiter.limit("10 per hour")
def send_reset_code():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'})
        
        # Check if user exists
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE email = ?', (email,))
            if not c.fetchone():
                return jsonify({'success': False, 'message': 'No account found with this email'})
        
        # Generate 6-digit code
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        # Store code with expiration (10 minutes)
        reset_codes[email] = {
            'code': code,
            'expires': datetime.now() + timedelta(minutes=10)
        }
        
        # Send email
        gmail_user = os.getenv('GMAIL_USER')
        gmail_pass = os.getenv('GMAIL_PASS')
        
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = email
        msg['Subject'] = 'SkillStake - Password Reset Code'
        
        body = f'''
Password Reset Request

Your password reset code is: {code}

This code will expire in 10 minutes.

If you didn't request this reset, please ignore this email.

SkillStake Team
        '''
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_user, gmail_pass)
        text = msg.as_string()
        server.sendmail(gmail_user, email, text)
        server.quit()
        
        return jsonify({'success': True, 'message': 'Reset code sent to your email'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to send reset code: {str(e)}'})

@app.route('/verify_reset_code', methods=['POST'])
def verify_reset_code():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        code = data.get('code', '').strip()
        
        if not all([email, code]):
            return jsonify({'success': False, 'message': 'Email and code are required'})
        
        # Verify code
        if email not in reset_codes:
            return jsonify({'success': False, 'message': 'No reset code found'})
        
        stored_data = reset_codes[email]
        if datetime.now() > stored_data['expires']:
            del reset_codes[email]
            return jsonify({'success': False, 'message': 'Reset code expired'})
        
        if stored_data['code'] != code:
            return jsonify({'success': False, 'message': 'Invalid reset code'})
        
        return jsonify({'success': True, 'message': 'Code verified'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Verification failed: {str(e)}'})

@app.route('/reset_password_complete', methods=['POST'])
def reset_password_complete():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        code = data.get('code', '').strip()
        new_password = data.get('new_password', '')
        
        if not all([email, code, new_password]):
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'})
        
        # Verify code
        if email not in reset_codes:
            return jsonify({'success': False, 'message': 'Reset session expired'})
        
        stored_data = reset_codes[email]
        if datetime.now() > stored_data['expires'] or stored_data['code'] != code:
            if email in reset_codes:
                del reset_codes[email]
            return jsonify({'success': False, 'message': 'Invalid or expired reset code'})
        
        # Update password
        with get_db_connection() as conn:
            c = conn.cursor()
            hashed_password = generate_password_hash(new_password)
            c.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
            conn.commit()
        
        # Clean up reset code
        del reset_codes[email]
        
        return jsonify({'success': True, 'message': 'Password reset successful'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Password reset failed: {str(e)}'})

@app.route('/register')
def register():
    return redirect(url_for('register_fixed'))

@app.route('/register_fixed')
def register_fixed():
    return render_template('register_fixed.html')

@app.route('/register_with_age', methods=['POST'])
@limiter.limit("10 per hour")
def register_with_age():
    age_confirmed = request.form.get('age_confirmed')
    if not age_confirmed:
        flash('You must confirm you are 18+ to register.', 'error')
        return redirect(url_for('register_fixed'))
    
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    phone = request.form.get('phone', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not all([username, email, password]):
        flash('Please fill in all required fields.', 'error')
        return redirect(url_for('register_fixed'))
    
    if password != confirm_password:
        flash('Passwords do not match!', 'error')
        return redirect(url_for('register_fixed'))
    
    if len(password) < 6:
        flash('Password must be at least 6 characters long.', 'error')
        return redirect(url_for('register_fixed'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Check if user exists
            c.execute('SELECT id FROM users WHERE username = ?', (username,))
            if c.fetchone():
                flash('Username is already taken. Please choose a different username.', 'error')
                return redirect(url_for('register_fixed'))
                
            c.execute('SELECT id FROM users WHERE email = ?', (email,))
            if c.fetchone():
                flash('Email is already registered. Please use a different email or try logging in.', 'error')
                return redirect(url_for('register_fixed'))
                
            if phone:
                c.execute('SELECT id FROM users WHERE phone = ?', (phone,))
                if c.fetchone():
                    flash('Phone number is already registered. Please use a different number.', 'error')
                    return redirect(url_for('register_fixed'))
            
            # Create user
            hashed_password = generate_password_hash(password)
            referral_code = username[:3].upper() + ''.join([str(random.randint(0, 9)) for _ in range(4)])
            
            c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code) 
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     (username, email, hashed_password, 0.0, phone, referral_code))
            conn.commit()
            
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))
            
    except Exception as e:
        flash('Registration failed. Please try again.', 'error')
        return redirect(url_for('register_fixed'))

@app.route('/admin_users')
@login_required
def admin_users():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT id, username, email, balance, created_at FROM users WHERE username != "admin"')
            users = c.fetchall()
        return render_template('admin_users.html', users=users)
    except:
        return render_template('admin_users.html', users=[])

@app.route('/admin_transactions')
@login_required
def admin_transactions():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM transactions ORDER BY created_at DESC LIMIT 100')
            transactions = c.fetchall()
        return render_template('admin_transactions.html', transactions=transactions)
    except:
        return render_template('admin_transactions.html', transactions=[])

@app.route('/admin_matches')
@login_required
def admin_matches():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM game_matches ORDER BY created_at DESC LIMIT 50')
            matches = c.fetchall()
        return render_template('admin_matches.html', matches=matches)
    except:
        return render_template('admin_matches.html', matches=[])

@app.route('/admin_deposits')
@login_required
def admin_deposits():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''SELECT t.*, u.username 
                       FROM transactions t
                       JOIN users u ON t.user_id = u.id
                       WHERE t.type IN ("pending_deposit", "pending_crypto_deposit")
                       ORDER BY t.created_at DESC''')
            pending_deposits = c.fetchall()
            
            c.execute('''SELECT t.*, u.username 
                       FROM transactions t
                       JOIN users u ON t.user_id = u.id
                       WHERE t.type IN ("deposit", "rejected_deposit")
                       ORDER BY t.created_at DESC LIMIT 20''')
            processed_deposits = c.fetchall()
            
        return render_template('admin_deposits.html', 
                             pending_deposits=pending_deposits,
                             processed_deposits=processed_deposits)
    except:
        return render_template('admin_deposits.html', 
                             pending_deposits=[],
                             processed_deposits=[])

@app.route('/admin_withdrawals')
@login_required
def admin_withdrawals():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('admin_withdrawals.html')

@app.route('/admin_settings')
@login_required
def admin_settings():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('admin_settings.html')

@app.route('/admin_tournaments')
@login_required
def admin_tournaments():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get all tournaments with participant count
            c.execute('''SELECT t.*, COUNT(tp.user_id) as participants
                       FROM tournaments t
                       LEFT JOIN tournament_participants tp ON t.id = tp.tournament_id
                       GROUP BY t.id
                       ORDER BY t.created_at DESC''')
            tournaments = c.fetchall()
            
            return render_template('admin_tournaments.html', tournaments=tournaments)
    except:
        return render_template('admin_tournaments.html', tournaments=[])

@app.route('/create_tournament', methods=['POST'])
@login_required
def create_tournament():
    if session.get('username') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        game_type = data.get('game_type', '').strip()
        entry_fee = float(data.get('entry_fee', 0))
        max_players = int(data.get('max_players', 16))
        
        if not all([name, game_type]) or entry_fee < 50:
            return jsonify({'success': False, 'message': 'Invalid tournament data'})
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO tournaments (name, game_type, entry_fee, max_players, whatsapp_group) 
                       VALUES (?, ?, ?, ?, ?)''',
                     (name, game_type, entry_fee, max_players, os.getenv('TOURNAMENT_WHATSAPP_GROUP', '')))
            conn.commit()
        
        return jsonify({'success': True, 'message': 'Tournament created successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error creating tournament'})

@app.route('/admin_support_center')
@login_required
def admin_support_center():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('admin_support.html')

@app.route('/api_test')
@login_required
def api_test():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    return redirect(url_for('admin_dashboard'))

@app.route('/clear_all_deposits')
@login_required
def clear_all_deposits():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    return redirect(url_for('admin_dashboard'))

# USER ROUTES - Regular user functionality
@app.route('/user_bonuses_page')
@login_required
def user_bonuses_page():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM transactions WHERE user_id = ? AND type = "daily_bonus" ORDER BY created_at DESC LIMIT 10', (session['user_id'],))
            bonus_history = c.fetchall()
        return render_template('user_bonuses.html', bonus_history=bonus_history, can_claim_today=True)
    except:
        return render_template('user_bonuses.html', bonus_history=[], can_claim_today=True)

@app.route('/referrals')
@login_required
def referrals():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT username, referral_code FROM users WHERE id = ?', (session['user_id'],))
            user_data = c.fetchone()
            referral_code = user_data[1] if user_data else 'Loading...'
            
            c.execute('SELECT username, created_at FROM users WHERE referred_by = ?', (session['user_id'],))
            referred_users = c.fetchall()
            
        return render_template('referrals.html', 
                             referral_code=referral_code,
                             referred_users=referred_users,
                             referral_earnings=len(referred_users) * 30)
    except:
        return render_template('referrals.html', referral_code='Loading...', referred_users=[], referral_earnings=0)

@app.route('/friends')
@login_required
def friends():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT id, username, phone FROM users WHERE id != ? AND username != "admin"', (session['user_id'],))
            all_users = c.fetchall()
        return render_template('friends.html', all_users=all_users, friends=[], requests=[])
    except:
        return render_template('friends.html', all_users=[], friends=[], requests=[])

@app.route('/match_history')
@login_required
def match_history():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM game_matches WHERE creator_id = ? OR opponent_id = ? ORDER BY created_at DESC LIMIT 20', 
                     (session['user_id'], session['user_id']))
            matches = c.fetchall()
            
            c.execute('SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', (session['user_id'],))
            transactions = c.fetchall()
            
        return render_template('match_history.html', matches=matches, transactions=transactions, withdrawals=[])
    except:
        return render_template('match_history.html', matches=[], transactions=[], withdrawals=[])

@app.route('/support_chat')
@login_required
def support_chat():
    return render_template('support_chat.html')

# Additional user routes for complete functionality
@app.route('/add_friend', methods=['POST'])
@login_required
def add_friend():
    flash('Friend request sent!', 'success')
    return redirect(url_for('friends'))

@app.route('/accept_friend/<int:request_id>')
@login_required
def accept_friend(request_id):
    flash('Friend request accepted!', 'success')
    return redirect(url_for('friends'))

@app.route('/match_chat/<int:match_id>')
@login_required
def match_chat(match_id):
    return render_template('match_chat.html', match_id=match_id)

@app.route('/claim_bonus', methods=['POST'])
@login_required
def claim_bonus():
    # Add 75 KSh to user balance
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            new_balance = session.get('balance', 0) + 75
            c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
            c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                     (session['user_id'], 'daily_bonus', 75, 'Daily login bonus'))
            conn.commit()
            session['balance'] = new_balance
            flash('Daily bonus claimed! +75 KSh added to your balance.', 'success')
    except:
        flash('Error claiming bonus. Please try again.', 'error')
    return redirect(url_for('user_bonuses_page'))

@app.route('/escalate_support', methods=['POST'])
@login_required
def escalate_support():
    return jsonify({'success': True, 'message': 'Support request escalated'})

@app.route('/api/daily_bonus_status')
@login_required
def daily_bonus_status():
    return jsonify({'can_claim': True, 'next_claim': 'tomorrow'})

@app.route('/api/user_balance')
@login_required
def api_user_balance():
    return jsonify({'balance': session.get('balance', 0), 'username': session.get('username', 'User')})

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

@app.route('/matches')
@login_required
def matches():
    return redirect(url_for('quick_matches'))

@app.route('/profile')
@login_required
def profile():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT username, email, phone, balance, created_at FROM users WHERE id = ?', (session['user_id'],))
            user = c.fetchone()
            return render_template('profile.html', user=user)
    except:
        return render_template('profile.html', user=None)

@app.route('/leaderboard')
@login_required
def leaderboard():
    return render_template('leaderboard.html')

@app.route('/tournaments')
@login_required
def tournaments():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Create tournaments table if not exists
            c.execute('''CREATE TABLE IF NOT EXISTS tournaments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                game_type TEXT NOT NULL,
                entry_fee REAL NOT NULL,
                max_players INTEGER DEFAULT 16,
                prize_pool REAL DEFAULT 0,
                status TEXT DEFAULT 'open',
                current_players INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                starts_at TIMESTAMP,
                whatsapp_group TEXT
            )''')
            
            # Create tournament_participants table
            c.execute('''CREATE TABLE IF NOT EXISTS tournament_participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tournament_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (tournament_id) REFERENCES tournaments (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )''')
            
            # Get active tournaments
            c.execute('''SELECT t.*, COUNT(tp.user_id) as participants
                       FROM tournaments t
                       LEFT JOIN tournament_participants tp ON t.id = tp.tournament_id
                       WHERE t.status = "open"
                       GROUP BY t.id
                       ORDER BY t.created_at DESC''')
            active_tournaments = c.fetchall()
            
            # Get user's tournament history
            c.execute('''SELECT t.name, t.game_type, t.entry_fee, tp.joined_at
                       FROM tournaments t
                       JOIN tournament_participants tp ON t.id = tp.tournament_id
                       WHERE tp.user_id = ?
                       ORDER BY tp.joined_at DESC LIMIT 10''', (session['user_id'],))
            user_tournaments = c.fetchall()
            
            return render_template('tournaments.html', 
                                 active_tournaments=active_tournaments,
                                 user_tournaments=user_tournaments)
    except:
        return render_template('tournaments.html', 
                             active_tournaments=[],
                             user_tournaments=[])

@app.route('/join_tournament/<int:tournament_id>', methods=['POST'])
@login_required
def join_tournament(tournament_id):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get tournament details
            c.execute('SELECT * FROM tournaments WHERE id = ? AND status = "open"', (tournament_id,))
            tournament = c.fetchone()
            
            if not tournament:
                return jsonify({'success': False, 'message': 'Tournament not found or closed'})
            
            # Check if user already joined
            c.execute('SELECT id FROM tournament_participants WHERE tournament_id = ? AND user_id = ?', 
                     (tournament_id, session['user_id']))
            if c.fetchone():
                return jsonify({'success': False, 'message': 'Already joined this tournament'})
            
            entry_fee = tournament[3]
            max_players = tournament[4]
            current_players = tournament[7]
            
            # Check if tournament is full
            if current_players >= max_players:
                return jsonify({'success': False, 'message': 'Tournament is full'})
            
            # Check user balance
            if session.get('balance', 0) < entry_fee:
                return jsonify({'success': False, 'message': 'Insufficient balance'})
            
            # Deduct entry fee and join tournament
            new_balance = session['balance'] - entry_fee
            c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
            session['balance'] = new_balance
            
            # Add participant
            c.execute('INSERT INTO tournament_participants (tournament_id, user_id) VALUES (?, ?)',
                     (tournament_id, session['user_id']))
            
            # Update tournament stats
            new_players = current_players + 1
            new_prize_pool = tournament[5] + (entry_fee * 0.85)  # 85% goes to prize pool
            c.execute('UPDATE tournaments SET current_players = ?, prize_pool = ? WHERE id = ?',
                     (new_players, new_prize_pool, tournament_id))
            
            # Add transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                       VALUES (?, ?, ?, ?)''',
                     (session['user_id'], 'tournament_entry', -entry_fee, f'Tournament entry: {tournament[1]}'))
            
            conn.commit()
            
            return jsonify({'success': True, 'message': f'Successfully joined tournament! Entry fee: KSh {entry_fee}'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error joining tournament'})

@app.route('/my_game_matches')
@login_required
def my_game_matches():
    return redirect(url_for('match_history'))

@app.route('/add_funds', methods=['GET', 'POST'])
@login_required
def add_funds():
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount', 0))
            mpesa_number = request.form.get('mpesa_number', '').strip()
            sender_name = request.form.get('sender_name', '').strip()
            receipt_file = request.files.get('receipt_screenshot')
            
            if not all([amount, mpesa_number, sender_name]):
                flash('Please fill in all fields', 'error')
                return redirect(url_for('wallet'))
            
            if amount < 100:
                flash('Minimum deposit amount is KSh 100', 'error')
                return redirect(url_for('wallet'))
            
            # Handle receipt screenshot
            receipt_data = None
            if receipt_file and receipt_file.filename:
                try:
                    import base64
                    receipt_data = base64.b64encode(receipt_file.read()).decode('utf-8')
                except:
                    pass
            
            with get_db_connection() as conn:
                c = conn.cursor()
                
                # Create pending deposit transaction with receipt
                description = f'M-Pesa deposit - {sender_name} ({mpesa_number}) - KSh {amount}'
                c.execute('''INSERT INTO transactions (user_id, type, amount, description, payment_proof) 
                           VALUES (?, ?, ?, ?, ?)''',
                         (session['user_id'], 'pending_deposit', amount, description, receipt_data))
                
                conn.commit()
            
            flash(f'Deposit request submitted! Amount: KSh {amount}. Admin will review and approve within 24 hours.', 'success')
            return redirect(url_for('wallet'))
            
        except ValueError:
            flash('Invalid deposit amount', 'error')
            return redirect(url_for('wallet'))
        except Exception as e:
            flash('Error processing deposit. Please try again.', 'error')
            return redirect(url_for('wallet'))
    
    return redirect(url_for('wallet'))

@app.route('/create_crypto_payment', methods=['POST'])
@login_required
def create_crypto_payment():
    try:
        data = request.get_json()
        amount = float(data.get('amount', 0))
        
        if amount < 1950:
            return jsonify({'success': False, 'error': 'Minimum amount is KSh 1,950'})
        
        api_key = os.getenv('NOWPAYMENTS_API_KEY')
        if not api_key:
            return jsonify({'success': False, 'error': 'Payment service unavailable'})
            
        order_id = f'SK_{session["user_id"]}_{int(time.time())}'
        usd_amount = round(amount / 130, 2)
        
        payment_data = {
            'price_amount': usd_amount,
            'price_currency': 'usd',
            'pay_currency': 'usdttrc20',
            'order_id': order_id,
            'order_description': f'SkillStake Gaming Deposit - KSh {amount}'
        }
        
        headers = {
            'x-api-key': api_key,
            'Content-Type': 'application/json'
        }
        
        response = requests.post('https://api.nowpayments.io/v1/payment',
                               headers=headers,
                               json=payment_data,
                               timeout=15)
        
        if response.status_code == 201:
            payment = response.json()
            payment_url = payment.get('payment_url') or payment.get('invoice_url')
            
            if payment_url:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    description = f'Crypto payment initiated - KSh {amount} (${usd_amount})'
                    c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                               VALUES (?, ?, ?, ?)''',
                             (session['user_id'], 'crypto_initiated', amount, description))
                    conn.commit()
                
                return jsonify({
                    'success': True,
                    'payment_url': payment_url,
                    'message': 'Redirecting to crypto payment...'
                })
            else:
                # Fallback: create manual crypto payment page
                payment_url = f'/crypto_manual_payment?amount={amount}&order_id={order_id}'
                return jsonify({
                    'success': True,
                    'payment_url': payment_url,
                    'message': 'Redirecting to crypto payment...'
                })
        else:
            # Fallback for API errors
            payment_url = f'/crypto_manual_payment?amount={amount}&order_id={order_id}'
            return jsonify({
                'success': True,
                'payment_url': payment_url,
                'message': 'Redirecting to crypto payment...'
            })
        
    except requests.exceptions.Timeout:
        return jsonify({'success': False, 'error': 'Payment service timeout - please try again'})
    except requests.exceptions.RequestException:
        return jsonify({'success': False, 'error': 'Network error - check connection'})
    except Exception as e:
        return jsonify({'success': False, 'error': 'Payment creation failed'})

@app.route('/crypto_manual_payment')
@login_required
def crypto_manual_payment():
    try:
        amount = float(request.args.get('amount', 0))
        order_id = request.args.get('order_id', '')
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Crypto Payment</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 2rem; background: #f8f9fa; }}
                .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
                .crypto-address {{ background: #f8f9fa; padding: 1rem; border-radius: 8px; margin: 1rem 0; word-break: break-all; font-family: monospace; }}
                .btn {{ background: #28a745; color: white; padding: 1rem 2rem; border: none; border-radius: 8px; cursor: pointer; margin: 0.5rem; text-decoration: none; display: inline-block; }}
                .btn-cancel {{ background: #dc3545; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>🔐 Crypto Payment</h2>
                <p><strong>Amount:</strong> KSh {amount} (~${amount/130:.2f})</p>
                <p><strong>Order ID:</strong> {order_id}</p>
                
                <div class="crypto-address">
                    <p><strong>USDT TRC-20 Address:</strong></p>
                    <code>TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE</code>
                </div>
                
                <p style="color: #666; font-size: 0.9rem;">Send exactly ${amount/130:.2f} USDT to the address above</p>
                
                <div style="margin: 2rem 0;">
                    <a href="/crypto_success?amount={amount}" class="btn">✅ Payment Sent</a>
                    <a href="/crypto_cancel" class="btn btn-cancel">❌ Cancel</a>
                </div>
                
                <p style="font-size: 0.8rem; color: #999;">Funds will be credited after blockchain confirmation (5-15 minutes)</p>
            </div>
        </body>
        </html>
        '''
        
    except Exception as e:
        return 'Error loading crypto payment page', 500

@app.route('/crypto_demo_payment')
@login_required
def crypto_demo_payment():
    try:
        amount = float(request.args.get('amount', 0))
        order_id = request.args.get('order_id', '')
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Crypto Payment</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
        </head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 2rem;">
            <h2>🔐 Crypto Payment Gateway</h2>
            <p>Amount: KSh {amount} (~${amount/130:.2f})</p>
            <p>Order ID: {order_id}</p>
            <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; margin: 1rem 0;">
                <p><strong>USDT TRC-20 Address:</strong></p>
                <code style="background: white; padding: 0.5rem; border-radius: 4px;">TDemo123CryptoAddressForTesting456</code>
            </div>
            <div style="margin: 2rem 0;">
                <button onclick="simulateSuccess()" style="background: #28a745; color: white; padding: 1rem 2rem; border: none; border-radius: 5px; margin: 0.5rem;">✅ Simulate Payment Success</button>
                <button onclick="simulateCancel()" style="background: #dc3545; color: white; padding: 1rem 2rem; border: none; border-radius: 5px; margin: 0.5rem;">❌ Cancel Payment</button>
            </div>
            <p><small>Demo mode - choose outcome above</small></p>
            
            <script>
                function simulateSuccess() {{
                    window.location.href = '/crypto_success?amount={amount}&order_id={order_id}';
                }}
                
                function simulateCancel() {{
                    window.location.href = '/crypto_cancel';
                }}
                
                setTimeout(function() {{
                    simulateSuccess();
                }}, 5000);
            </script>
        </body>
        </html>
        '''
        
    except Exception as e:
        return 'Error loading crypto payment page', 500

@app.route('/paypal_checkout')
@login_required
def paypal_checkout():
    try:
        amount = float(request.args.get('amount', 0))
        
        if amount < 130:
            flash('Minimum amount is KSh 130', 'error')
            return redirect(url_for('wallet'))
        
        import base64
        
        client_id = os.getenv('PAYPAL_CLIENT_ID')
        client_secret = os.getenv('PAYPAL_CLIENT_SECRET')
        # Auto-detect sandbox vs production based on client ID
        if client_id and client_id.startswith('SB'):
            base_url = 'https://api.sandbox.paypal.com'
        else:
            base_url = 'https://api.paypal.com'
        
        if not client_id or not client_secret:
            flash('PayPal service unavailable', 'error')
            return redirect(url_for('wallet'))
        
        # Get OAuth token
        auth = base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()
        token_headers = {
            'Authorization': f'Basic {auth}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        token_response = requests.post(f'{base_url}/v1/oauth2/token', 
                                     headers=token_headers, 
                                     data='grant_type=client_credentials',
                                     timeout=15)
        
        if token_response.status_code != 200:
            try:
                error_data = token_response.json()
                error_msg = error_data.get('error_description', 'Authentication failed')
                flash(f'PayPal error: {error_msg}', 'error')
            except:
                flash(f'PayPal authentication failed (Status: {token_response.status_code})', 'error')
            return redirect(url_for('wallet'))
        
        access_token = token_response.json()['access_token']
        usd_amount = round(amount / 130, 2)
        
        # Create payment with guest checkout enabled
        payment_data = {
            'intent': 'sale',
            'payer': {
                'payment_method': 'paypal',
                'payer_info': {
                    'payment_method': 'paypal'
                }
            },
            'transactions': [{
                'amount': {
                    'total': str(usd_amount),
                    'currency': 'USD'
                },
                'description': f'SkillStake Gaming Deposit - KSh {amount}',
                'item_list': {
                    'items': [{
                        'name': 'SkillStake Gaming Credit',
                        'sku': f'DEPOSIT_{amount}',
                        'price': str(usd_amount),
                        'currency': 'USD',
                        'quantity': 1
                    }]
                },
                'note_to_payer': 'Gaming platform deposit - supports guest checkout'
            }],
            'note_to_payer': 'You can pay with credit/debit card without PayPal account',
            'redirect_urls': {
                'return_url': 'https://skillstakegamers-wxc6.onrender.com/paypal_success',
                'cancel_url': 'https://skillstakegamers-wxc6.onrender.com/paypal_cancel'
            },
            'application_context': {
                'brand_name': 'SkillStake Gaming',
                'landing_page': 'billing',
                'user_action': 'commit',
                'return_url': 'https://skillstakegamers-wxc6.onrender.com/paypal_success',
                'cancel_url': 'https://skillstakegamers-wxc6.onrender.com/paypal_cancel'
            }
        }
        
        payment_headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        payment_response = requests.post(f'{base_url}/v1/payments/payment',
                                       headers=payment_headers,
                                       json=payment_data,
                                       timeout=15)
        
        if payment_response.status_code == 201:
            payment = payment_response.json()
            approval_url = None
            
            for link in payment.get('links', []):
                if link.get('rel') == 'approval_url':
                    approval_url = link.get('href')
                    break
            
            if approval_url:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    description = f'PayPal payment initiated - KSh {amount} (${usd_amount})'
                    c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                               VALUES (?, ?, ?, ?)''',
                             (session['user_id'], 'paypal_initiated', amount, description))
                    conn.commit()
                
                return redirect(approval_url)
            else:
                flash('PayPal approval URL not found', 'error')
                return redirect(url_for('wallet'))
        else:
            try:
                error_data = payment_response.json()
                error_msg = error_data.get('message', f'Payment creation failed (Status: {payment_response.status_code})')
                if 'details' in error_data:
                    details = error_data['details'][0] if error_data['details'] else {}
                    error_msg += f" - {details.get('issue', '')}"
                flash(f'PayPal error: {error_msg}', 'error')
            except:
                flash(f'PayPal payment creation failed (Status: {payment_response.status_code})', 'error')
            return redirect(url_for('wallet'))
        
    except requests.exceptions.Timeout:
        flash('PayPal timeout - please try again', 'error')
        return redirect(url_for('wallet'))
    except requests.exceptions.RequestException:
        flash('PayPal network error', 'error')
        return redirect(url_for('wallet'))
    except Exception as e:
        flash('PayPal error occurred', 'error')
        return redirect(url_for('wallet'))

@app.route('/alert_admin_deposit', methods=['POST'])
@login_required
def alert_admin_deposit():
    try:
        data = request.get_json()
        transaction_id = data.get('transaction_id')
        amount = data.get('amount')
        
        # In a real app, this would send notification to admin
        # For now, just return success
        return jsonify({
            'success': True,
            'message': f'Alert sent to admin about KSh {amount} deposit (Transaction #{transaction_id})'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to send alert'})

@app.route('/paypal_success')
@login_required
def paypal_success():
    try:
        payment_id = request.args.get('paymentId')
        payer_id = request.args.get('PayerID')
        
        if not payment_id or not payer_id:
            flash('Invalid PayPal response', 'error')
            return redirect(url_for('wallet'))
        
        import base64
        
        client_id = os.getenv('PAYPAL_CLIENT_ID')
        client_secret = os.getenv('PAYPAL_CLIENT_SECRET')
        # Auto-detect sandbox vs production based on client ID
        if client_id and client_id.startswith('SB'):
            base_url = 'https://api.sandbox.paypal.com'
        else:
            base_url = 'https://api.paypal.com'
        
        # Get OAuth token
        auth = base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()
        token_headers = {
            'Authorization': f'Basic {auth}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        token_response = requests.post(f'{base_url}/v1/oauth2/token', 
                                     headers=token_headers, 
                                     data='grant_type=client_credentials',
                                     timeout=15)
        
        if token_response.status_code == 200:
            access_token = token_response.json()['access_token']
            
            # Execute payment
            execute_data = {'payer_id': payer_id}
            execute_headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            execute_response = requests.post(f'{base_url}/v1/payments/payment/{payment_id}/execute',
                                           headers=execute_headers,
                                           json=execute_data,
                                           timeout=15)
            
            if execute_response.status_code == 200:
                payment_data = execute_response.json()
                usd_amount = float(payment_data['transactions'][0]['amount']['total'])
                ksh_amount = usd_amount * 130
                
                with get_db_connection() as conn:
                    c = conn.cursor()
                    
                    current_balance = session.get('balance', 0)
                    new_balance = current_balance + ksh_amount
                    c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
                    session['balance'] = new_balance
                    
                    c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                               VALUES (?, ?, ?, ?)''',
                             (session['user_id'], 'paypal_deposit', ksh_amount, f'PayPal deposit completed - ${usd_amount:.2f} (KSh {ksh_amount:.0f})'))
                    
                    conn.commit()
                
                flash(f'PayPal deposit successful! KSh {ksh_amount:.0f} added to your balance.', 'success')
            else:
                flash('PayPal payment execution failed', 'error')
        else:
            flash('PayPal authentication failed', 'error')
        
        return redirect(url_for('wallet'))
        
    except requests.exceptions.Timeout:
        flash('PayPal timeout error', 'error')
        return redirect(url_for('wallet'))
    except requests.exceptions.RequestException:
        flash('PayPal network error', 'error')
        return redirect(url_for('wallet'))
    except Exception as e:
        flash('PayPal processing error', 'error')
        return redirect(url_for('wallet'))

@app.route('/paypal_cancel')
@login_required
def paypal_cancel():
    try:
        # Update the most recent initiated PayPal transaction to cancelled
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''UPDATE transactions 
                       SET type = "paypal_cancelled", description = description || " - CANCELLED"
                       WHERE user_id = ? AND type = "paypal_initiated" 
                       ORDER BY created_at DESC LIMIT 1''', (session['user_id'],))
            conn.commit()
    except:
        pass
    
    flash('PayPal payment cancelled', 'info')
    return redirect(url_for('wallet'))

@app.route('/crypto_success')
@login_required
def crypto_success():
    try:
        amount = float(request.args.get('amount', 0))
        if amount > 0:
            with get_db_connection() as conn:
                c = conn.cursor()
                description = f'Crypto payment pending verification - KSh {amount} (${amount/130:.2f})'
                c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                           VALUES (?, ?, ?, ?)''',
                         (session['user_id'], 'pending_crypto_deposit', amount, description))
                conn.commit()
            flash(f'Crypto payment submitted! KSh {amount} will be credited after admin verification.', 'info')
        else:
            flash('Crypto payment initiated! You will be credited once payment is confirmed.', 'info')
    except:
        flash('Crypto payment initiated! You will be credited once payment is confirmed.', 'info')
    return redirect(url_for('wallet'))

@app.route('/crypto_cancel')
@login_required
def crypto_cancel():
    try:
        # Update the most recent initiated crypto transaction to cancelled
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''UPDATE transactions 
                       SET type = "crypto_cancelled", description = description || " - CANCELLED"
                       WHERE user_id = ? AND type = "crypto_initiated" 
                       ORDER BY created_at DESC LIMIT 1''', (session['user_id'],))
            conn.commit()
    except:
        pass
    
    flash('Crypto payment cancelled', 'info')
    return redirect(url_for('wallet'))

@app.route('/fpl_battles')
@login_required
def fpl_battles():
    # Get user's current balance for display
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
            user_balance = c.fetchone()
            if user_balance:
                session['balance'] = user_balance[0]
    except:
        pass
    
    # Battle types with better descriptions
    battle_types = [
        {
            'id': 'gameweek_points',
            'name': 'Gameweek Points Battle',
            'description': 'Compare total FPL points scored in the current gameweek',
            'min_bet': 50,
            'max_bet': 1000
        },
        {
            'id': 'captain_battle',
            'name': 'Captain Battle',
            'description': 'Whose captain will score more points this gameweek?',
            'min_bet': 30,
            'max_bet': 500
        },
        {
            'id': 'transfer_battle',
            'name': 'Transfer Battle',
            'description': 'Best transfer of the gameweek wins',
            'min_bet': 40,
            'max_bet': 800
        },
        {
            'id': 'overall_rank',
            'name': 'Overall Rank Battle',
            'description': 'Compare FPL overall rankings - lower rank wins',
            'min_bet': 100,
            'max_bet': 2000
        }
    ]
    
    # Get real FPL matches from API
    live_matches = []
    current_gameweek = 15
    
    try:
        import requests
        from datetime import datetime
        
        # Get bootstrap data for teams and current gameweek
        bootstrap_response = requests.get('https://fantasy.premierleague.com/api/bootstrap-static/', timeout=10)
        
        if bootstrap_response.status_code == 200:
            bootstrap_data = bootstrap_response.json()
            
            # Get current gameweek
            for event in bootstrap_data.get('events', []):
                if event.get('is_current', False):
                    current_gameweek = event.get('id', 15)
                    break
            
            # Create teams lookup
            teams_data = {}
            for team in bootstrap_data.get('teams', []):
                teams_data[team['id']] = {
                    'name': team['name'],
                    'short_name': team['short_name'],
                    'code': team['code']
                }
            
            # Get fixtures for current and next gameweek
            fixtures_response = requests.get('https://fantasy.premierleague.com/api/fixtures/', timeout=10)
            if fixtures_response.status_code == 200:
                fixtures_data = fixtures_response.json()
                
                # Get unfinished fixtures from current and next gameweek
                for fixture in fixtures_data:
                    fixture_gw = fixture.get('event')
                    if (fixture_gw and fixture_gw >= current_gameweek and 
                        fixture_gw <= current_gameweek + 1 and 
                        not fixture.get('finished', False) and 
                        fixture.get('team_h') and fixture.get('team_a')):
                        
                        home_team = teams_data.get(fixture['team_h'], {})
                        away_team = teams_data.get(fixture['team_a'], {})
                        
                        # Format kickoff time
                        kickoff_time = f'GW {fixture_gw}'
                        if fixture.get('kickoff_time'):
                            try:
                                kickoff_str = fixture['kickoff_time']
                                if 'T' in kickoff_str:
                                    kickoff_dt = datetime.fromisoformat(kickoff_str.replace('Z', ''))
                                    kickoff_time = kickoff_dt.strftime('%a %d %b')
                            except:
                                kickoff_time = f'GW {fixture_gw}'
                        
                        live_matches.append({
                            'id': fixture['id'],
                            'home': home_team.get('short_name', 'HOME'),
                            'away': away_team.get('short_name', 'AWAY'),
                            'home_logo': f"https://resources.premierleague.com/premierleague/badges/25/t{home_team.get('code', 1)}.png",
                            'away_logo': f"https://resources.premierleague.com/premierleague/badges/25/t{away_team.get('code', 1)}.png",
                            'time': kickoff_time
                        })
                
                # Limit to 8 matches
                live_matches = live_matches[:8]
    
    except Exception as e:
        print(f'FPL API Error: {e}')
    
    # Always ensure we have matches to show
    if not live_matches:
        live_matches = [
            {
                'id': 1,
                'home': 'ARS',
                'away': 'CHE',
                'home_logo': 'https://resources.premierleague.com/premierleague/badges/25/t3.png',
                'away_logo': 'https://resources.premierleague.com/premierleague/badges/25/t8.png',
                'time': f'GW {current_gameweek}'
            },
            {
                'id': 2,
                'home': 'LIV',
                'away': 'MCI',
                'home_logo': 'https://resources.premierleague.com/premierleague/badges/25/t14.png',
                'away_logo': 'https://resources.premierleague.com/premierleague/badges/25/t43.png',
                'time': f'GW {current_gameweek}'
            },
            {
                'id': 3,
                'home': 'MUN',
                'away': 'TOT',
                'home_logo': 'https://resources.premierleague.com/premierleague/badges/25/t1.png',
                'away_logo': 'https://resources.premierleague.com/premierleague/badges/25/t6.png',
                'time': f'GW {current_gameweek}'
            },
            {
                'id': 4,
                'home': 'NEW',
                'away': 'AVL',
                'home_logo': 'https://resources.premierleague.com/premierleague/badges/25/t4.png',
                'away_logo': 'https://resources.premierleague.com/premierleague/badges/25/t7.png',
                'time': f'GW {current_gameweek}'
            }
        ]
    
    # Get open battles from database
    open_battles = []
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Ensure fpl_battles table exists
            c.execute('''CREATE TABLE IF NOT EXISTS fpl_battles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                battle_type TEXT NOT NULL,
                creator_id INTEGER NOT NULL,
                creator_fpl_id TEXT NOT NULL,
                opponent_id INTEGER,
                opponent_fpl_id TEXT,
                stake_amount REAL NOT NULL,
                total_pot REAL NOT NULL,
                winner_id INTEGER,
                status TEXT DEFAULT 'open',
                gameweek INTEGER DEFAULT 1,
                creator_points INTEGER DEFAULT 0,
                opponent_points INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )''')
            
            c.execute('''SELECT fb.*, u.username as creator_name
                       FROM fpl_battles fb
                       JOIN users u ON fb.creator_id = u.id
                       WHERE fb.status = "open" AND fb.creator_id != ?
                       ORDER BY fb.created_at DESC LIMIT 10''', (session['user_id'],))
            open_battles = c.fetchall()
    except Exception as e:
        pass
    
    return render_template('fpl_battles.html', 
                         live_matches=live_matches,
                         battle_types=battle_types,
                         open_battles=open_battles,
                         current_gameweek=current_gameweek)

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

@app.route('/upload_match_screenshot', methods=['POST'])
@login_required
def upload_match_screenshot():
    return jsonify({'success': False, 'message': 'Screenshot verification system coming soon! Contact admin for manual verification.'})

@app.route('/withdraw_funds', methods=['POST'])
@login_required
def withdraw_funds():
    try:
        withdrawal_method = request.form.get('withdrawal_method')
        amount = float(request.form.get('amount', 0))
        
        if amount < 100:
            flash('Minimum withdrawal amount is KSh 100', 'error')
            return redirect(url_for('wallet'))
        
        if amount > session.get('balance', 0):
            flash('Insufficient balance for withdrawal', 'error')
            return redirect(url_for('wallet'))
        
        # Calculate fees based on method
        fee = 0
        if withdrawal_method == 'mpesa':
            fee = 25 + (amount * 0.02)
        elif withdrawal_method == 'paypal':
            fee = (amount * 0.055) + (amount * 0.02)
        elif withdrawal_method == 'crypto':
            fee = (amount * 0.035) + (amount * 0.02)
        elif withdrawal_method == 'bank':
            fee = 50 + (amount * 0.02)
        
        net_amount = amount - fee
        
        if net_amount < 50:
            flash('Net amount after fees is too low. Minimum net: KSh 50', 'error')
            return redirect(url_for('wallet'))
        
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Deduct amount from balance
            new_balance = session['balance'] - amount
            c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
            session['balance'] = new_balance
            
            # Create withdrawal transaction
            description = f'{withdrawal_method.upper()} withdrawal - KSh {amount} (Fee: KSh {fee:.0f}, Net: KSh {net_amount:.0f})'
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                       VALUES (?, ?, ?, ?)''',
                     (session['user_id'], 'pending_withdrawal', -amount, description))
            
            conn.commit()
        
        flash(f'Withdrawal request submitted! Net amount: KSh {net_amount:.0f} (after KSh {fee:.0f} fees)', 'success')
        return redirect(url_for('wallet'))
        
    except ValueError:
        flash('Invalid withdrawal amount', 'error')
        return redirect(url_for('wallet'))
    except Exception as e:
        flash('Error processing withdrawal. Please try again.', 'error')
        return redirect(url_for('wallet'))

@app.route('/create_fpl_battle', methods=['POST'])
@login_required
def create_fpl_battle():
    try:
        battle_type = request.form.get('battle_type')
        fpl_team_id = request.form.get('fpl_team_id', '').strip()
        stake_amount = float(request.form.get('stake_amount', 0))
        
        if not all([battle_type, fpl_team_id, stake_amount]):
            flash('Please fill in all fields', 'error')
            return redirect(url_for('fpl_battles'))
        
        # Validate FPL team ID format
        if not fpl_team_id.isdigit() or len(fpl_team_id) < 6 or len(fpl_team_id) > 8:
            flash('FPL Team ID must be 6-8 digits (e.g., 1234567)', 'error')
            return redirect(url_for('fpl_battles'))
        
        if stake_amount < 30 or stake_amount > 2000:
            flash('Stake must be between 30 and 2000 KSh', 'error')
            return redirect(url_for('fpl_battles'))
        
        if session.get('balance', 0) < stake_amount:
            flash('Insufficient balance. Please add funds to your wallet.', 'error')
            return redirect(url_for('fpl_battles'))
        
        # Verify FPL team exists and get team name
        team_name = 'Unknown Team'
        import requests
        fpl_url = f'https://fantasy.premierleague.com/api/entry/{fpl_team_id}/'
        try:
            fpl_response = requests.get(fpl_url, timeout=8)
            if fpl_response.status_code == 200:
                fpl_data = fpl_response.json()
                team_name = fpl_data.get('name', 'Unknown Team')
                # Validate it's an active team
                if not fpl_data.get('id'):
                    flash('Invalid FPL Team ID. Please check your team ID and try again.', 'error')
                    return redirect(url_for('fpl_battles'))
            else:
                flash('Could not verify FPL Team ID. Please ensure it\'s correct.', 'error')
                return redirect(url_for('fpl_battles'))
        except:
            flash('Unable to verify FPL team. Please check your internet connection and team ID.', 'error')
            return redirect(url_for('fpl_battles'))
        
        # Get current gameweek
        current_gameweek = 1
        try:
            bootstrap_response = requests.get('https://fantasy.premierleague.com/api/bootstrap-static/', timeout=5)
            if bootstrap_response.status_code == 200:
                bootstrap_data = bootstrap_response.json()
                for event in bootstrap_data.get('events', []):
                    if event.get('is_current', False):
                        current_gameweek = event.get('id', 1)
                        break
        except:
            pass
        
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Create fpl_battles table if it doesn't exist
            c.execute('''CREATE TABLE IF NOT EXISTS fpl_battles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                battle_type TEXT NOT NULL,
                creator_id INTEGER NOT NULL,
                creator_fpl_id TEXT NOT NULL,
                opponent_id INTEGER,
                opponent_fpl_id TEXT,
                stake_amount REAL NOT NULL,
                total_pot REAL NOT NULL,
                winner_id INTEGER,
                status TEXT DEFAULT 'open',
                gameweek INTEGER DEFAULT 1,
                creator_points INTEGER DEFAULT 0,
                opponent_points INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )''')
            
            commission = stake_amount * 0.08
            total_pot = (stake_amount * 2) - commission
            
            # Deduct stake from user balance
            new_balance = session['balance'] - stake_amount
            c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
            session['balance'] = new_balance
            
            # Create battle
            c.execute('''INSERT INTO fpl_battles 
                       (battle_type, creator_id, creator_fpl_id, stake_amount, total_pot, gameweek) 
                       VALUES (?, ?, ?, ?, ?, ?)''',
                     (battle_type, session['user_id'], fpl_team_id, stake_amount, total_pot, current_gameweek))
            
            # Add transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                       VALUES (?, ?, ?, ?)''',
                     (session['user_id'], 'fpl_battle_stake', -stake_amount, f'FPL Battle: {battle_type} - Team: {team_name}'))
            
            conn.commit()
        
        flash(f'FPL Battle created successfully! Team: {team_name} | Stake: KSh {stake_amount}', 'success')
        return redirect(url_for('fpl_battles'))
        
    except ValueError:
        flash('Invalid stake amount. Please enter a valid number.', 'error')
        return redirect(url_for('fpl_battles'))
    except Exception as e:
        flash('Error creating battle. Please try again.', 'error')
        return redirect(url_for('fpl_battles'))

@app.route('/join_fpl_battle/<int:battle_id>', methods=['POST'])
@login_required
def join_fpl_battle(battle_id):
    try:
        fpl_team_id = request.form.get('fpl_team_id', '').strip()
        
        if not fpl_team_id:
            return jsonify({'success': False, 'message': 'FPL Team ID required'})
        
        # Validate FPL team ID format
        if not fpl_team_id.isdigit() or len(fpl_team_id) < 6 or len(fpl_team_id) > 8:
            return jsonify({'success': False, 'message': 'FPL Team ID must be 6-8 digits'})
        
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get battle details
            c.execute('SELECT * FROM fpl_battles WHERE id = ? AND status = "open"', (battle_id,))
            battle = c.fetchone()
            
            if not battle:
                return jsonify({'success': False, 'message': 'Battle not found or already started'})
            
            if battle[2] == session['user_id']:  # creator_id
                return jsonify({'success': False, 'message': 'Cannot join your own battle'})
            
            # Check if user already used this FPL ID
            if battle[3] == fpl_team_id:  # creator_fpl_id
                return jsonify({'success': False, 'message': 'Cannot use the same FPL team ID as the creator'})
            
            stake_amount = battle[5]  # stake_amount
            if session.get('balance', 0) < stake_amount:
                return jsonify({'success': False, 'message': 'Insufficient balance. Please add funds.'})
            
            # Verify FPL team exists and get team name
            team_name = 'Unknown Team'
            import requests
            fpl_url = f'https://fantasy.premierleague.com/api/entry/{fpl_team_id}/'
            try:
                fpl_response = requests.get(fpl_url, timeout=8)
                if fpl_response.status_code == 200:
                    fpl_data = fpl_response.json()
                    team_name = fpl_data.get('name', 'Unknown Team')
                    if not fpl_data.get('id'):
                        return jsonify({'success': False, 'message': 'Invalid FPL Team ID. Please check and try again.'})
                else:
                    return jsonify({'success': False, 'message': 'Could not verify FPL Team ID. Please check it\'s correct.'})
            except:
                return jsonify({'success': False, 'message': 'Unable to verify FPL team. Check your connection and team ID.'})
            
            # Update battle and user balance
            new_balance = session['balance'] - stake_amount
            c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
            c.execute('UPDATE fpl_battles SET opponent_id = ?, opponent_fpl_id = ?, status = "active" WHERE id = ?', 
                     (session['user_id'], fpl_team_id, battle_id))
            
            # Add transaction
            c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                     (session['user_id'], 'fpl_battle_stake', -stake_amount, f'Joined FPL Battle #{battle_id} - Team: {team_name}'))
            
            conn.commit()
            session['balance'] = new_balance
            
        return jsonify({'success': True, 'message': f'Successfully joined FPL battle! Team: {team_name}'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error joining battle. Please try again.'})

@app.route('/my_fpl_battles')
@login_required
def my_fpl_battles():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''SELECT fb.*, 
                               cu.username as creator_name,
                               ou.username as opponent_name,
                               CASE 
                                   WHEN fb.creator_id = ? THEN 'creator'
                                   ELSE 'opponent'
                               END as user_role
                       FROM fpl_battles fb
                       LEFT JOIN users cu ON fb.creator_id = cu.id
                       LEFT JOIN users ou ON fb.opponent_id = ou.id
                       WHERE fb.creator_id = ? OR fb.opponent_id = ?
                       ORDER BY fb.created_at DESC''', 
                     (session['user_id'], session['user_id'], session['user_id']))
            battles = c.fetchall()
        return render_template('my_fpl_battles.html', battles=battles)
    except:
        return render_template('my_fpl_battles.html', battles=[])

@app.route('/admin_fpl_battles')
@login_required
def admin_fpl_battles():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''SELECT fb.*, 
                               cu.username as creator_name,
                               ou.username as opponent_name
                       FROM fpl_battles fb
                       LEFT JOIN users cu ON fb.creator_id = cu.id
                       LEFT JOIN users ou ON fb.opponent_id = ou.id
                       ORDER BY fb.created_at DESC''')
            battles = c.fetchall()
        return render_template('admin_fpl_battles.html', battles=battles)
    except:
        return render_template('admin_fpl_battles.html', battles=[])

@app.route('/resolve_fpl_battles')
@login_required
def resolve_fpl_battles():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    
    try:
        import requests
        resolved_count = 0
        
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get active battles
            c.execute('SELECT * FROM fpl_battles WHERE status = "active"')
            active_battles = c.fetchall()
            
            for battle in active_battles:
                try:
                    # Get FPL data for both players
                    creator_url = f'https://fantasy.premierleague.com/api/entry/{battle[3]}/event/{battle[10]}/picks/'
                    opponent_url = f'https://fantasy.premierleague.com/api/entry/{battle[5]}/event/{battle[10]}/picks/'
                    
                    creator_response = requests.get(creator_url, timeout=5)
                    opponent_response = requests.get(opponent_url, timeout=5)
                    
                    if creator_response.status_code == 200 and opponent_response.status_code == 200:
                        creator_data = creator_response.json()
                        opponent_data = opponent_response.json()
                        
                        creator_points = creator_data.get('entry_history', {}).get('points', 0)
                        opponent_points = opponent_data.get('entry_history', {}).get('points', 0)
                        
                        # Determine winner
                        winner_id = None
                        status = 'completed'
                        
                        if creator_points > opponent_points:
                            winner_id = battle[2]  # creator_id
                        elif opponent_points > creator_points:
                            winner_id = battle[4]  # opponent_id
                        else:
                            status = 'draw'  # Tie
                        
                        # Update battle
                        c.execute('''UPDATE fpl_battles 
                                   SET status = ?, winner_id = ?, creator_points = ?, opponent_points = ?, completed_at = CURRENT_TIMESTAMP
                                   WHERE id = ?''',
                                 (status, winner_id, creator_points, opponent_points, battle[0]))
                        
                        # Award winnings
                        if winner_id:
                            c.execute('SELECT balance FROM users WHERE id = ?', (winner_id,))
                            current_balance = c.fetchone()[0] or 0
                            new_balance = current_balance + battle[7]  # total_pot
                            c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, winner_id))
                            
                            # Add transaction
                            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                                       VALUES (?, ?, ?, ?)''',
                                     (winner_id, 'fpl_battle_win', battle[7], f'Won FPL Battle #{battle[0]}'))
                        else:
                            # Refund both players for draw
                            for user_id in [battle[2], battle[4]]:
                                c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
                                current_balance = c.fetchone()[0] or 0
                                new_balance = current_balance + battle[6]  # stake_amount
                                c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, user_id))
                                
                                c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                                           VALUES (?, ?, ?, ?)''',
                                         (user_id, 'fpl_battle_refund', battle[6], f'FPL Battle #{battle[0]} - Draw Refund'))
                        
                        resolved_count += 1
                        
                except Exception as e:
                    continue
            
            conn.commit()
        
        flash(f'Resolved {resolved_count} FPL battles', 'success')
        return redirect(url_for('admin_fpl_battles'))
        
    except Exception as e:
        flash('Error resolving battles', 'error')
        return redirect(url_for('admin_fpl_battles'))

@app.route('/battle_status/<int:battle_id>')
@login_required
def battle_status(battle_id):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''SELECT fb.*, 
                               cu.username as creator_name,
                               ou.username as opponent_name
                       FROM fpl_battles fb
                       LEFT JOIN users cu ON fb.creator_id = cu.id
                       LEFT JOIN users ou ON fb.opponent_id = ou.id
                       WHERE fb.id = ? AND (fb.creator_id = ? OR fb.opponent_id = ?)''',
                     (battle_id, session['user_id'], session['user_id']))
            battle = c.fetchone()
            
            if not battle:
                flash('Battle not found', 'error')
                return redirect(url_for('my_fpl_battles'))
            
        return render_template('battle_status.html', battle=battle)
    except:
        flash('Error loading battle', 'error')
        return redirect(url_for('my_fpl_battles'))

@app.route('/withdrawal_chat/<int:withdrawal_id>')
@login_required
def withdrawal_chat(withdrawal_id):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM transactions WHERE id = ? AND user_id = ? AND type = "pending_withdrawal"', 
                     (withdrawal_id, session['user_id']))
            withdrawal = c.fetchone()
            
            if not withdrawal:
                flash('Withdrawal not found', 'error')
                return redirect(url_for('wallet'))
            
        return render_template('withdrawal_chat.html', withdrawal=withdrawal)
    except:
        flash('Error loading withdrawal chat', 'error')
        return redirect(url_for('wallet'))



@app.route('/approve_deposit/<int:transaction_id>', methods=['POST'])
@login_required
def approve_deposit(transaction_id):
    if session.get('username') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get transaction details
            c.execute('SELECT * FROM transactions WHERE id = ? AND type IN ("pending_deposit", "pending_crypto_deposit")', (transaction_id,))
            transaction = c.fetchone()
            
            if not transaction:
                return jsonify({'success': False, 'message': 'Transaction not found'})
            
            user_id = transaction[1]
            amount = transaction[3]
            
            # Update user balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            current_balance = c.fetchone()[0] or 0
            new_balance = current_balance + amount
            c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, user_id))
            
            # Update transaction status
            if transaction[2] == 'pending_crypto_deposit':
                c.execute('UPDATE transactions SET type = "crypto_deposit" WHERE id = ?', (transaction_id,))
            else:
                c.execute('UPDATE transactions SET type = "deposit" WHERE id = ?', (transaction_id,))
            
            conn.commit()
            
        return jsonify({'success': True, 'message': f'Deposit approved! KSh {amount} added to user balance.'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error approving deposit'})

@app.route('/reject_deposit/<int:transaction_id>', methods=['POST'])
@login_required
def reject_deposit(transaction_id):
    if session.get('username') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        data = request.get_json()
        reason = data.get('reason', 'No reason provided')
        
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Update transaction status
            c.execute('UPDATE transactions SET type = "rejected_deposit", description = description || " - Rejected: " || ? WHERE id = ? AND type = "pending_deposit"', 
                     (reason, transaction_id))
            
            if c.rowcount == 0:
                return jsonify({'success': False, 'message': 'Transaction not found'})
            
            conn.commit()
            
        return jsonify({'success': True, 'message': 'Deposit rejected successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error rejecting deposit'})

@app.route('/nowpayments_webhook', methods=['POST'])
def nowpayments_webhook():
    try:
        data = request.get_json()
        payment_status = data.get('payment_status')
        order_id = data.get('order_id', '')
        usd_amount = float(data.get('price_amount', 0))
        
        if '_' in order_id:
            user_id = int(order_id.split('_')[0])
            ksh_amount = usd_amount * 130
            
            with get_db_connection() as conn:
                c = conn.cursor()
                
                if payment_status == 'finished':
                    c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
                    current_balance = c.fetchone()[0] or 0
                    new_balance = current_balance + ksh_amount
                    c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, user_id))
                    
                    c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                               VALUES (?, ?, ?, ?)''',
                             (user_id, 'crypto_deposit', ksh_amount, f'Crypto deposit confirmed - ${usd_amount:.2f} (KSh {ksh_amount:.0f})'))
                    
                elif payment_status in ['failed', 'expired', 'refunded']:
                    c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                               VALUES (?, ?, ?, ?)''',
                             (user_id, 'failed_crypto_deposit', 0, f'Crypto payment {payment_status} - ${usd_amount:.2f}'))
                
                conn.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.errorhandler(404)
def not_found(error):
    return redirect(url_for('home'))

@app.errorhandler(500)
def internal_error(error):
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)