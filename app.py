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
app.permanent_session_lifetime = timedelta(hours=24)

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
                
                c.execute('''INSERT INTO users (username, email, password, referral_code, email_verified) 
                             VALUES (?, ?, ?, ?, ?)''',
                         (username, email, hashed_password, referral_code, 0))
                
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
                    session.clear()
                    session.permanent = True
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    session['balance'] = user[4]
                    session['is_admin'] = user[1] == 'admin'
                    session['logged_in'] = True
                    
                    if user[1] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('dashboard'))
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
        email = sanitize_input(request.form.get('email', '').strip())
        
        if not validate_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('forgot_password.html')
        if email:
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
        else:
            flash('Please enter your email address.', 'error')
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
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
    return render_template('wallet.html')

@app.route('/quick_matches')
@login_required
def quick_matches():
    return render_template('quick_matches.html')

@app.route('/games', endpoint='games')
@login_required
def games_page():
    return redirect(url_for('home'))

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
    return render_template('profile.html')

@app.route('/support_chat')
@login_required
def support_chat():
    return redirect(url_for('dashboard'))

@app.route('/fpl_battles')
@login_required
def fpl_battles():
    return redirect(url_for('dashboard'))

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

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
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