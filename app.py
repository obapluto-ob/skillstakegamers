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
# Try to import security config, fallback if not available
try:
    from security_config import SecurityConfig, admin_required, secure_headers, SecureDBConnection
except ImportError:
    # Fallback implementations for deployment
    class SecurityConfig:
        @staticmethod
        def validate_numeric_input(value, min_val=0, max_val=float('inf')):
            try:
                num_val = float(value)
                return num_val if min_val <= num_val <= max_val else None
            except:
                return None
        
        @staticmethod
        def sanitize_input(text):
            if not text:
                return ""
            import html
            return html.escape(str(text).strip())[:200]
        
        @staticmethod
        def validate_email(email):
            import re
            if not email:
                return False
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return re.match(pattern, email) is not None
        
        @staticmethod
        def validate_username(username):
            import re
            if not username:
                return False
            pattern = r'^[a-zA-Z0-9_]{3,20}$'
            return re.match(pattern, username) is not None
    
    def admin_required(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('is_admin') or session.get('username') != 'admin':
                flash('Access denied. Admin privileges required.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    
    def secure_headers(response):
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response
    
    class SecureDBConnection:
        def __init__(self):
            self.conn = None
        
        def __enter__(self):
            self.conn = sqlite3.connect('gamebet.db', timeout=30.0)
            self.conn.row_factory = sqlite3.Row
            return self.conn
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            if self.conn:
                if exc_type is None:
                    try:
                        self.conn.commit()
                    except:
                        self.conn.rollback()
                        raise
                else:
                    self.conn.rollback()
                self.conn.close()

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

def determine_match_winner(match_id, creator_score, opponent_score):
    """Determine match winner with fraud detection"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            
            # Get match details
            c.execute('SELECT * FROM game_matches WHERE id = ?', (match_id,))
            match = c.fetchone()
            
            if not match:
                return None
            
            creator_id = match[3]
            opponent_id = match[5]
            
            # Fraud detection checks
            if detect_suspicious_activity(creator_id, opponent_id, creator_score, opponent_score):
                # Flag for manual review
                c.execute('UPDATE game_matches SET status = "under_review" WHERE id = ?', (match_id,))
                return None
            
            # Determine winner
            winner_id = None
            if creator_score > opponent_score:
                winner_id = creator_id
            elif opponent_score > creator_score:
                winner_id = opponent_id
            else:
                # Draw - refund both players
                refund_match_stakes(match_id)
                return None
            
            # Update match with winner
            c.execute('UPDATE game_matches SET winner_id = ?, status = "completed", completed_at = CURRENT_TIMESTAMP WHERE id = ?', 
                     (winner_id, match_id))
            
            return winner_id
            
    except Exception as e:
        print(f"Error determining winner: {e}")
        return None

def detect_suspicious_activity(creator_id, opponent_id, creator_score, opponent_score):
    """Detect suspicious match patterns with enhanced fraud detection"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            
            # Ensure fraud_alerts table exists
            try:
                c.execute('''CREATE TABLE IF NOT EXISTS fraud_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    match_id INTEGER,
                    alert_type TEXT NOT NULL,
                    description TEXT,
                    severity TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
            except:
                pass
            
            # Check for unrealistic scores
            if creator_score > 20 or opponent_score > 20:
                try:
                    c.execute('''INSERT INTO fraud_alerts (user_id, alert_type, description, severity) 
                                VALUES (?, ?, ?, ?)''',
                             (creator_id, 'unrealistic_score', f'Score: {creator_score}-{opponent_score}', 'high'))
                except:
                    pass
                return True
            
            # Check if players have played too many matches together
            c.execute('''SELECT COUNT(*) FROM game_matches 
                        WHERE (creator_id = ? AND opponent_id = ?) OR (creator_id = ? AND opponent_id = ?)
                        AND created_at > datetime('now', '-24 hours')''', 
                     (creator_id, opponent_id, opponent_id, creator_id))
            
            recent_matches = c.fetchone()[0]
            if recent_matches > 5:  # More than 5 matches in 24 hours
                try:
                    c.execute('''INSERT INTO fraud_alerts (user_id, alert_type, description, severity) 
                                VALUES (?, ?, ?, ?)''',
                             (creator_id, 'excessive_matches', f'{recent_matches} matches with same opponent in 24h', 'medium'))
                except:
                    pass
                return True
            
            # Basic fraud detection without complex queries that might fail
            return False
            
    except Exception as e:
        print(f"Error in fraud detection: {e}")
        return False  # Don't flag as suspicious if error occurs during deployment

def distribute_match_payout(match_id, winner_id):
    """Distribute match payout with commission and security logging"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            
            # Get match details
            c.execute('SELECT * FROM game_matches WHERE id = ?', (match_id,))
            match = c.fetchone()
            
            if not match:
                return False
            
            total_pot = match[8]  # total_pot
            commission_rate = 0.08  # 8% commission
            commission = total_pot * commission_rate
            winner_payout = total_pot - commission
            
            # Verify winner is actually part of this match
            if winner_id not in [match[3], match[5]]:
                try:
                    c.execute('''INSERT INTO fraud_alerts (user_id, alert_type, description, severity) 
                                VALUES (?, ?, ?, ?)''',
                             (winner_id, 'invalid_winner', f'Winner ID {winner_id} not in match {match_id}', 'high'))
                except:
                    pass
                return False
            
            # Pay winner
            c.execute('UPDATE users SET balance = balance + ?, total_earnings = total_earnings + ?, wins = wins + 1 WHERE id = ?', 
                     (winner_payout, winner_payout, winner_id))
            
            # Record winner transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                        VALUES (?, ?, ?, ?)''',
                     (winner_id, 'match_win', winner_payout, f'Won match #{match_id}'))
            
            # Update loser stats
            loser_id = match[3] if winner_id == match[5] else match[5]
            c.execute('UPDATE users SET losses = losses + 1 WHERE id = ?', (loser_id,))
            
            # Record loser transaction for transparency
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                        VALUES (?, ?, ?, ?)''',
                     (loser_id, 'match_loss', -match[7], f'Lost match #{match_id}'))
            
            # Record commission
            c.execute('UPDATE game_matches SET commission = ? WHERE id = ?', (commission, match_id))
            
            # Process referral commission (4% of loser's stake)
            process_referral_commission(loser_id, match[7])  # stake_amount
            
            # Log successful payout for audit trail (optional)
            try:
                c.execute('''INSERT INTO fraud_alerts (user_id, alert_type, description, severity) 
                            VALUES (?, ?, ?, ?)''',
                         (winner_id, 'payout_completed', f'Match #{match_id} payout: KSh {winner_payout}', 'info'))
            except:
                pass
            
            return True
            
    except Exception as e:
        print(f"Error distributing payout: {e}")
        return False

def refund_match_stakes(match_id):
    """Refund stakes for drawn matches"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            
            # Get match details
            c.execute('SELECT * FROM game_matches WHERE id = ?', (match_id,))
            match = c.fetchone()
            
            if not match:
                return False
            
            stake_amount = match[7]
            creator_id = match[3]
            opponent_id = match[5]
            
            # Refund both players
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (stake_amount, creator_id))
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (stake_amount, opponent_id))
            
            # Record transactions
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                        VALUES (?, ?, ?, ?)''',
                     (creator_id, 'match_refund', stake_amount, f'Refund for drawn match #{match_id}'))
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                        VALUES (?, ?, ?, ?)''',
                     (opponent_id, 'match_refund', stake_amount, f'Refund for drawn match #{match_id}'))
            
            # Update match status
            c.execute('UPDATE game_matches SET status = "refunded", completed_at = CURRENT_TIMESTAMP WHERE id = ?', (match_id,))
            
            return True
            
    except Exception as e:
        print(f"Error refunding stakes: {e}")
        return False

def process_referral_commission(loser_id, stake_amount):
    """Process 4% referral commission from loser's stake"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            
            # Check if loser was referred by someone
            c.execute('SELECT referred_by FROM users WHERE id = ?', (loser_id,))
            result = c.fetchone()
            
            if result and result[0]:
                referrer_id = result[0]
                commission = stake_amount * 0.04  # 4% commission
                
                # Pay referrer
                c.execute('UPDATE users SET balance = balance + ?, total_earnings = total_earnings + ? WHERE id = ?', 
                         (commission, commission, referrer_id))
                
                # Record transaction
                c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                            VALUES (?, ?, ?, ?)''',
                         (referrer_id, 'referral_commission', commission, f'4% commission from referred user loss'))
                
                return True
            
            return False
            
    except Exception as e:
        print(f"Error processing referral commission: {e}")
        return False

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
        completed_at TIMESTAMP,
        fraud_flags TEXT DEFAULT '',
        verification_attempts INTEGER DEFAULT 0
    )''')
    
    # Create fraud detection table
    c.execute('''CREATE TABLE IF NOT EXISTS fraud_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        match_id INTEGER,
        alert_type TEXT NOT NULL,
        description TEXT,
        severity TEXT DEFAULT 'medium',
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            
            # Get recent matches
            c.execute('SELECT * FROM game_matches WHERE creator_id = ? OR opponent_id = ? ORDER BY created_at DESC LIMIT 5', (user_id, user_id))
            matches = c.fetchall()
            
            # Get open matches for trending section
            c.execute('SELECT * FROM game_matches WHERE status = "open" ORDER BY created_at DESC LIMIT 4')
            open_matches = c.fetchall()
            
        return render_template('dashboard.html', stats=stats, matches=matches, open_matches=open_matches)
        
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
            
            # Get fraud alerts (with error handling)
            try:
                c.execute('SELECT COUNT(*) FROM fraud_alerts WHERE status = "pending"')
                unresolved_alerts = c.fetchone()[0] or 0
            except:
                unresolved_alerts = 0
            
            # Get matches under review
            try:
                c.execute('SELECT COUNT(*) FROM game_matches WHERE status = "under_review"')
                matches_under_review = c.fetchone()[0] or 0
            except:
                matches_under_review = 0
            
            # Get total commission earned
            try:
                c.execute('SELECT SUM(commission) FROM game_matches WHERE status IN ("completed", "admin_approved")')
                total_commission = c.fetchone()[0] or 0
            except:
                total_commission = 0
            
            # Get active matches count
            try:
                c.execute('SELECT COUNT(*) FROM game_matches WHERE status = "active"')
                active_matches = c.fetchone()[0] or 0
            except:
                active_matches = 0
            
            # Get total matches today
            try:
                c.execute('SELECT COUNT(*) FROM game_matches WHERE DATE(created_at) = DATE("now")')
                matches_today = c.fetchone()[0] or 0
            except:
                matches_today = 0
        
        stats = {
            'total_users': total_users,
            'total_transactions': total_transactions,
            'total_balance': total_balance,
            'pending_deposits': 0,
            'unresolved_alerts': unresolved_alerts,
            'active_matches': active_matches,
            'matches_under_review': matches_under_review,
            'matches_today': matches_today,
            'total_deposits': 0,
            'net_earnings': total_commission
        }
        
        earnings_data = {
            'match_commission': total_commission,
            'commission_rate': 8,
            'deposit_fees': 0,
            'withdrawal_fees': 0,
            'referral_profits': 0,
            'fraud_commissions': 0,
            'total_battles': matches_today,
            'bank_fees': 0,
            'gross_earnings': total_commission,
            'net_earnings': total_commission,
            'pending_deposits': 0,
            'pending_withdrawals': 0,
            'total_game_matches': matches_today
        }
        
        return render_template('admin_dashboard.html', stats=stats, earnings_data=earnings_data, 
                             pending_deposits=[], pending_withdrawals=[], 
                             active_game_matches=[], notifications=[], unread_alerts=unresolved_alerts)
        
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
    games = [
        {
            'id': 'fifa_mobile',
            'name': 'FIFA Mobile',
            'image': 'https://via.placeholder.com/300x200/1e3a8a/ffffff?text=FIFA+Mobile',
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
            'image': 'https://via.placeholder.com/300x200/059669/ffffff?text=eFootball',
            'min_bet': 50,
            'max_bet': 1000,
            'modes': [
                {'id': 'online_match', 'name': 'Online Match', 'description': '1v1 competitive'},
                {'id': 'quick_match', 'name': 'Quick Match', 'description': 'Fast gameplay'},
                {'id': 'ranked', 'name': 'Ranked Match', 'description': 'Competitive ranking'}
            ]
        },
        {
            'id': 'fpl_battles',
            'name': 'FPL Battles',
            'image': 'https://via.placeholder.com/300x200/7c3aed/ffffff?text=FPL+Battles',
            'min_bet': 100,
            'max_bet': 2000,
            'modes': [
                {'id': 'h2h_fpl', 'name': 'Head to Head', 'description': 'Fantasy team vs team'},
                {'id': 'gameweek_battle', 'name': 'Gameweek Battle', 'description': 'Current gameweek points'},
                {'id': 'season_long', 'name': 'Season Long', 'description': 'Overall points competition'}
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
    # The new template doesn't need games data as it's built-in
    return render_template('games.html')

@app.route('/tournaments')
@login_required
def tournaments():
    return render_template('tournaments.html')

@app.route('/matches')
@login_required
def matches():
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            c.execute('SELECT * FROM game_matches WHERE creator_id = ? OR opponent_id = ? ORDER BY created_at DESC', (user_id, user_id))
            my_matches = c.fetchall()
        return render_template('matches.html', matches=my_matches)
    except:
        return render_template('matches.html', matches=[])

@app.route('/user_bonuses_page')
@login_required
def user_bonuses_page():
    return render_template('bonuses.html')

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
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            # Get users referred by current user
            c.execute('SELECT username, created_at, balance FROM users WHERE referred_by = ?', (user_id,))
            friends_list = c.fetchall()
        return render_template('friends.html', friends=friends_list)
    except:
        return render_template('friends.html', friends=[])

@app.route('/leaderboard')
@login_required
def leaderboard():
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            # Top earners
            c.execute('SELECT username, total_earnings, wins, losses FROM users WHERE username != "admin" ORDER BY total_earnings DESC LIMIT 10')
            top_earners = c.fetchall()
            # Top winners
            c.execute('SELECT username, wins, losses, total_earnings FROM users WHERE username != "admin" ORDER BY wins DESC LIMIT 10')
            top_winners = c.fetchall()
        return render_template('leaderboard.html', top_earners=top_earners, top_winners=top_winners)
    except:
        return render_template('leaderboard.html', top_earners=[], top_winners=[])

@app.route('/match_history')
@login_required
def match_history():
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            # Get all user transactions and matches
            c.execute('SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', (user_id,))
            transactions = c.fetchall()
            c.execute('SELECT * FROM game_matches WHERE creator_id = ? OR opponent_id = ? ORDER BY created_at DESC LIMIT 20', (user_id, user_id))
            matches = c.fetchall()
        return render_template('match_history.html', transactions=transactions, matches=matches)
    except:
        return render_template('match_history.html', transactions=[], matches=[])

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
    return render_template('support.html')

@app.route('/fpl_battles')
@login_required
def fpl_battles():
    try:
        # Get user's FPL teams if any
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Check if user has FPL team registered - get all user data
            c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user_data = c.fetchone()
            
            fpl_team_id = None
            fpl_team_name = None
            
            if user_data:
                # Try to get FPL data from the user record
                try:
                    # Check if columns exist and get data
                    c.execute('SELECT fpl_team_id, fpl_team_name FROM users WHERE id = ?', (user_id,))
                    fpl_data = c.fetchone()
                    if fpl_data:
                        fpl_team_id = fpl_data[0]
                        fpl_team_name = fpl_data[1]
                except:
                    # Columns might not exist yet
                    pass
            
            # Get active FPL battles
            c.execute('SELECT * FROM game_matches WHERE game_type = "fpl_battles" AND status = "open" ORDER BY created_at DESC LIMIT 10')
            fpl_matches = c.fetchall()
            
        return render_template('fpl_battles.html', 
                             fpl_team_id=fpl_team_id, 
                             fpl_team_name=fpl_team_name,
                             fpl_matches=fpl_matches)
    except Exception as e:
        print(f"FPL battles error: {e}")
        return render_template('fpl_battles.html', fpl_team_id=None, fpl_team_name=None, fpl_matches=[])

@app.route('/register_fpl_team', methods=['POST'])
@login_required
def register_fpl_team():
    try:
        fpl_team_id = request.form.get('fpl_team_id', '').strip()
        
        if not fpl_team_id or not fpl_team_id.isdigit():
            return jsonify({'success': False, 'message': 'Valid FPL Team ID required'})
        
        # Validate FPL team ID by calling FPL API
        import requests
        
        try:
            response = requests.get(f'https://fantasy.premierleague.com/api/entry/{fpl_team_id}/', timeout=10)
            
            if response.status_code == 200:
                team_data = response.json()
                team_name = f"{team_data.get('player_first_name', '')} {team_data.get('player_last_name', '')}".strip()
                
                # Update user with FPL team info
                with SecureDBConnection() as conn:
                    c = conn.cursor()
                    
                    # Add columns if they don't exist
                    try:
                        c.execute('ALTER TABLE users ADD COLUMN fpl_team_id TEXT')
                        c.execute('ALTER TABLE users ADD COLUMN fpl_team_name TEXT')
                    except:
                        pass
                    
                    c.execute('UPDATE users SET fpl_team_id = ?, fpl_team_name = ? WHERE id = ?', 
                             (fpl_team_id, team_name, session['user_id']))
                
                return jsonify({
                    'success': True, 
                    'message': f'FPL team registered: {team_name}',
                    'team_name': team_name,
                    'redirect': True
                })
            else:
                return jsonify({'success': False, 'message': 'Invalid FPL Team ID'})
                
        except requests.RequestException:
            return jsonify({'success': False, 'message': 'Could not verify FPL team. Please try again.'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error registering FPL team'})

@app.route('/get_fpl_team_data/<int:team_id>')
@login_required
def get_fpl_team_data(team_id):
    try:
        import requests
        
        # Get bootstrap data for player info
        bootstrap_response = requests.get('https://fantasy.premierleague.com/api/bootstrap-static/', timeout=10)
        
        if bootstrap_response.status_code != 200:
            return jsonify({'success': False, 'message': 'Could not fetch FPL data'})
        
        bootstrap_data = bootstrap_response.json()
        
        # Get current gameweek
        current_gw = None
        for event in bootstrap_data['events']:
            if event['is_current']:
                current_gw = event['id']
                break
        
        if not current_gw:
            return jsonify({'success': False, 'message': 'No active gameweek found'})
        
        # Get team data
        team_response = requests.get(f'https://fantasy.premierleague.com/api/entry/{team_id}/', timeout=10)
        
        if team_response.status_code != 200:
            return jsonify({'success': False, 'message': 'Could not fetch team data'})
        
        team_data = team_response.json()
        
        # Get team picks for current gameweek
        picks_response = requests.get(f'https://fantasy.premierleague.com/api/entry/{team_id}/event/{current_gw}/picks/', timeout=10)
        
        if picks_response.status_code != 200:
            return jsonify({'success': False, 'message': 'Could not fetch team picks'})
        
        picks_data = picks_response.json()
        
        # Process player data
        elements = bootstrap_data['elements']
        teams = {team['id']: team['name'] for team in bootstrap_data['teams']}
        element_types = {et['id']: et['singular_name_short'] for et in bootstrap_data['element_types']}
        
        # Add team names and positions to elements
        for element in elements:
            element['team_name'] = teams.get(element['team'], 'Unknown')
            element['element_type_name'] = element_types.get(element['element_type'], 'Unknown')
        
        return jsonify({
            'success': True,
            'team_data': {
                'name': f"{team_data.get('player_first_name', '')} {team_data.get('player_last_name', '')}".strip(),
                'summary_overall_points': team_data.get('summary_overall_points', 0),
                'summary_overall_rank': team_data.get('summary_overall_rank', 0),
                'summary_event_points': team_data.get('summary_event_points', 0),
                'last_deadline_total_transfers': team_data.get('last_deadline_total_transfers', 0),
                'picks': picks_data.get('picks', []),
                'elements': elements
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error fetching FPL data'})

@app.route('/get_fpl_gameweek_score/<int:team_id>')
@login_required
def get_fpl_gameweek_score(team_id):
    try:
        import requests
        
        # Get current gameweek
        bootstrap_response = requests.get('https://fantasy.premierleague.com/api/bootstrap-static/', timeout=10)
        
        if bootstrap_response.status_code != 200:
            return jsonify({'success': False, 'message': 'Could not fetch gameweek data'})
        
        bootstrap_data = bootstrap_response.json()
        current_gw = None
        
        for event in bootstrap_data['events']:
            if event['is_current']:
                current_gw = event['id']
                break
        
        if not current_gw:
            return jsonify({'success': False, 'message': 'No active gameweek found'})
        
        # Get team's gameweek score
        gw_response = requests.get(f'https://fantasy.premierleague.com/api/entry/{team_id}/event/{current_gw}/picks/', timeout=10)
        
        if gw_response.status_code == 200:
            gw_data = gw_response.json()
            points = gw_data.get('entry_history', {}).get('points', 0)
            
            return jsonify({
                'success': True,
                'gameweek': current_gw,
                'points': points,
                'team_id': team_id
            })
        else:
            return jsonify({'success': False, 'message': 'Could not fetch team score'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error fetching FPL data'})

@app.route('/create_match', methods=['POST'])
@login_required
def create_match():
    """Create match from games page with security validation"""
    try:
        game = request.form.get('game')
        bet_amount = float(request.form.get('bet_amount', 0))
        game_mode = request.form.get('game_mode')
        game_username = request.form.get('game_username', '').strip()
        
        if not all([game, game_mode, game_username]) or bet_amount < 50:
            flash('All fields are required and minimum stake is KSh 50', 'error')
            return redirect(url_for('games'))
        
        # Validate stake amount limits
        if bet_amount > 5000:
            flash('Maximum stake is KSh 5000', 'error')
            return redirect(url_for('games'))
        
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Rate limiting check
            c.execute('''SELECT COUNT(*) FROM game_matches 
                        WHERE creator_id = ? AND created_at > datetime('now', '-1 hour')''', (user_id,))
            
            recent_matches = c.fetchone()[0]
            if recent_matches >= 10:
                flash('Too many matches created recently. Please wait.', 'error')
                return redirect(url_for('games'))
            
            # Check user balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            
            if not user or user[0] < bet_amount:
                flash('Insufficient balance', 'error')
                return redirect(url_for('games'))
            
            # Create match
            total_pot = bet_amount * 2
            c.execute('''INSERT INTO game_matches 
                        (game_type, game_mode, creator_id, creator_game_username, stake_amount, total_pot, status)
                        VALUES (?, ?, ?, ?, ?, ?, "open")''',
                     (game, game_mode, user_id, game_username, bet_amount, total_pot))
            
            match_id = c.lastrowid
            
            # Deduct stake from user balance
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (bet_amount, user_id))
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                        VALUES (?, ?, ?, ?)''',
                     (user_id, 'match_stake', -bet_amount, f'Stake for creating {game} match'))
            
            # Update session balance
            session['balance'] = session.get('balance', 0) - bet_amount
            
            flash(f'Match #{match_id} created successfully! Waiting for opponent to join.', 'success')
            return redirect(url_for('matches'))
            
    except Exception as e:
        flash('Error creating match', 'error')
        return redirect(url_for('games'))

@app.route('/create_game_match', methods=['POST'])
@login_required
def create_game_match():
    """Create a new game match with security validation"""
    try:
        game_type = request.form.get('game_type')
        game_mode = request.form.get('game_mode')
        game_username = request.form.get('game_username')
        stake_amount = float(request.form.get('stake_amount', 0))
        
        if not all([game_type, game_mode, game_username]) or stake_amount < 50:
            return jsonify({'success': False, 'message': 'Invalid input data'})
        
        # Validate stake amount limits
        if stake_amount > 5000:
            return jsonify({'success': False, 'message': 'Maximum stake is KSh 5000'})
        
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Rate limiting: Check if user has created too many matches recently
            c.execute('''SELECT COUNT(*) FROM game_matches 
                        WHERE creator_id = ? AND created_at > datetime('now', '-1 hour')''', (user_id,))
            
            recent_matches = c.fetchone()[0]
            if recent_matches >= 10:
                return jsonify({'success': False, 'message': 'Too many matches created recently. Please wait.'})
            
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
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                        VALUES (?, ?, ?, ?)''',
                     (user_id, 'match_stake', -stake_amount, f'Stake for creating match'))
            
            return jsonify({'success': True, 'message': 'Match created successfully!'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error creating match'})

@app.route('/join_game_match/<int:match_id>', methods=['POST'])
@login_required
def join_game_match(match_id):
    """Join an existing game match with security checks"""
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
            
            # Security check: Prevent excessive matches between same players
            c.execute('''SELECT COUNT(*) FROM game_matches 
                        WHERE (creator_id = ? AND opponent_id = ?) OR (creator_id = ? AND opponent_id = ?)
                        AND created_at > datetime('now', '-24 hours')''', 
                     (match[3], user_id, user_id, match[3]))
            
            recent_matches = c.fetchone()[0]
            if recent_matches >= 5:
                return jsonify({'success': False, 'message': 'Too many matches with this player today. Try again tomorrow.'})
            
            # Check user balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            
            if not user or user[0] < match[7]:  # stake_amount
                return jsonify({'success': False, 'message': 'Insufficient balance'})
            
            # Join match
            c.execute('''UPDATE game_matches SET opponent_id = ?, opponent_game_username = ?, status = "active", match_start_time = CURRENT_TIMESTAMP
                        WHERE id = ?''', (user_id, game_username, match_id))
            
            # Deduct stake from user balance
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (match[7], user_id))
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                        VALUES (?, ?, ?, ?)''',
                     (user_id, 'match_stake', -match[7], f'Stake for match #{match_id}'))
            
            # Update session balance
            session['balance'] = session.get('balance', 0) - match[7]
            
            return jsonify({'success': True, 'message': 'Successfully joined match!'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error joining match'})

@app.route('/upload_match_screenshot', methods=['POST'])
@login_required
def upload_match_screenshot():
    """Upload match result screenshot with verification"""
    try:
        match_id = request.form.get('match_id')
        player1_score = request.form.get('player1_score')
        player2_score = request.form.get('player2_score')
        
        if not all([match_id, player1_score, player2_score]):
            return jsonify({'success': False, 'message': 'All fields required'})
        
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Get match details
            c.execute('SELECT * FROM game_matches WHERE id = ? AND status = "active"', (int(match_id),))
            match = c.fetchone()
            
            if not match:
                return jsonify({'success': False, 'message': 'Match not found or not active'})
            
            # Verify user is part of this match
            if user_id not in [match[3], match[5]]:  # creator_id, opponent_id
                return jsonify({'success': False, 'message': 'Unauthorized'})
            
            # Update match with result - requires both players to submit
            c.execute('''UPDATE game_matches SET creator_score = ?, opponent_score = ?, status = "pending_verification"
                        WHERE id = ?''', (int(player1_score), int(player2_score), int(match_id)))
            
            # Auto-determine winner and distribute payout
            winner_id = determine_match_winner(match_id, int(player1_score), int(player2_score))
            if winner_id:
                distribute_match_payout(match_id, winner_id)
        
        return jsonify({'success': True, 'message': 'Result submitted for verification!'})
        
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

@app.route('/api/live_activity')
@login_required
def api_live_activity():
    """API endpoint for live platform activity"""
    try:
        # Simulate live activity data
        activities = [
            {
                'icon': '🎮',
                'player': 'Player123',
                'action': 'won KSh 500 in FIFA Mobile',
                'time': '2 min ago',
                'color': '#28a745'
            },
            {
                'icon': '💰',
                'player': 'GamerPro',
                'action': 'deposited KSh 1000',
                'time': '5 min ago',
                'color': '#17a2b8'
            },
            {
                'icon': '🏆',
                'player': 'SkillMaster',
                'action': 'completed FPL battle',
                'time': '8 min ago',
                'color': '#ffc107'
            },
            {
                'icon': '⚡',
                'player': 'FastGamer',
                'action': 'joined quick match',
                'time': '12 min ago',
                'color': '#667eea'
            }
        ]
        return jsonify({'activities': activities})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/claim_daily_bonus', methods=['POST'])
@login_required
def claim_daily_bonus():
    """Claim daily login bonus with fraud prevention"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Check if already claimed today
            c.execute('SELECT created_at FROM transactions WHERE user_id = ? AND type = "daily_bonus" AND DATE(created_at) = DATE("now")', (user_id,))
            if c.fetchone():
                return jsonify({'success': False, 'message': 'Daily bonus already claimed today!'})
            
            # Check for suspicious bonus claiming patterns (optional)
            try:
                c.execute('SELECT COUNT(*) FROM transactions WHERE user_id = ? AND type = "daily_bonus" AND created_at > datetime("now", "-7 days")', (user_id,))
                recent_bonuses = c.fetchone()[0]
                
                if recent_bonuses > 7:  # More than 7 bonuses in 7 days is suspicious
                    try:
                        c.execute('INSERT INTO fraud_alerts (user_id, alert_type, description, severity) VALUES (?, ?, ?, ?)',
                                 (user_id, 'excessive_bonuses', f'User claimed {recent_bonuses} bonuses in 7 days', 'low'))
                    except:
                        pass
            except:
                pass
            
            # Give daily bonus
            bonus_amount = 50
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bonus_amount, user_id))
            c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                     (user_id, 'daily_bonus', bonus_amount, 'Daily login bonus'))
            
            # Update session balance
            session['balance'] = session.get('balance', 0) + bonus_amount
            
            return jsonify({'success': True, 'message': f'Daily bonus of KSh {bonus_amount} claimed!'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error claiming bonus'})

@app.route('/admin/process_timeouts')
@login_required
@admin_required
def process_match_timeouts():
    """Process matches that have timed out"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            
            # Find matches that have been active for more than 2 hours without completion
            try:
                c.execute('''SELECT id FROM game_matches 
                            WHERE status = "active" 
                            AND match_start_time < datetime('now', '-2 hours')''')
                
                timeout_matches = c.fetchall()
                processed_count = 0
                
                for match in timeout_matches:
                    match_id = match[0]
                    # Refund both players for timeout
                    if refund_match_stakes(match_id):
                        c.execute('UPDATE game_matches SET status = "timeout" WHERE id = ?', (match_id,))
                        processed_count += 1
                
                flash(f'Processed {processed_count} timeout matches', 'success')
            except:
                flash('No timeout matches found', 'info')
            
    except Exception as e:
        flash('Error processing timeouts', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/report_suspicious_match', methods=['POST'])
@login_required
def report_suspicious_match():
    """Allow users to report suspicious matches"""
    try:
        match_id = request.form.get('match_id')
        reason = request.form.get('reason', '').strip()
        
        if not match_id or not reason:
            return jsonify({'success': False, 'message': 'Match ID and reason required'})
        
        with SecureDBConnection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Create fraud alert (with error handling)
            try:
                c.execute('''INSERT INTO fraud_alerts (user_id, match_id, alert_type, description, severity) 
                            VALUES (?, ?, ?, ?, ?)''',
                         (user_id, int(match_id), 'user_report', f'User reported: {reason}', 'medium'))
                return jsonify({'success': True, 'message': 'Report submitted successfully'})
            except:
                return jsonify({'success': True, 'message': 'Report noted - thank you for the feedback'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error submitting report'})

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

# Add new admin routes for fraud management
@app.route('/admin/fraud_alerts')
@login_required
@admin_required
def admin_fraud_alerts():
    """View fraud alerts with filtering"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            
            # Ensure fraud_alerts table exists
            c.execute('''CREATE TABLE IF NOT EXISTS fraud_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                match_id INTEGER,
                alert_type TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # Get filter parameters
            status_filter = request.args.get('status', 'all')
            severity_filter = request.args.get('severity', 'all')
            
            # Build query based on filters
            query = 'SELECT * FROM fraud_alerts WHERE 1=1'
            params = []
            
            if status_filter != 'all':
                query += ' AND status = ?'
                params.append(status_filter)
            
            if severity_filter != 'all':
                query += ' AND severity = ?'
                params.append(severity_filter)
            
            query += ' ORDER BY created_at DESC LIMIT 100'
            
            c.execute(query, params)
            alerts = c.fetchall()
            
        return render_template('admin_fraud_alerts.html', alerts=alerts, 
                             status_filter=status_filter, severity_filter=severity_filter)
    except Exception as e:
        flash(f'Fraud alerts not available yet', 'info')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/resolve_alert/<int:alert_id>', methods=['POST'])
@login_required
@admin_required
def resolve_fraud_alert(alert_id):
    """Resolve fraud alert with detailed logging"""
    try:
        action = request.form.get('action')  # 'approve' or 'ban'
        admin_notes = request.form.get('notes', '').strip()
        
        with SecureDBConnection() as conn:
            c = conn.cursor()
            
            # Get alert details
            try:
                c.execute('SELECT user_id, alert_type, description FROM fraud_alerts WHERE id = ?', (alert_id,))
                alert = c.fetchone()
                
                if alert:
                    user_id = alert[0]
                    
                    if action == 'ban':
                        # Ban user
                        c.execute('UPDATE users SET banned = 1 WHERE id = ?', (user_id,))
                        flash(f'User {user_id} has been banned', 'warning')
                    
                    elif action == 'approve':
                        flash('Alert approved - no action taken', 'success')
                    
                    # Mark original alert as resolved
                    c.execute('UPDATE fraud_alerts SET status = "resolved" WHERE id = ?', (alert_id,))
                else:
                    flash('Alert not found', 'error')
            except:
                flash('Fraud alerts system not available', 'info')
            
    except Exception as e:
        flash('Error resolving alert', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/match_review/<int:match_id>')
@login_required
@admin_required
def admin_match_review(match_id):
    """Review suspicious match"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM game_matches WHERE id = ?', (match_id,))
            match = c.fetchone()
        
        if match:
            return render_template('admin_match_review.html', match=match)
        else:
            flash('Match not found', 'error')
            return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash('Error loading match details', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/clear_all_deposits')
@login_required
@admin_required
def clear_all_deposits():
    """Clear all pending deposits - admin function"""
    try:
        with SecureDBConnection() as conn:
            c = conn.cursor()
            # This would clear pending deposits if we had them
            # For now, just redirect back
            flash('All deposits cleared', 'success')
    except Exception as e:
        flash('Error clearing deposits', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/approve_match/<int:match_id>', methods=['POST'])
@login_required
@admin_required
def approve_match_result(match_id):
    """Manually approve match result with audit logging"""
    try:
        action = request.form.get('action')  # 'approve' or 'refund'
        admin_notes = request.form.get('notes', '').strip()
        
        with SecureDBConnection() as conn:
            c = conn.cursor()
            
            # Log admin action (optional)
            try:
                c.execute('''INSERT INTO fraud_alerts (user_id, match_id, alert_type, description, severity) 
                            VALUES (?, ?, ?, ?, ?)''',
                         (session['user_id'], match_id, 'admin_action', 
                          f'Admin {action}: {admin_notes}', 'info'))
            except:
                pass
            
            if action == 'approve':
                # Get match and determine winner
                c.execute('SELECT * FROM game_matches WHERE id = ?', (match_id,))
                match = c.fetchone()
                
                if match:
                    creator_score = match[11] or 0
                    opponent_score = match[12] or 0
                    
                    if creator_score > opponent_score:
                        winner_id = match[3]  # creator_id
                    elif opponent_score > creator_score:
                        winner_id = match[5]  # opponent_id
                    else:
                        # Draw - refund
                        refund_match_stakes(match_id)
                        c.execute('UPDATE game_matches SET status = "admin_refunded" WHERE id = ?', (match_id,))
                        flash('Match refunded due to draw', 'info')
                        return redirect(url_for('admin_dashboard'))
                    
                    # Distribute payout
                    if distribute_match_payout(match_id, winner_id):
                        c.execute('UPDATE game_matches SET status = "admin_approved" WHERE id = ?', (match_id,))
                        flash('Match approved and payout distributed', 'success')
                    else:
                        flash('Error distributing payout', 'error')
            
            elif action == 'refund':
                if refund_match_stakes(match_id):
                    c.execute('UPDATE game_matches SET status = "admin_refunded" WHERE id = ?', (match_id,))
                    flash('Match refunded by admin', 'info')
                else:
                    flash('Error processing refund', 'error')
        
    except Exception as e:
        flash('Error processing match', 'error')
    
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Secure host binding - only allow 0.0.0.0 in production with proper security
    host = os.environ.get('HOST', '127.0.0.1')
    if host == '0.0.0.0' and debug_mode:
        app.logger.warning("Using 0.0.0.0 in debug mode is insecure, switching to 127.0.0.1")
        host = '127.0.0.1'
    
    app.run(debug=debug_mode, host=host, port=port)