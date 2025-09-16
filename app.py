from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
from datetime import timedelta, datetime
from dotenv import load_dotenv
import random

load_dotenv()

def get_db_connection():
    return sqlite3.connect('gamebet.db', timeout=30.0)

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
    admin_password = generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin123'))
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
        conn = get_db_connection()
        c = conn.cursor()
        user_id = session['user_id']
        
        c.execute('SELECT id, username, balance FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        
        if not user:
            session.clear()
            flash('User not found. Please login again.', 'error')
            return redirect(url_for('login'))
        
        session['balance'] = user[2] or 0
        
        stats = {
            'balance': user[2] or 0,
            'wins': 0,
            'losses': 0,
            'earnings': 0
        }
        
        conn.close()
        return render_template('dashboard.html', stats=stats, recent_matches=[])
        
    except Exception as e:
        flash(f'Dashboard error: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@app.route('/register_fixed', methods=['GET', 'POST'])
def register_fixed():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return render_template('register_fixed.html')
        
        try:
            conn = get_db_connection()
            c = conn.cursor()
            
            # Check if user exists
            c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if c.fetchone():
                flash('Username or email already exists!', 'error')
                conn.close()
                return render_template('register_fixed.html')
            
            # Create user
            hashed_password = generate_password_hash(password)
            referral_code = f'REF{random.randint(100000, 999999)}'
            
            c.execute('''INSERT INTO users (username, email, password, referral_code, email_verified) 
                         VALUES (?, ?, ?, ?, ?)''',
                     (username, email, hashed_password, referral_code, 1))
            
            conn.commit()
            conn.close()
            
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register_fixed.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form.get('login_input', '').strip()
        password = request.form.get('password', '')
        
        if not login_input or not password:
            flash('Please enter both username/email and password!', 'error')
            return render_template('login_fixed.html')
        
        try:
            conn = get_db_connection()
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
                
            conn.close()
        except Exception as e:
            flash('Login error occurred. Please try again.', 'error')
    
    return render_template('login_fixed.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    
    try:
        conn = get_db_connection()
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
        
        conn.close()
        return render_template('admin_dashboard.html', stats=stats, earnings_data={}, 
                             pending_deposits=[], pending_withdrawals=[], 
                             active_game_matches=[], notifications=[], unread_alerts=0)
        
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}', 'error')
        return render_template('admin_dashboard.html', stats={}, earnings_data={}, 
                             pending_deposits=[], pending_withdrawals=[], 
                             active_game_matches=[], notifications=[], unread_alerts=0)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if email:
            flash('Password reset instructions sent to your email (if account exists).', 'info')
        else:
            flash('Please enter your email address.', 'error')
    return render_template('forgot_password.html')

@app.route('/admin/users')
@login_required
def admin_users():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/transactions')
@login_required
def admin_transactions():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/matches')
@login_required
def admin_matches():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/support_center')
@login_required
def admin_support_center():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    return redirect(url_for('admin_dashboard'))

@app.route('/api_test')
@login_required
def api_test():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    return redirect(url_for('admin_dashboard'))

@app.route('/games')
def games():
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.errorhandler(404)
def not_found(error):
    return redirect(url_for('home'))

@app.errorhandler(500)
def internal_error(error):
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)