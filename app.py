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
    return sqlite3.connect('gamebet.db')

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
            skill_tokens INTEGER DEFAULT 0
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
        c.execute('''INSERT OR IGNORE INTO users (username, email, password, balance, phone, referral_code) 
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 ('admin', 'admin@skillstake.com', admin_password, 0.0, '0700000000', 'ADMIN001'))
        conn.commit()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-key-change-in-production')
app.permanent_session_lifetime = timedelta(hours=24)

# Rate limiting configuration
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["1000 per day", "200 per hour"]
)

init_db()

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
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
            
            stats = {
                'balance': user[2] or 0,
                'wins': 0,
                'losses': 0,
                'earnings': 0
            }
            
            return render_template('dashboard.html', stats=stats, recent_matches=[])
            
    except Exception as e:
        flash(f'Dashboard error: {str(e)}', 'error')
        return redirect(url_for('login'))

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

@app.route('/quick_matches')
@login_required
def quick_matches():
    games_list = [
        {
            'id': 'fifa_mobile',
            'name': 'FIFA Mobile',
            'min_bet': 100,
            'max_bet': 5000,
            'image': 'https://cdn.cloudflare.steamstatic.com/steam/apps/1811260/header.jpg',
            'modes': [
                {'id': 'h2h', 'name': 'Head to Head', 'description': '11v11 online matches'},
                {'id': 'vsa', 'name': 'VS Attack', 'description': 'Turn-based attacking gameplay'}
            ]
        },
        {
            'id': 'efootball',
            'name': 'eFootball',
            'min_bet': 80,
            'max_bet': 4000,
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
    if request.is_json:
        data = request.get_json()
        game_type = data.get('game_type')
        game_mode = data.get('game_mode')
        stake_amount = data.get('stake_amount')
        game_username = data.get('game_username', '').strip()
    else:
        game_type = request.form.get('game_type')
        game_mode = request.form.get('game_mode')
        stake_amount = request.form.get('stake_amount')
        game_username = request.form.get('game_username', '').strip()
    
    if not all([game_type, game_mode, stake_amount, game_username]):
        error_msg = 'Please fill in all fields.'
        if request.is_json:
            return jsonify({'success': False, 'message': error_msg})
        flash(error_msg, 'error')
        return redirect(url_for('quick_matches'))
    
    try:
        stake = float(stake_amount)
        if not (50 <= stake <= 1000):
            error_msg = 'Stake must be between 50 and 1000.'
            if request.is_json:
                return jsonify({'success': False, 'message': error_msg})
            flash(error_msg, 'error')
            return redirect(url_for('quick_matches'))
    except (ValueError, TypeError):
        error_msg = 'Invalid stake amount.'
        if request.is_json:
            return jsonify({'success': False, 'message': error_msg})
        flash(error_msg, 'error')
        return redirect(url_for('quick_matches'))
    
    if session.get('balance', 0) < stake:
        error_msg = 'Insufficient balance. Please deposit funds.'
        if request.is_json:
            return jsonify({'success': False, 'message': error_msg})
        flash(error_msg, 'error')
        return redirect(url_for('quick_matches'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            commission = stake * 0.08
            total_pot = (stake * 2) - commission
            
            new_balance = session['balance'] - stake
            c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
            session['balance'] = new_balance
            
            c.execute('''INSERT INTO game_matches 
                       (game_type, game_mode, creator_id, creator_game_username, stake_amount, total_pot, commission) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (game_type, game_mode, session['user_id'], game_username, stake, total_pot, commission))
            
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                       VALUES (?, ?, ?, ?)''',
                     (session['user_id'], 'match_stake', -stake, f'{game_type.title()} match stake: {game_mode}'))
            
            conn.commit()
            
        success_msg = f'Match created! Game: {game_type.title()} | Mode: {game_mode} | Stake: KSh {stake}'
        if request.is_json:
            return jsonify({'success': True, 'message': success_msg})
        flash(success_msg, 'success')
        return redirect(url_for('quick_matches'))
        
    except Exception as e:
        error_msg = 'Error creating match. Please try again.'
        if request.is_json:
            return jsonify({'success': False, 'message': error_msg})
        flash(error_msg, 'error')
        return redirect(url_for('quick_matches'))

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