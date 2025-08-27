from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import os
import secrets
import re

app = Flask(__name__)
app.secret_key = 'gamebet_secret_key_2024'
app.config['WTF_CSRF_ENABLED'] = False

# Disable optional modules that might cause issues
result_detector = None
security_manager = None

# CSP header disabled for testing
# @app.after_request
# def add_security_headers(response):
#     response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https:; img-src 'self' https: data:; font-src 'self' https:;"
#     return response

# Database optimization
DB_PATH = 'gamebet.db'

def get_db_connection():
    """Get optimized database connection"""
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.execute('PRAGMA journal_mode=WAL')  # Better concurrency
    conn.execute('PRAGMA synchronous=NORMAL')  # Faster writes
    conn.execute('PRAGMA cache_size=10000')  # More cache
    conn.execute('PRAGMA temp_store=MEMORY')  # Use memory for temp
    return conn

# Database setup
def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        balance REAL DEFAULT 0.0,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        total_earnings REAL DEFAULT 0.0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Matches table
    c.execute('''CREATE TABLE IF NOT EXISTS matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game TEXT NOT NULL,
        player1_id INTEGER,
        player2_id INTEGER,
        bet_amount REAL NOT NULL,
        total_pot REAL NOT NULL,
        winner_id INTEGER,
        status TEXT DEFAULT 'pending',
        game_mode TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (player1_id) REFERENCES users (id),
        FOREIGN KEY (player2_id) REFERENCES users (id),
        FOREIGN KEY (winner_id) REFERENCES users (id)
    )''')
    
    # Transactions table
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Match results table for fraud prevention
    c.execute('''CREATE TABLE IF NOT EXISTS match_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER,
        user_id INTEGER,
        result_claimed TEXT NOT NULL,
        proof_text TEXT,
        screenshot_data TEXT,
        ai_verification TEXT,
        confidence REAL,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (match_id) REFERENCES matches (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Match ready status table
    c.execute('''CREATE TABLE IF NOT EXISTS match_ready (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER,
        user_id INTEGER,
        ready_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (match_id) REFERENCES matches (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Security logs table
    c.execute('''CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        user_id INTEGER,
        ip_address TEXT,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Add security fields to users table
    try:
        c.execute('ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0')
        c.execute('ALTER TABLE users ADD COLUMN last_login_attempt TIMESTAMP')
        c.execute('ALTER TABLE users ADD COLUMN account_locked BOOLEAN DEFAULT 0')
        c.execute('ALTER TABLE users ADD COLUMN suspicious_activity_score INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Columns already exist
    
    # Add screenshot hash to match_results
    try:
        c.execute('ALTER TABLE match_results ADD COLUMN screenshot_hash TEXT')
    except sqlite3.OperationalError:
        pass
    
    # Create deposit verifications table
    c.execute('''CREATE TABLE IF NOT EXISTS deposit_verifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id INTEGER,
        user_id INTEGER,
        mpesa_number TEXT NOT NULL,
        sender_name TEXT NOT NULL,
        receipt_screenshot TEXT NOT NULL,
        amount_sent REAL NOT NULL,
        verified BOOLEAN DEFAULT 0,
        verified_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (transaction_id) REFERENCES transactions (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Add database indexes for performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_matches_players ON matches(player1_id, player2_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type)')
    
    conn.commit()
    
    # Create admin user if not exists
    c.execute('SELECT * FROM users WHERE username = "admin"')
    admin_exists = c.fetchone()
    
    if not admin_exists:
        admin_password = generate_password_hash('admin123')  # Change this password!
        c.execute('INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)',
                 ('admin', 'admin@gamebet.com', admin_password, 0.0))
        conn.commit()
        print("Admin user created: username=admin, password=admin123")
    
    conn.close()

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        
        # Input validation
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            flash('Username must be 3-20 characters, letters/numbers/underscore only', 'error')
            return render_template('register.html')
        
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email format', 'error')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return render_template('register.html')
        
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        try:
            hashed_password = generate_password_hash(password)
            c.execute('INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)',
                     (username, email, hashed_password, 0.0))  # Start with KSh 0
            conn.commit()
            flash('Registration successful! Add funds to start playing.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists!', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        ip_address = request.environ.get('REMOTE_ADDR', 'unknown')
        
        # Rate limiting (if security module available)
        if security_manager and not security_manager.check_ip_rate_limit(ip_address, 10):
            security_manager.log_security_event('rate_limit_exceeded', None, ip_address, 'Login attempts')
            flash('Too many login attempts. Please wait a minute.', 'error')
            return render_template('login.html')
        
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        
        if user:
            # Check if account is locked
            if user[11]:  # account_locked field
                flash('Account temporarily locked due to suspicious activity. Contact admin.', 'error')
                return render_template('login.html')
            
            # Check failed attempts
            if user[9] >= 5:  # failed_login_attempts >= 5
                c.execute('UPDATE users SET account_locked = 1 WHERE id = ?', (user[0],))
                conn.commit()
                if security_manager:
                    security_manager.log_security_event('account_locked', user[0], ip_address, 'Too many failed attempts')
                flash('Account locked due to multiple failed attempts.', 'error')
                conn.close()
                return render_template('login.html')
            
            if check_password_hash(user[3], password):
                # Successful login - reset failed attempts
                c.execute('UPDATE users SET failed_login_attempts = 0, last_login_attempt = datetime("now") WHERE id = ?', (user[0],))
                conn.commit()
                
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['balance'] = user[4]
                
                if security_manager:
                    security_manager.log_security_event('successful_login', user[0], ip_address, 'User logged in')
                conn.close()
                return redirect(url_for('dashboard'))
            else:
                # Failed login - increment counter
                c.execute('UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_login_attempt = datetime("now") WHERE id = ?', (user[0],))
                conn.commit()
                if security_manager:
                    security_manager.log_security_event('failed_login', user[0], ip_address, 'Wrong password')
        else:
            if security_manager:
                security_manager.log_security_event('failed_login', None, ip_address, f'Unknown email: {email}')
        
        conn.close()
        flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

def refresh_user_balance():
    """Refresh user balance from database"""
    if 'user_id' in session:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
        result = c.fetchone()
        if result:
            session['balance'] = result[0]
        conn.close()

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Refresh balance from database
    refresh_user_balance()
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get user stats
    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    
    # Get recent matches
    c.execute('''SELECT m.*, u1.username as p1_name, u2.username as p2_name, w.username as winner_name
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 LEFT JOIN users w ON m.winner_id = w.id
                 WHERE m.player1_id = ? OR m.player2_id = ?
                 ORDER BY m.created_at DESC LIMIT 5''', (session['user_id'], session['user_id']))
    matches = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', user=user, matches=matches)

@app.route('/games')
def games():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Refresh balance from database
    refresh_user_balance()
    
    games_list = [
        {'id': 'pubg_mobile', 'name': 'PUBG Mobile', 'image': 'https://via.placeholder.com/300x200/FF6B35/FFFFFF?text=PUBG+Mobile', 'min_bet': 50, 'max_bet': 2000},
        {'id': 'cod_mobile', 'name': 'Call of Duty Mobile', 'image': 'https://via.placeholder.com/300x200/2E8B57/FFFFFF?text=COD+Mobile', 'min_bet': 50, 'max_bet': 2000},
        {'id': 'free_fire', 'name': 'Free Fire', 'image': 'https://via.placeholder.com/300x200/FF4500/FFFFFF?text=Free+Fire', 'min_bet': 30, 'max_bet': 1500},
        {'id': 'fifa_mobile', 'name': 'FIFA Mobile', 'image': 'https://via.placeholder.com/300x200/FFD700/000000?text=FIFA+Mobile', 'min_bet': 80, 'max_bet': 3000},
        {'id': 'efootball', 'name': 'eFootball', 'image': 'https://via.placeholder.com/300x200/32CD32/FFFFFF?text=eFootball', 'min_bet': 100, 'max_bet': 4000},
        {'id': 'clash_royale', 'name': 'Clash Royale', 'image': 'https://via.placeholder.com/300x200/4169E1/FFFFFF?text=Clash+Royale', 'min_bet': 40, 'max_bet': 1000},
        {'id': 'mobile_legends', 'name': 'Mobile Legends', 'image': 'https://via.placeholder.com/300x200/8A2BE2/FFFFFF?text=Mobile+Legends', 'min_bet': 60, 'max_bet': 2500},
        {'id': 'fortnite', 'name': 'Fortnite', 'image': 'https://via.placeholder.com/300x200/9932CC/FFFFFF?text=Fortnite', 'min_bet': 100, 'max_bet': 5000},
        {'id': 'valorant', 'name': 'Valorant', 'image': 'https://via.placeholder.com/300x200/DC143C/FFFFFF?text=Valorant', 'min_bet': 150, 'max_bet': 8000},
        {'id': 'apex_legends', 'name': 'Apex Legends', 'image': 'https://via.placeholder.com/300x200/FF1493/FFFFFF?text=Apex+Legends', 'min_bet': 120, 'max_bet': 6000},
        {'id': 'rocket_league', 'name': 'Rocket League', 'image': 'https://via.placeholder.com/300x200/00CED1/FFFFFF?text=Rocket+League', 'min_bet': 90, 'max_bet': 4000},
        {'id': 'among_us', 'name': 'Among Us', 'image': 'https://via.placeholder.com/300x200/FF69B4/FFFFFF?text=Among+Us', 'min_bet': 25, 'max_bet': 500}
    ]
    
    return render_template('games.html', games=games_list)

@app.route('/create_match', methods=['POST'])
def create_match():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    game = request.form['game']
    try:
        bet_amount = float(request.form['bet_amount'])
        if bet_amount <= 0 or bet_amount > 10000:  # Max bet limit
            flash('Invalid bet amount. Max bet: KSh 10,000', 'error')
            return redirect(url_for('games'))
    except (ValueError, TypeError):
        flash('Invalid bet amount format', 'error')
        return redirect(url_for('games'))
    
    game_mode = request.form['game_mode']
    
    # Professional validations
    if bet_amount <= 0:
        flash('Invalid bet amount!', 'error')
        return redirect(url_for('games'))
    
    if bet_amount > session['balance']:
        flash('Insufficient balance! Please add funds to your wallet.', 'error')
        return redirect(url_for('wallet'))
    
    if session['balance'] < 50:
        flash('Minimum balance of KSh 50 required to create matches.', 'error')
        return redirect(url_for('wallet'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Create match
    total_pot = bet_amount * 2
    platform_fee = total_pot * 0.08  # 8% platform fee (reduced for bank costs)
    
    c.execute('''INSERT INTO matches (game, player1_id, bet_amount, total_pot, game_mode)
                 VALUES (?, ?, ?, ?, ?)''', (game, session['user_id'], bet_amount, total_pot, game_mode))
    
    # Deduct bet from balance
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (bet_amount, session['user_id']))
    
    # Add transaction
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''', (session['user_id'], 'bet', -bet_amount, f'Bet placed for {game}'))
    
    conn.commit()
    conn.close()
    
    # Update session balance
    session['balance'] -= bet_amount
    
    flash('Match created! Waiting for opponent...', 'success')
    return redirect(url_for('matches'))

@app.route('/matches')
def matches():
    return "Test matches page"

@app.route('/cancel_match/<int:match_id>', methods=['POST'])
def cancel_match(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get match details
    c.execute('SELECT * FROM matches WHERE id = ?', (match_id,))
    match = c.fetchone()
    
    if not match:
        flash('Match not found!', 'error')
        return redirect(url_for('matches'))
    
    # Check if user can cancel (must be creator or participant)
    if match[2] != session['user_id'] and match[3] != session['user_id']:
        flash('You cannot cancel this match!', 'error')
        return redirect(url_for('matches'))
    
    # Check if match can be cancelled - strict rules apply
    if match[7] in ['completed', 'cancelled', 'disputed']:
        flash('Cannot cancel finished matches!', 'error')
        return redirect(url_for('matches'))
    
    bet_amount = match[4]
    
    # STRICT CANCELLATION RULES WITH PENALTIES
    user_id = session['user_id']
    penalty_msg = 'Match cancelled'
    
    if match[7] == 'pending' and match[3] is None:
        # FREE CANCELLATION: No opponent joined yet
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bet_amount, match[2]))
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''', (match[2], 'refund', bet_amount, f'Match #{match_id} cancelled - Free cancellation'))
        penalty_msg = 'Match cancelled (no penalty)'
        
    elif match[7] in ['pending', 'waiting_start'] and match[3] is not None:
        # PENALTY CANCELLATION: Opponent joined but game not started
        penalty = bet_amount * 0.20  # 20% penalty
        refund_p1 = bet_amount - penalty
        refund_p2 = bet_amount
        
        # Refund with penalty
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (refund_p1, match[2]))
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (refund_p2, match[3]))
        
        # Record transactions
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''', (match[2], 'refund', refund_p1, f'Match #{match_id} cancelled - 20% penalty applied'))
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''', (match[3], 'refund', refund_p2, f'Match #{match_id} cancelled by opponent'))
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''', (user_id, 'penalty', penalty, f'Cancellation penalty - Match #{match_id}'))
        
        penalty_msg = f'Match cancelled with 20% penalty (KSh {penalty:.0f})'
        
    elif match[7] == 'active':
        # HEAVY PENALTY: Game is active
        penalty = bet_amount * 0.50  # 50% penalty
        refund_canceller = bet_amount - penalty
        winner_payout = bet_amount * 1.8  # Other player gets 80% of total pot
        
        # Determine who is cancelling and who wins
        if user_id == match[2]:  # Player 1 cancelling
            c.execute('UPDATE users SET balance = balance + ?, losses = losses + 1 WHERE id = ?', (refund_canceller, match[2]))
            c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1, total_earnings = total_earnings + ? WHERE id = ?', 
                     (winner_payout, match[3], winner_payout))
            c.execute('UPDATE matches SET status = "completed", winner_id = ? WHERE id = ?', (match[3], match_id))
        else:  # Player 2 cancelling
            c.execute('UPDATE users SET balance = balance + ?, losses = losses + 1 WHERE id = ?', (refund_canceller, match[3]))
            c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1, total_earnings = total_earnings + ? WHERE id = ?', 
                     (winner_payout, match[2], winner_payout))
            c.execute('UPDATE matches SET status = "completed", winner_id = ? WHERE id = ?', (match[2], match_id))
        
        # Record transactions
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''', (user_id, 'forfeit', refund_canceller, f'Match #{match_id} forfeited - 50% penalty'))
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''', (user_id, 'penalty', penalty, f'Forfeit penalty - Match #{match_id}'))
        
        penalty_msg = f'Match forfeited with 50% penalty (KSh {penalty:.0f}). Opponent wins!'
        
    # Increase cancellation count for repeat offender tracking
    c.execute('UPDATE users SET suspicious_activity_score = suspicious_activity_score + 5 WHERE id = ?', (user_id,))
    
    # Update match status (only if not already completed)
    if match[7] != 'active':
        c.execute('UPDATE matches SET status = "cancelled" WHERE id = ?', (match_id,))
    
    # Clean up ready status
    c.execute('DELETE FROM match_ready WHERE match_id = ?', (match_id,))
    
    conn.commit()
    conn.close()
    
    # Refresh user balance
    refresh_user_balance()
    
    flash(penalty_msg, 'warning' if 'penalty' in penalty_msg else 'success')
    return redirect(url_for('matches'))

@app.route('/join_match/<int:match_id>')
def join_match(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get match details
    c.execute('SELECT * FROM matches WHERE id = ? AND status = "pending"', (match_id,))
    match = c.fetchone()
    
    if not match:
        flash('Match not available!', 'error')
        return redirect(url_for('matches'))
    
    bet_amount = match[3]
    
    if bet_amount > session['balance']:
        flash('Insufficient balance!', 'error')
        return redirect(url_for('matches'))
    
    # Check if game needs lobby
    lobby_games = ['pubg_mobile', 'cod_mobile', 'cod_warzone', 'valorant', 'apex_legends']
    
    if match[1] in lobby_games:
        # Games with lobby system
        c.execute('UPDATE matches SET player2_id = ?, status = "waiting_start" WHERE id = ?', (session['user_id'], match_id))
        flash('Match joined! Enter lobby to start the game.', 'success')
        return redirect(url_for('match_lobby', match_id=match_id))
    else:
        # Simple games go directly active
        c.execute('UPDATE matches SET player2_id = ?, status = "active" WHERE id = ?', (session['user_id'], match_id))
    
    # Deduct bet from balance
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (bet_amount, session['user_id']))
    
    # Add transaction
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''', (session['user_id'], 'bet', -bet_amount, f'Joined match #{match_id}'))
    
    conn.commit()
    conn.close()
    
    # Update session balance
    session['balance'] -= bet_amount
    
    flash('Match joined! Game is now active. Submit your result when done.', 'success')
    return redirect(url_for('matches'))

@app.route('/submit_result', methods=['POST'])
def submit_result():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Login required'})
    
    user_id = session['user_id']
    ip_address = request.environ.get('REMOTE_ADDR', 'unknown')
    
    # Rate limiting - max 3 result submissions per minute (if security module available)
    if security_manager and not security_manager.check_rate_limit(user_id, 'submit_result', 3):
        security_manager.log_security_event('rate_limit_exceeded', user_id, ip_address, 'Result submission spam')
        return jsonify({'success': False, 'message': 'Too many submissions. Please wait.'})
    
    # Check for suspicious activity (if security module available)
    if security_manager and security_manager.check_suspicious_activity(user_id):
        security_manager.log_security_event('suspicious_activity', user_id, ip_address, 'High activity detected')
        return jsonify({'success': False, 'message': 'Account flagged for review. Contact admin.'})
    
    match_id = int(request.form['match_id'])
    result_type = request.form['result_type']
    proof_text = request.form.get('proof', '')
    screenshot = request.form.get('screenshot', '')
    
    # Validate screenshot
    if not screenshot:
        return jsonify({'success': False, 'message': 'Screenshot is required'})
    
    # Screenshot validation (if security module available)
    screenshot_hash = None
    if security_manager:
        is_valid, validation_result = security_manager.validate_screenshot_integrity(screenshot)
        if not is_valid:
            security_manager.log_security_event('invalid_screenshot', user_id, ip_address, validation_result)
            return jsonify({'success': False, 'message': f'Screenshot validation failed: {validation_result}'})
        screenshot_hash = validation_result
    
    # Check for spam in proof text (if security module available)
    if security_manager and security_manager.detect_spam_patterns(user_id, proof_text):
        security_manager.log_security_event('spam_detected', user_id, ip_address, f'Spam in proof text: {proof_text[:100]}')
        return jsonify({'success': False, 'message': 'Spam detected in submission. Please use appropriate language.'})
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get match and validate
    c.execute('SELECT * FROM matches WHERE id = ? AND status = "active"', (match_id,))
    match = c.fetchone()
    
    if not match or (match[2] != user_id and match[3] != user_id):
        return jsonify({'success': False, 'message': 'Invalid match'})
    
    # Check if result already submitted
    c.execute('SELECT * FROM match_results WHERE match_id = ? AND user_id = ?', (match_id, user_id))
    existing = c.fetchone()
    
    if existing:
        return jsonify({'success': False, 'message': 'Result already submitted'})
    
    # AI Analysis (if result detector available)
    ai_verification = None
    confidence = 0
    
    if result_detector:
        game_type = match[1]
        analysis = result_detector.analyze_screenshot(screenshot, game_type)
        ai_verification = analysis['result']
        confidence = analysis['confidence']
    
    # Fraud detection (if AI and security modules available)
    if ai_verification and ai_verification != 'unknown' and ai_verification != result_type:
        if security_manager:
            security_manager.log_security_event('fraud_attempt', user_id, ip_address, 
                                              f'Claimed {result_type} but AI detected {ai_verification}')
        
        # Increase suspicious activity score
        c.execute('UPDATE users SET suspicious_activity_score = suspicious_activity_score + 10 WHERE id = ?', (user_id,))
        
        return jsonify({
            'success': False, 
            'message': f'FRAUD DETECTED: Screenshot shows {ai_verification} but you claimed {result_type}. Account flagged.'
        })
    
    # Store result with security data
    c.execute('''INSERT INTO match_results (match_id, user_id, result_claimed, proof_text, 
                                          screenshot_data, ai_verification, confidence, screenshot_hash, submitted_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))''', 
                (match_id, user_id, result_type, proof_text, screenshot, ai_verification, confidence, screenshot_hash))
    
    # Check if both players submitted
    c.execute('SELECT * FROM match_results WHERE match_id = ?', (match_id,))
    results = c.fetchall()
    
    if len(results) == 2:
        process_match_results(match_id, results, match)
    
    conn.commit()
    conn.close()
    
    if security_manager:
        security_manager.log_security_event('result_submitted', user_id, ip_address, f'Match {match_id}: {result_type}')
    
    verification_msg = f" (AI Confidence: {confidence*100:.0f}%)" if ai_verification else ""
    return jsonify({'success': True, 'message': f'Result verified and submitted!{verification_msg}'})

def process_match_results(match_id, results, match):
    """Smart result processing with anti-fraud logic"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    player1_result = next((r for r in results if r[1] == match[2]), None)
    player2_result = next((r for r in results if r[1] == match[3]), None)
    
    # Anti-fraud logic
    if player1_result[2] == 'win' and player2_result[2] == 'win':
        # Both claim win - FRAUD DETECTED
        winner_id = determine_fraud_winner(match[2], match[3])
        c.execute('UPDATE matches SET status = "disputed", winner_id = ? WHERE id = ?', (winner_id, match_id))
        
    elif player1_result[2] == 'loss' and player2_result[2] == 'loss':
        # Both claim loss - SUSPICIOUS
        winner_id = determine_random_winner(match[2], match[3])
        c.execute('UPDATE matches SET status = "completed", winner_id = ? WHERE id = ?', (winner_id, match_id))
        
    else:
        # Normal case - one win, one loss
        winner_id = match[2] if player1_result[2] == 'win' else match[3]
        c.execute('UPDATE matches SET status = "completed", winner_id = ? WHERE id = ?', (winner_id, match_id))
    
    # Calculate smart payout
    total_pot = match[4]
    raw_payout = total_pot * 0.92
    winner_payout = (raw_payout // 10) * 10  # Round down
    
    # Pay winner
    c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1, total_earnings = total_earnings + ? WHERE id = ?',
              (winner_payout, winner_payout, winner_id))
    
    # Update loser
    loser_id = match[2] if winner_id == match[3] else match[3]
    c.execute('UPDATE users SET losses = losses + 1 WHERE id = ?', (loser_id,))
    
    # Record transaction
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''', (winner_id, 'win', winner_payout, f'Won match #{match_id}'))
    
    conn.commit()
    conn.close()

def determine_fraud_winner(player1_id, player2_id):
    """When both claim win, pick based on account history"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Check win rates - lower win rate gets benefit of doubt
    c.execute('SELECT wins, losses FROM users WHERE id = ?', (player1_id,))
    p1_stats = c.fetchone()
    c.execute('SELECT wins, losses FROM users WHERE id = ?', (player2_id,))
    p2_stats = c.fetchone()
    
    p1_winrate = p1_stats[0] / max(1, p1_stats[0] + p1_stats[1])
    p2_winrate = p2_stats[0] / max(1, p2_stats[0] + p2_stats[1])
    
    conn.close()
    
    # Lower win rate wins (anti-farming)
    return player1_id if p1_winrate <= p2_winrate else player2_id

def determine_random_winner(player1_id, player2_id):
    """Random winner when both claim loss"""
    import random
    return random.choice([player1_id, player2_id])

@app.route('/wallet')
def wallet():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Refresh balance from database
    refresh_user_balance()
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get transactions
    c.execute('''SELECT * FROM transactions WHERE user_id = ? 
                 ORDER BY created_at DESC LIMIT 20''', (session['user_id'],))
    transactions = c.fetchall()
    
    conn.close()
    
    return render_template('wallet.html', transactions=transactions)

@app.route('/add_funds', methods=['POST'])
def add_funds():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        amount = float(request.form['amount'])
        if amount <= 0 or amount > 50000:
            flash('Invalid amount. Max deposit: KSh 50,000', 'error')
            return redirect(url_for('wallet'))
    except (ValueError, TypeError):
        flash('Invalid amount format', 'error')
        return redirect(url_for('wallet'))
    
    if amount < 100:
        flash('Minimum deposit is KSh 100', 'error')
        return redirect(url_for('wallet'))
    
    # Get additional deposit info
    mpesa_number = request.form.get('mpesa_number', '').strip()
    sender_name = request.form.get('sender_name', '').strip()
    
    if not mpesa_number or not sender_name:
        flash('M-Pesa number and sender name are required', 'error')
        return redirect(url_for('wallet'))
    
    # Validate M-Pesa number format
    if not re.match(r'^07\d{8}$|^01\d{8}$|^\+2547\d{8}$|^2547\d{8}$', mpesa_number):
        flash('Invalid M-Pesa number format', 'error')
        return redirect(url_for('wallet'))
    
    # Handle receipt screenshot
    receipt_screenshot = None
    if 'receipt_screenshot' in request.files:
        file = request.files['receipt_screenshot']
        if file and file.filename:
            # Convert to base64 for storage
            import base64
            receipt_data = file.read()
            receipt_screenshot = base64.b64encode(receipt_data).decode('utf-8')
    
    if not receipt_screenshot:
        flash('M-Pesa receipt screenshot is required', 'error')
        return redirect(url_for('wallet'))
    
    # Smart pricing: Round down to nearest 50, difference = hidden fee
    net_deposit = (amount // 50) * 50
    processing_fee = amount - net_deposit
    
    # Minimum hidden fee of 2%
    if processing_fee < amount * 0.02:
        processing_fee = amount * 0.02
        net_deposit = amount - processing_fee
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Create pending deposit transaction with verification details
    description = f'M-Pesa deposit KSh {amount} from {sender_name} ({mpesa_number}) - Awaiting verification'
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''', (session['user_id'], 'pending_deposit', net_deposit, description))
    
    transaction_id = c.lastrowid
    
    # Store deposit verification details
    c.execute('''INSERT INTO deposit_verifications (transaction_id, user_id, mpesa_number, sender_name, 
                                                   receipt_screenshot, amount_sent, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, datetime('now'))''', 
                (transaction_id, session['user_id'], mpesa_number, sender_name, receipt_screenshot, amount))
    
    # Record processing fee as revenue
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''', (session['user_id'], 'processing_fee', processing_fee, 'Deposit processing fee (2%)'))
    
    conn.commit()
    conn.close()
    
    flash(f'Deposit request submitted! Admin will verify your M-Pesa payment and add KSh {net_deposit:.0f} to your account.', 'success')
    return redirect(url_for('wallet'))

@app.route('/withdraw', methods=['POST'])
def withdraw():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        amount = float(request.form['amount'])
        if amount <= 0:
            flash('Invalid withdrawal amount', 'error')
            return redirect(url_for('wallet'))
    except (ValueError, TypeError):
        flash('Invalid amount format', 'error')
        return redirect(url_for('wallet'))
    
    if amount < 200:
        flash('Minimum withdrawal is KSh 200', 'error')
        return redirect(url_for('wallet'))
    
    # Get M-Pesa details
    mpesa_number = request.form.get('mpesa_number', '').strip()
    account_name = request.form.get('account_name', '').strip()
    
    if not mpesa_number or not account_name:
        flash('M-Pesa number and account name are required', 'error')
        return redirect(url_for('wallet'))
    
    # Validate M-Pesa number format
    if not re.match(r'^07\d{8}$|^01\d{8}$|^\+2547\d{8}$|^2547\d{8}$', mpesa_number):
        flash('Invalid M-Pesa number format', 'error')
        return redirect(url_for('wallet'))
    
    # Dynamic withdrawal fee based on amount (3-5%)
    if amount <= 500:
        withdrawal_fee = amount * 0.05  # 5% for small amounts
    elif amount <= 2000:
        withdrawal_fee = amount * 0.04  # 4% for medium amounts  
    else:
        withdrawal_fee = amount * 0.03  # 3% for large amounts
    
    # Minimum fee KSh 20
    withdrawal_fee = max(20, withdrawal_fee)
    total_deduction = amount + withdrawal_fee
    
    if total_deduction > session['balance']:
        flash(f'Insufficient balance! Need KSh {total_deduction:.0f} (KSh {amount} + KSh {withdrawal_fee:.0f} fee)', 'error')
        return redirect(url_for('wallet'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Deduct total amount including fee
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (total_deduction, session['user_id']))
    
    # Create withdrawal request with M-Pesa details
    description = f'Withdrawal KSh {amount} to {mpesa_number} ({account_name}) - Fee: KSh {withdrawal_fee:.0f}'
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''', (session['user_id'], 'pending_withdrawal', -amount, description))
    
    # Record withdrawal fee as revenue
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''', (session['user_id'], 'withdrawal_fee', withdrawal_fee, 'Withdrawal processing fee'))
    
    conn.commit()
    conn.close()
    
    session['balance'] -= total_deduction
    
    flash(f'Withdrawal request submitted! KSh {amount:.0f} will be sent to {mpesa_number} within 24 hours. Fee: KSh {withdrawal_fee:.0f}', 'success')
    return redirect(url_for('wallet'))

# Admin routes
@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('username') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get stats
    c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
    total_users = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM matches WHERE status = "active"')
    active_matches = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "deposit"')
    total_deposits = c.fetchone()[0]
    
    # Get financial calculations
    earnings_data = calculate_fees_and_commissions()
    
    # Pending transactions only
    c.execute('''SELECT t.*, u.username, u.email FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 WHERE t.type = "pending_deposit"
                 ORDER BY t.created_at DESC''')
    pending_deposits = c.fetchall()
    
    c.execute('''SELECT t.*, u.username, u.email FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 WHERE t.type = "pending_withdrawal"
                 ORDER BY t.created_at DESC''')
    pending_withdrawals = c.fetchall()
    
    conn.close()
    
    # Get notifications
    notifications = get_admin_notifications()
    
    stats = {
        'total_users': total_users,
        'active_matches': active_matches,
        'total_deposits': total_deposits,
        'net_earnings': earnings_data['net_earnings'],
        'gross_earnings': earnings_data['gross_earnings'],
        'bank_fees': earnings_data['bank_fees']
    }
    
    return render_template('admin_dashboard.html', stats=stats, 
                         pending_withdrawals=pending_withdrawals, pending_deposits=pending_deposits,
                         notifications=notifications, earnings_data=earnings_data)

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('SELECT * FROM users WHERE username != "admin" ORDER BY created_at DESC')
    users = c.fetchall()
    
    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/transactions')
def admin_transactions():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('''SELECT t.*, u.username FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 ORDER BY t.created_at DESC LIMIT 50''')
    transactions = c.fetchall()
    
    conn.close()
    return render_template('admin_transactions.html', transactions=transactions)

@app.route('/admin/matches')
def admin_matches():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('''SELECT m.*, u1.username as p1_name, u2.username as p2_name, w.username as winner_name
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 LEFT JOIN users w ON m.winner_id = w.id
                 ORDER BY m.created_at DESC LIMIT 50''')
    matches = c.fetchall()
    
    conn.close()
    return render_template('admin_matches.html', matches=matches)

@app.route('/admin/disputes')
def admin_disputes():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get disputed matches with results
    c.execute('''SELECT m.*, u1.username as p1_name, u2.username as p2_name,
                        r1.result_claimed as p1_claim, r1.proof_text as p1_proof,
                        r2.result_claimed as p2_claim, r2.proof_text as p2_proof
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 LEFT JOIN match_results r1 ON m.id = r1.match_id AND r1.user_id = m.player1_id
                 LEFT JOIN match_results r2 ON m.id = r2.match_id AND r2.user_id = m.player2_id
                 WHERE m.status = "disputed"
                 ORDER BY m.created_at DESC''')
    disputes = c.fetchall()
    
    conn.close()
    return render_template('admin_disputes.html', disputes=disputes)

@app.route('/match_lobby/<int:match_id>')
def match_lobby(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get match details
    c.execute('''SELECT m.*, u1.username as player1_name, u2.username as player2_name
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.id = ? AND (m.player1_id = ? OR m.player2_id = ?)''', 
                (match_id, session['user_id'], session['user_id']))
    match = c.fetchone()
    
    if not match:
        flash('Match not found', 'error')
        return redirect(url_for('matches'))
    
    # Check ready status
    c.execute('SELECT * FROM match_ready WHERE match_id = ? AND user_id = ?', (match_id, session['user_id']))
    user_ready = c.fetchone() is not None
    
    c.execute('SELECT COUNT(*) FROM match_ready WHERE match_id = ?', (match_id,))
    ready_count = c.fetchone()[0]
    
    conn.close()
    
    match_dict = {
        'id': match[0],
        'game': match[1],
        'total_pot': match[5],
        'game_mode': match[8],
        'player1_name': match[10],
        'player2_name': match[11],
        'status': match[7],
        'user_ready': user_ready,
        'ready_count': ready_count
    }
    
    return render_template('match_lobby.html', match=match_dict)

@app.route('/ready_match/<int:match_id>', methods=['POST'])
def ready_match(match_id):
    if 'user_id' not in session:
        return jsonify({'success': False})
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Mark user as ready
    c.execute('INSERT OR IGNORE INTO match_ready (match_id, user_id) VALUES (?, ?)', (match_id, session['user_id']))
    
    # Check if both ready
    c.execute('SELECT COUNT(*) FROM match_ready WHERE match_id = ?', (match_id,))
    ready_count = c.fetchone()[0]
    
    if ready_count == 2:
        c.execute('UPDATE matches SET status = "active" WHERE id = ?', (match_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'ready_count': ready_count})

@app.route('/match_result/<int:match_id>')
def match_result(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get match details
    c.execute('''SELECT m.*, u1.username as player1_name, u2.username as player2_name
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.id = ? AND m.status = "active"
                 AND (m.player1_id = ? OR m.player2_id = ?)''', 
                (match_id, session['user_id'], session['user_id']))
    match = c.fetchone()
    
    if not match:
        flash('Match not found or not active', 'error')
        return redirect(url_for('matches'))
    
    # Check if already submitted
    c.execute('SELECT * FROM match_results WHERE match_id = ? AND user_id = ?', (match_id, session['user_id']))
    existing = c.fetchone()
    
    if existing:
        flash('You have already submitted result for this match', 'error')
        return redirect(url_for('matches'))
    
    conn.close()
    
    # Convert to dict for template
    match_dict = {
        'id': match[0],
        'game': match[1],
        'total_pot': match[5],
        'game_mode': match[8],
        'player1_name': match[10],
        'player2_name': match[11]
    }
    
    return render_template('match_result.html', match=match_dict)

@app.route('/analyze_screenshot', methods=['POST'])
def analyze_screenshot():
    """Real-time screenshot analysis endpoint"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Login required'})
    
    data = request.get_json()
    screenshot = data.get('screenshot')
    game_type = data.get('game_type')
    
    if not screenshot:
        return jsonify({'success': False, 'message': 'No screenshot provided'})
    
    try:
        # Analyze with AI (if available)
        if result_detector:
            analysis = result_detector.analyze_screenshot(screenshot, game_type)
            return jsonify({
                'success': True,
                'result': analysis['result'],
                'confidence': analysis['confidence'],
                'methods': analysis['methods_used']
            })
        else:
            return jsonify({
                'success': True,
                'result': 'unknown',
                'confidence': 0,
                'methods': ['AI module not available']
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Analysis failed: {str(e)}'
        })

@app.route('/admin/view_deposit/<int:transaction_id>')
def view_deposit_details(transaction_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get deposit verification details
    c.execute('''SELECT dv.*, t.amount, u.username, u.email 
                 FROM deposit_verifications dv
                 JOIN transactions t ON dv.transaction_id = t.id
                 JOIN users u ON dv.user_id = u.id
                 WHERE dv.transaction_id = ?''', (transaction_id,))
    deposit_details = c.fetchone()
    
    conn.close()
    
    if deposit_details:
        return jsonify({
            'success': True,
            'details': {
                'username': deposit_details[8],
                'email': deposit_details[9],
                'mpesa_number': deposit_details[3],
                'sender_name': deposit_details[4],
                'amount_sent': deposit_details[6],
                'amount_to_credit': deposit_details[7],
                'receipt_screenshot': deposit_details[5],
                'created_at': deposit_details[10]
            }
        })
    
    return jsonify({'success': False, 'message': 'Deposit not found'})

@app.route('/admin/approve_deposit/<int:transaction_id>', methods=['POST'])
def approve_deposit(transaction_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('SELECT * FROM transactions WHERE id = ? AND type = "pending_deposit"', (transaction_id,))
    transaction = c.fetchone()
    
    if transaction:
        user_id = transaction[1]
        amount = transaction[3]
        
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
        c.execute('UPDATE transactions SET type = "deposit", description = "M-Pesa deposit confirmed by admin" WHERE id = ?', (transaction_id,))
        c.execute('UPDATE deposit_verifications SET verified = 1, verified_by = ? WHERE transaction_id = ?', (session['user_id'], transaction_id))
        
        conn.commit()
        flash('Deposit approved successfully!', 'success')
    
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_deposit/<int:transaction_id>', methods=['POST'])
def reject_deposit(transaction_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('UPDATE transactions SET type = "rejected_deposit", description = "Deposit rejected - Payment not received" WHERE id = ? AND type = "pending_deposit"', (transaction_id,))
    
    conn.commit()
    conn.close()
    
    flash('Deposit rejected!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/approve_withdrawal/<int:transaction_id>', methods=['POST'])
def approve_withdrawal(transaction_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('UPDATE transactions SET type = "withdrawal", description = "Withdrawal processed by admin" WHERE id = ? AND type = "pending_withdrawal"', (transaction_id,))
    
    conn.commit()
    conn.close()
    
    flash('Withdrawal approved and processed!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_withdrawal/<int:transaction_id>', methods=['POST'])
def reject_withdrawal(transaction_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get transaction to refund user
    c.execute('SELECT * FROM transactions WHERE id = ? AND type = "pending_withdrawal"', (transaction_id,))
    transaction = c.fetchone()
    
    if transaction:
        user_id = transaction[1]
        amount = abs(transaction[3])  # Make positive for refund
        
        # Refund user balance
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
        c.execute('UPDATE transactions SET type = "rejected_withdrawal", description = "Withdrawal rejected - Funds refunded" WHERE id = ?', (transaction_id,))
        
        conn.commit()
        flash('Withdrawal rejected and funds refunded!', 'success')
    
    conn.close()
    return redirect(url_for('admin_dashboard'))

# Commission and fee calculations
def calculate_fees_and_commissions():
    """Calculate platform earnings considering Kenyan bank fees"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Platform commission: 8% (reduced from 10% to account for bank fees)
    # Cooperative Bank M-Pesa fees: ~KSh 11-33 per transaction
    
    # Total match pots completed
    c.execute('SELECT COALESCE(SUM(total_pot), 0) FROM matches WHERE status = "completed"')
    total_completed_pots = c.fetchone()[0]
    
    # Platform commission (8%)
    match_earnings = total_completed_pots * 0.08
    
    # Processing fees (2% of deposits)
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "processing_fee"')
    processing_fees = c.fetchone()[0]
    
    # Withdrawal fees (KSh 15 each)
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "withdrawal_fee"')
    withdrawal_fees = c.fetchone()[0]
    
    gross_earnings = match_earnings + processing_fees + withdrawal_fees
    
    # Estimate bank fees (average KSh 22 per withdrawal)
    c.execute('SELECT COUNT(*) FROM transactions WHERE type = "withdrawal"')
    withdrawal_count = c.fetchone()[0]
    
    estimated_bank_fees = withdrawal_count * 22
    net_earnings = max(0, gross_earnings - estimated_bank_fees)
    
    conn.close()
    
    return {
        'gross_earnings': gross_earnings,
        'bank_fees': estimated_bank_fees,
        'net_earnings': net_earnings,
        'commission_rate': 8  # 8% instead of 10%
    }

def get_admin_notifications():
    """Get important notifications for admin"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    notifications = []
    
    # Check pending deposits
    c.execute('SELECT COUNT(*) FROM transactions WHERE type = "pending_deposit"')
    pending_deposits = c.fetchone()[0]
    if pending_deposits > 0:
        notifications.append(f'{pending_deposits} pending deposits need approval')
    
    # Check pending withdrawals
    c.execute('SELECT COUNT(*) FROM transactions WHERE type = "pending_withdrawal"')
    pending_withdrawals = c.fetchone()[0]
    if pending_withdrawals > 0:
        notifications.append(f'{pending_withdrawals} withdrawals awaiting M-Pesa payment')
    
    # Check low balance users trying to play
    c.execute('SELECT COUNT(*) FROM users WHERE balance < 50 AND balance > 0')
    low_balance_users = c.fetchone()[0]
    if low_balance_users > 0:
        notifications.append(f'{low_balance_users} users have insufficient balance to play')
    
    # Check active matches without opponents
    c.execute('SELECT COUNT(*) FROM matches WHERE status = "pending" AND player2_id IS NULL')
    waiting_matches = c.fetchone()[0]
    if waiting_matches > 0:
        notifications.append(f'{waiting_matches} matches waiting for opponents')
    
    conn.close()
    return notifications

@app.route('/admin/clear_all_data', methods=['POST'])
def clear_all_data():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Clear all data but keep admin user
    c.execute('DELETE FROM transactions WHERE user_id != (SELECT id FROM users WHERE username = "admin")')
    c.execute('DELETE FROM matches')
    c.execute('UPDATE users SET balance = 0, wins = 0, losses = 0, total_earnings = 0 WHERE username != "admin"')
    
    conn.commit()
    conn.close()
    
    flash('All platform data cleared!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/promotions')
def promotions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('promotions.html')

@app.route('/buy_boost', methods=['POST'])
def buy_boost():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Login required'})
    
    data = request.get_json()
    boost_type = data.get('type')
    price = float(data.get('price', 0))
    
    if price > session['balance']:
        return jsonify({'success': False, 'message': 'Insufficient balance'})
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Deduct from balance
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (price, session['user_id']))
    
    # Record boost purchase (pure profit)
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''', (session['user_id'], 'boost_purchase', -price, f'Purchased {boost_type} boost'))
    
    conn.commit()
    conn.close()
    
    session['balance'] -= price
    
    return jsonify({'success': True, 'message': 'Boost activated!'})

@app.route('/api/match_status/<int:match_id>')
def match_status(match_id):
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('SELECT status FROM matches WHERE id = ?', (match_id,))
    result = c.fetchone()
    conn.close()
    
    if result:
        return jsonify({'status': result[0]})
    return jsonify({'status': 'not_found'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    # init_db()  # Disabled for testing
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)