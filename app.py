from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
import random

def analyze_screenshot(screenshot_data, claimed_result):
    """AI analysis of screenshot to verify if it's a valid game screenshot"""
    # Simple validation - check file size and basic properties
    if len(screenshot_data) < 10000:  # Too small to be a real screenshot
        return {'validity': 'NOT_GAME_SCREENSHOT', 'reason': 'File too small'}
    
    # For now, mark most screenshots as invalid to prevent fake submissions
    # In production, this would use actual AI image recognition
    analysis = {
        'is_game_screenshot': False,  # Strict validation
        'matches_claimed_result': False,
        'confidence': 0.3,
        'detected_game': 'Unknown',
        'detected_result': 'unclear',
        'validity': 'NOT_GAME_SCREENSHOT',
        'reason': 'Screenshot validation failed - not a recognized game screenshot'
    }
    
    return analysis

app = Flask(__name__)
app.secret_key = 'gamebet_secret_key_2024'

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/create_match', methods=['POST'])
def create_match():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    game = request.form['game']
    bet_amount = float(request.form['bet_amount'])
    game_mode = request.form.get('game_mode', 'Standard')
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Check if user has enough balance
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()[0]
    
    if balance < bet_amount:
        flash('Insufficient balance!', 'error')
        conn.close()
        return redirect(url_for('games'))
    
    # Deduct bet amount from creator
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (bet_amount, session['user_id']))
    session['balance'] = balance - bet_amount
    
    # Create match
    total_pot = bet_amount * 2
    c.execute('''INSERT INTO matches (game, player1_id, bet_amount, total_pot, game_mode, status)
                 VALUES (?, ?, ?, ?, ?, ?)''', (game, session['user_id'], bet_amount, total_pot, game_mode, 'pending'))
    
    conn.commit()
    conn.close()
    
    flash(f'Match created! KSh {bet_amount} deducted from your balance.', 'success')
    return redirect(url_for('matches'))

@app.route('/games')
def games():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Update session balance
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()
    if balance:
        session['balance'] = balance[0]
    conn.close()
    
    games_list = [
        {'id': 'pubg_mobile', 'name': 'PUBG Mobile', 'image': 'https://images.unsplash.com/photo-1542751371-adc38448a05e?w=300&h=200&fit=crop', 'min_bet': 50, 'max_bet': 2000, 'modes': ['Solo', 'Duo', 'Squad']},
        {'id': 'cod_mobile', 'name': 'Call of Duty Mobile', 'image': 'https://images.unsplash.com/photo-1511512578047-dfb367046420?w=300&h=200&fit=crop', 'min_bet': 50, 'max_bet': 2000, 'modes': ['Team Deathmatch', 'Battle Royale', 'Domination']},
        {'id': 'fifa_mobile', 'name': 'FIFA Mobile', 'image': 'https://images.unsplash.com/photo-1574629810360-7efbbe195018?w=300&h=200&fit=crop', 'min_bet': 80, 'max_bet': 3000, 'modes': ['Head to Head', 'VSA', 'Manager Mode']},
        {'id': 'efootball', 'name': 'eFootball', 'image': 'https://images.unsplash.com/photo-1431324155629-1a6deb1dec8d?w=300&h=200&fit=crop', 'min_bet': 100, 'max_bet': 4000, 'modes': ['Online Match', 'Dream Team', 'Master League']},
        {'id': 'pes', 'name': 'PES Mobile', 'image': 'https://images.unsplash.com/photo-1553778263-73a83bab9b0c?w=300&h=200&fit=crop', 'min_bet': 90, 'max_bet': 3500, 'modes': ['myClub', 'Local Match', 'Online Co-op']}
    ]
    
    return render_template('games.html', games=games_list)

@app.route('/matches')
def matches():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Update session balance
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()
    if balance:
        session['balance'] = balance[0]
    
    # Available matches (not mine)
    c.execute('''SELECT m.id, m.game, m.player1_id, COALESCE(m.bet_amount, 0) as bet_amount, 
                        COALESCE(m.total_pot, 0) as total_pot, m.status, m.game_mode, u.username, u.phone
                 FROM matches m
                 JOIN users u ON m.player1_id = u.id
                 WHERE m.status = 'pending' AND m.player1_id != ?''', (session['user_id'],))
    available_matches = c.fetchall()
    
    # My matches
    c.execute('''SELECT m.id, m.game, m.player1_id, m.player2_id, 
                        COALESCE(m.bet_amount, 0) as bet_amount, COALESCE(m.total_pot, 0) as total_pot,
                        m.winner_id, m.status, m.game_mode, m.created_at,
                        u1.username as p1_name, u2.username as p2_name, u1.phone as p1_phone, u2.phone as p2_phone
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.player1_id = ? OR m.player2_id = ?
                 ORDER BY m.id DESC''', (session['user_id'], session['user_id']))
    my_matches = c.fetchall()
    
    conn.close()
    
    return render_template('matches.html', available_matches=available_matches, my_matches=my_matches)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        mpesa_number = request.form['mpesa_number'].strip()
        password = request.form['password']
        referral_code = request.form.get('referral_code', '').strip()
        
        # Use M-Pesa number as both email and phone
        email = mpesa_number + '@gamebet.local'  # Create unique email from M-Pesa
        phone = mpesa_number
        
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Check if M-Pesa number already exists
        c.execute('SELECT username FROM users WHERE phone = ?', (phone,))
        existing_phone = c.fetchone()
        if existing_phone:
            flash(f'M-Pesa number {mpesa_number} is already registered to user: {existing_phone[0]}', 'error')
            conn.close()
            return render_template('register.html')
        
        try:
            hashed_password = generate_password_hash(password)
            
            # Generate unique referral code
            import random, string
            user_referral_code = username[:3].upper() + ''.join(random.choices(string.digits, k=4))
            
            # Check if referred by someone
            referred_by_id = None
            if referral_code:
                c.execute('SELECT id FROM users WHERE referral_code = ?', (referral_code,))
                referrer = c.fetchone()
                if referrer:
                    referred_by_id = referrer[0]
            
            c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code, referred_by) 
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (username, email, hashed_password, 0.0, phone, user_referral_code, referred_by_id))
            
            # Give referral bonus (but admin keeps more)
            if referred_by_id:
                # Referrer gets KSh 30 (reduced from 50)
                c.execute('UPDATE users SET balance = balance + 30 WHERE id = ?', (referred_by_id,))
                c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                             VALUES (?, ?, ?, ?)''', 
                         (referred_by_id, 'referral_bonus', 30, f'Referral bonus for inviting {username}'))
                
                # Admin keeps KSh 20 profit per referral
                c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                             VALUES (?, ?, ?, ?)''', 
                         (1, 'admin_referral_profit', 20, f'Admin profit from {username} referral'))
            
            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken! Please choose a different username.', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login_input'].strip()
        password = request.form['password']
        
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Allow login with username or M-Pesa number
        c.execute('SELECT * FROM users WHERE username = ? OR phone = ?', (login_input, login_input))
        user = c.fetchone()
        
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['balance'] = user[4]
            conn.close()
            return redirect(url_for('dashboard'))
        
        conn.close()
        flash('Invalid username/M-Pesa number or password!', 'error')
    
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        mpesa_number = request.form['mpesa_number'].strip()
        new_password = request.form['new_password']
        
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        # Check if M-Pesa number exists
        c.execute('SELECT id, username FROM users WHERE phone = ?', (mpesa_number,))
        user = c.fetchone()
        
        if user:
            # Update password
            hashed_password = generate_password_hash(new_password)
            c.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user[0]))
            conn.commit()
            flash(f'Password updated successfully for {user[1]}!', 'success')
            conn.close()
            return redirect(url_for('login'))
        else:
            flash('M-Pesa number not found!', 'error')
            conn.close()
    
    return render_template('forgot_password.html')

@app.route('/check_user/<mpesa_number>')
def check_user(mpesa_number):
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('SELECT username, phone FROM users WHERE phone = ? OR username = ?', (mpesa_number, mpesa_number))
    user = c.fetchone()
    conn.close()
    
    if user:
        return f'Found: {user[0]} - Phone: {user[1] or "No phone number set"}'  
    else:
        return f'No user found with M-Pesa number: {mpesa_number}'

@app.route('/add_funds', methods=['POST'])
def add_funds():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    amount = float(request.form['amount'])
    mpesa_number = request.form.get('mpesa_number', '')
    sender_name = request.form.get('sender_name', '')
    
    # Handle receipt screenshot
    receipt_screenshot = None
    if 'receipt_screenshot' in request.files:
        file = request.files['receipt_screenshot']
        if file and file.filename:
            import base64
            receipt_data = file.read()
            receipt_screenshot = base64.b64encode(receipt_data).decode('utf-8')
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Calculate amount to credit (with processing fee)
    processing_fee = amount * 0.03  # 3% fee
    amount_to_credit = amount - processing_fee
    
    # Log admin profit from deposit fee
    c.execute('''CREATE TABLE IF NOT EXISTS admin_profits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT,
        amount REAL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''INSERT INTO admin_profits (source, amount, description, created_at) 
                 VALUES (?, ?, ?, datetime('now'))''',
             ('deposit_fee', processing_fee, f'Deposit fee from {sender_name}'))
    
    # Create pending deposit transaction with screenshot
    description = f'M-Pesa deposit KSh {amount} from {sender_name} ({mpesa_number}) - To credit: KSh {amount_to_credit:.0f}'
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''', (session['user_id'], 'pending_deposit', amount_to_credit, description))
    
    transaction_id = c.lastrowid
    
    # Store deposit verification details
    c.execute('''INSERT INTO deposit_verifications (transaction_id, user_id, mpesa_number, sender_name, 
                                                   receipt_screenshot, amount_sent, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, datetime('now'))''', 
                (transaction_id, session['user_id'], mpesa_number, sender_name, receipt_screenshot or '', amount))
    
    conn.commit()
    conn.close()
    
    flash('Deposit request submitted!', 'success')
    return redirect(url_for('wallet'))

@app.route('/withdraw', methods=['POST'])
def withdraw():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    amount = float(request.form['amount'])
    mpesa_number = request.form['mpesa_number']
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Check if user has enough balance
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()[0]
    
    if balance < amount:
        flash('Insufficient balance!', 'error')
        conn.close()
        return redirect(url_for('wallet'))
    
    # Deduct amount + withdrawal fee from balance
    withdrawal_fee = 25
    total_deduction = amount + withdrawal_fee
    
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (total_deduction, session['user_id']))
    
    # Create withdrawal request
    c.execute('INSERT INTO withdrawals (user_id, amount, mpesa_number, status) VALUES (?, ?, ?, ?)',
             (session['user_id'], amount, mpesa_number, 'pending'))
    
    # Log admin profit from withdrawal fee
    c.execute('''CREATE TABLE IF NOT EXISTS admin_profits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT,
        amount REAL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''INSERT INTO admin_profits (source, amount, description, created_at) 
                 VALUES (?, ?, ?, datetime('now'))''',
             ('withdrawal_fee', withdrawal_fee, f'Withdrawal fee from {session["username"]}'))
    
    conn.commit()
    conn.close()
    
    flash('Withdrawal request submitted!', 'success')
    return redirect(url_for('wallet'))

@app.route('/wallet')
def wallet():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Update session balance
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()
    if balance:
        session['balance'] = balance[0]
    
    # Get withdrawal history
    c.execute('SELECT * FROM withdrawals WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],))
    withdrawals = c.fetchall()
    
    conn.close()
    
    return render_template('wallet.html', transactions=[], withdrawals=withdrawals)

@app.route('/promotions')
def promotions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Update session balance
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()
    if balance:
        session['balance'] = balance[0]
    conn.close()
    
    return render_template('promotions.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    
    # Update session balance
    if user:
        session['balance'] = user[4]
    
    # Get recent matches for history with proper data
    c.execute('''SELECT m.id, m.game, m.player1_id, m.player2_id, m.bet_amount, m.total_pot, 
                        m.winner_id, m.status, m.game_mode, m.created_at,
                        u1.username as p1_name, u2.username as p2_name
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.player1_id = ? OR m.player2_id = ?
                 ORDER BY m.created_at DESC LIMIT 5''', (session['user_id'], session['user_id']))
    recent_matches = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', user=user, matches=recent_matches)

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('username') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Calculate real stats
    c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
    total_users = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM matches WHERE status = "active"')
    active_matches = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "deposit"')
    total_deposits = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(total_pot), 0) FROM matches WHERE status = "completed"')
    total_completed_pots = c.fetchone()[0]
    
    # Revenue sources
    match_commission = total_completed_pots * 0.16  # 16% commission (8% from each player)
    
    c.execute('SELECT COALESCE(SUM(amount_sent * 0.03), 0) FROM deposit_verifications')
    deposit_fees = c.fetchone()[0]  # 3% on all deposits
    
    c.execute('SELECT COUNT(*) FROM withdrawals WHERE status = "completed"')
    withdrawal_count = c.fetchone()[0]
    withdrawal_fees = withdrawal_count * 25  # KSh 25 per withdrawal fee
    
    total_earnings = match_commission + deposit_fees + withdrawal_fees
    
    stats = {
        'total_users': total_users,
        'active_matches': active_matches,
        'total_deposits': total_deposits,
        'net_earnings': total_earnings,
        'gross_earnings': total_earnings,
        'bank_fees': 0
    }
    
    # Calculate bank fees and other costs
    bank_fees = (deposit_fees * 0.15) + (withdrawal_fees * 0.20)  # Bank charges
    net_earnings = total_earnings - bank_fees
    
    earnings_data = {
        'gross_earnings': total_earnings,
        'match_commission': match_commission,
        'deposit_fees': deposit_fees,
        'withdrawal_fees': withdrawal_fees,
        'bank_fees': bank_fees,
        'net_earnings': net_earnings,
        'commission_rate': 8
    }
    
    # Get pending deposits
    c.execute('''SELECT t.*, u.username, u.email FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 WHERE t.type = "pending_deposit"
                 ORDER BY t.created_at DESC''')
    pending_deposits = c.fetchall()
    
    # Get pending withdrawals from withdrawals table
    c.execute('''SELECT w.id, u.username, w.amount, w.mpesa_number, w.status, w.created_at
                 FROM withdrawals w
                 JOIN users u ON w.user_id = u.id
                 WHERE w.status = "pending"
                 ORDER BY w.created_at ASC''')
    pending_withdrawals = c.fetchall()
    
    # Get disputed matches with results, screenshots and AI analysis
    c.execute('''SELECT m.id, m.game, m.bet_amount, m.total_pot, 
                        u1.username as p1_name, u2.username as p2_name,
                        (SELECT claimed_result FROM match_results WHERE match_id = m.id AND submitter_id = m.player1_id LIMIT 1) as p1_result,
                        (SELECT claimed_result FROM match_results WHERE match_id = m.id AND submitter_id = m.player2_id LIMIT 1) as p2_result,
                        (SELECT screenshot FROM match_results WHERE match_id = m.id AND submitter_id = m.player1_id LIMIT 1) as p1_screenshot,
                        (SELECT screenshot FROM match_results WHERE match_id = m.id AND submitter_id = m.player2_id LIMIT 1) as p2_screenshot,
                        (SELECT ai_analysis FROM match_results WHERE match_id = m.id AND submitter_id = m.player1_id LIMIT 1) as p1_ai,
                        (SELECT ai_analysis FROM match_results WHERE match_id = m.id AND submitter_id = m.player2_id LIMIT 1) as p2_ai
                 FROM matches m
                 JOIN users u1 ON m.player1_id = u1.id
                 JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.status = "disputed"
                 ORDER BY m.id DESC''')
    disputed_matches = c.fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', stats=stats, pending_withdrawals=pending_withdrawals, pending_deposits=pending_deposits, disputed_matches=disputed_matches, notifications=[], earnings_data=earnings_data)

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username != "admin" ORDER BY id DESC')
    users = c.fetchall()
    conn.close()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/transactions')
def admin_transactions():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get all transactions with user info
    c.execute('''SELECT t.id, t.user_id, t.type, t.amount, t.description, t.created_at, u.username
                 FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 ORDER BY t.created_at DESC LIMIT 100''')
    transactions = c.fetchall()
    
    conn.close()
    return render_template('admin_transactions.html', transactions=transactions)

@app.route('/cancel_match/<int:match_id>', methods=['POST'])
def cancel_match(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get match details
    c.execute('SELECT player1_id, player2_id, bet_amount, status FROM matches WHERE id = ?', (match_id,))
    match = c.fetchone()
    
    if not match:
        flash('Match not found!', 'error')
        conn.close()
        return redirect(url_for('matches'))
    
    player1_id, player2_id, bet_amount, status = match
    
    if status == 'pending' and not player2_id:
        # No opponent joined - free cancellation
        c.execute('UPDATE matches SET status = "cancelled" WHERE id = ?', (match_id,))
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bet_amount, player1_id))
        flash('Match cancelled - full refund given!', 'success')
    
    elif status == 'pending' and player2_id:
        # Opponent joined - 20% penalty
        penalty = bet_amount * 0.2
        refund = bet_amount - penalty
        
        c.execute('UPDATE matches SET status = "cancelled" WHERE id = ?', (match_id,))
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (refund, session['user_id']))  # Partial refund to canceller
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bet_amount, player2_id))      # Full refund to opponent
        
        flash(f'Match cancelled - KSh {penalty} penalty applied, KSh {refund} refunded!', 'success')
    
    elif status == 'active':
        # Active match - 50% penalty (forfeit)
        penalty = bet_amount * 0.5
        refund = bet_amount - penalty
        opponent_id = player2_id if session['user_id'] == player1_id else player1_id
        
        c.execute('UPDATE matches SET status = "completed", winner_id = ? WHERE id = ?', (opponent_id, match_id))
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (refund, session['user_id']))  # Partial refund to forfeiter
        c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1, total_earnings = total_earnings + ? WHERE id = ?', 
                 (bet_amount * 1.68, bet_amount * 1.68, opponent_id))  # Full winnings to opponent
        c.execute('UPDATE users SET losses = losses + 1 WHERE id = ?', (session['user_id'],))
        
        flash(f'Match forfeited - KSh {penalty} penalty applied, opponent wins!', 'error')
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('matches'))

@app.route('/join_match/<int:match_id>')
def join_match(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get match details and check if already joined
    c.execute('SELECT bet_amount, status, player2_id FROM matches WHERE id = ?', (match_id,))
    match = c.fetchone()
    
    if not match:
        flash('Match not found!', 'error')
        conn.close()
        return redirect(url_for('matches'))
    
    if match[1] != 'pending' or match[2] is not None:
        flash('Match not available or already joined!', 'error')
        conn.close()
        return redirect(url_for('matches'))
    
    bet_amount = match[0]
    
    # Check if user has enough balance
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()[0]
    
    if balance < bet_amount:
        flash(f'Insufficient balance! Need KSh {bet_amount} to join this match.', 'error')
        conn.close()
        return redirect(url_for('matches'))
    
    # Atomic transaction: deduct money and join match
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (bet_amount, session['user_id']))
    c.execute('UPDATE matches SET player2_id = ? WHERE id = ? AND player2_id IS NULL', (session['user_id'], match_id))
    
    # Check if update was successful
    if c.rowcount == 0:
        # Match was already joined by someone else, refund
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bet_amount, session['user_id']))
        flash('Match was already joined by another player!', 'error')
        conn.commit()
        conn.close()
        return redirect(url_for('matches'))
    
    session['balance'] = balance - bet_amount
    conn.commit()
    conn.close()
    
    flash(f'Match joined! KSh {bet_amount} deducted. Both players must confirm to start.', 'success')
    return redirect(url_for('match_lobby', match_id=match_id))

@app.route('/admin/matches')
def admin_matches():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get all matches with complete info
    c.execute('''SELECT m.id, m.game, m.player1_id, m.player2_id, m.bet_amount, m.total_pot, 
                        m.winner_id, m.status, m.game_mode, m.created_at,
                        u1.username as p1_name, u2.username as p2_name, uw.username as winner_name
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 LEFT JOIN users uw ON m.winner_id = uw.id
                 ORDER BY m.created_at DESC LIMIT 100''')
    matches = c.fetchall()
    
    conn.close()
    return render_template('admin_matches.html', matches=matches)

@app.route('/admin/approve_deposit/<int:transaction_id>', methods=['GET', 'POST'])
def approve_deposit(transaction_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get transaction details
    c.execute('SELECT user_id, amount FROM transactions WHERE id = ?', (transaction_id,))
    transaction = c.fetchone()
    
    if transaction:
        user_id, amount = transaction
        # Add amount to user balance
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
        # Update transaction status
        c.execute('UPDATE transactions SET type = "deposit" WHERE id = ?', (transaction_id,))
        conn.commit()
        flash('Deposit approved and credited to user!', 'success')
    
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/approve_withdrawal/<int:withdrawal_id>', methods=['GET', 'POST'])
def approve_withdrawal(withdrawal_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        payment_proof = None
        if 'payment_proof' in request.files:
            file = request.files['payment_proof']
            if file and file.filename:
                import base64
                proof_data = file.read()
                payment_proof = base64.b64encode(proof_data).decode('utf-8')
        
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        c.execute('UPDATE withdrawals SET status = "completed", payment_proof = ? WHERE id = ?', 
                 (payment_proof, withdrawal_id))
        conn.commit()
        conn.close()
        
        flash('Withdrawal approved with payment proof!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    # Show approval form
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('SELECT w.*, u.username FROM withdrawals w JOIN users u ON w.user_id = u.id WHERE w.id = ?', (withdrawal_id,))
    withdrawal = c.fetchone()
    conn.close()
    
    return render_template('admin_approve_withdrawal.html', withdrawal=withdrawal)

@app.route('/admin/reject_deposit/<int:transaction_id>', methods=['GET', 'POST'])
def reject_deposit(transaction_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('UPDATE transactions SET type = "rejected_deposit" WHERE id = ?', (transaction_id,))
    conn.commit()
    conn.close()
    
    flash('Deposit rejected!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_withdrawal/<int:withdrawal_id>', methods=['GET', 'POST'])
def reject_withdrawal(withdrawal_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get withdrawal details to refund the user
    c.execute('SELECT user_id, amount FROM withdrawals WHERE id = ?', (withdrawal_id,))
    withdrawal = c.fetchone()
    
    if withdrawal:
        user_id, amount = withdrawal
        # Refund the amount to user's balance
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
        # Mark withdrawal as rejected
        c.execute('UPDATE withdrawals SET status = "rejected" WHERE id = ?', (withdrawal_id,))
        conn.commit()
        flash('Withdrawal rejected and amount refunded to user!', 'success')
    else:
        flash('Withdrawal not found!', 'error')
    
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/view_deposit/<int:transaction_id>')
def view_deposit_details(transaction_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('''SELECT dv.mpesa_number, dv.sender_name, dv.receipt_screenshot, dv.amount_sent, dv.created_at,
                        (dv.amount_sent - dv.amount_sent * 0.02) as amount_to_credit, u.username, u.email,
                        (dv.amount_sent * 0.02) as processing_fee
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
                'username': deposit_details[6],
                'email': deposit_details[7],
                'mpesa_number': deposit_details[0],
                'sender_name': deposit_details[1],
                'amount_sent': deposit_details[3],
                'amount_to_credit': deposit_details[5],
                'processing_fee': deposit_details[8],
                'receipt_screenshot': deposit_details[2],
                'created_at': deposit_details[4]
            }
        })
    
    return jsonify({'success': False, 'message': 'Deposit not found'})

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        phone = request.form.get('phone', '').strip()
        
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        c.execute('UPDATE users SET phone = ? WHERE id = ?', (phone, session['user_id']))
        conn.commit()
        
        # Get updated user data
        c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        flash('Profile updated successfully!', 'success')
        return render_template('profile.html', user=user)
    
    # Get current user data
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# New routes for features
@app.route('/friends')
def friends():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get friends list
    c.execute('''SELECT u.id, u.username, u.phone, f.status
                 FROM friends f
                 JOIN users u ON (f.friend_id = u.id)
                 WHERE f.user_id = ? AND f.status = 'accepted'
                 ORDER BY u.username''', (session['user_id'],))
    friends_list = c.fetchall()
    
    # Get friend requests
    c.execute('''SELECT u.id, u.username, f.id as request_id
                 FROM friends f
                 JOIN users u ON f.user_id = u.id
                 WHERE f.friend_id = ? AND f.status = 'pending'
                 ORDER BY f.created_at DESC''', (session['user_id'],))
    friend_requests = c.fetchall()
    
    # Get all active users (exclude self and existing friends/requests)
    c.execute('''SELECT u.id, u.username, u.phone, 
                        CASE WHEN u.id IN (
                            SELECT CASE WHEN f.user_id = ? THEN f.friend_id ELSE f.user_id END
                            FROM friends f 
                            WHERE (f.user_id = ? OR f.friend_id = ?)
                        ) THEN 1 ELSE 0 END as is_connected
                 FROM users u 
                 WHERE u.id != ? AND u.username != 'admin'
                 ORDER BY u.username''', 
                (session['user_id'], session['user_id'], session['user_id'], session['user_id']))
    all_users = c.fetchall()
    
    conn.close()
    return render_template('friends.html', friends=friends_list, requests=friend_requests, all_users=all_users)

@app.route('/add_friend', methods=['POST'])
def add_friend():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = request.form['username'].strip()
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Find user
    c.execute('SELECT id FROM users WHERE username = ? AND id != ?', (username, session['user_id']))
    friend = c.fetchone()
    
    if friend:
        # Check if already friends or request exists
        c.execute('SELECT id FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
                 (session['user_id'], friend[0], friend[0], session['user_id']))
        existing = c.fetchone()
        
        if not existing:
            c.execute('INSERT INTO friends (user_id, friend_id) VALUES (?, ?)', (session['user_id'], friend[0]))
            conn.commit()
            flash('Friend request sent!', 'success')
        else:
            flash('Already friends or request pending!', 'error')
    else:
        flash('User not found!', 'error')
    
    conn.close()
    return redirect(url_for('friends'))

@app.route('/accept_friend/<int:request_id>')
def accept_friend(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('UPDATE friends SET status = "accepted" WHERE id = ? AND friend_id = ?', (request_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Friend request accepted!', 'success')
    return redirect(url_for('friends'))

@app.route('/leaderboard')
def leaderboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Top players by wins
    c.execute('''SELECT username, wins, losses, total_earnings, 
                        CASE WHEN (wins + losses) > 0 THEN ROUND((wins * 100.0 / (wins + losses)), 1) ELSE 0 END as win_rate
                 FROM users WHERE username != 'admin' AND (wins + losses) > 0
                 ORDER BY wins DESC, win_rate DESC LIMIT 20''')
    top_players = c.fetchall()
    
    # Top earners
    c.execute('''SELECT username, total_earnings, wins, losses
                 FROM users WHERE username != 'admin' AND total_earnings > 0
                 ORDER BY total_earnings DESC LIMIT 20''')
    top_earners = c.fetchall()
    
    conn.close()
    return render_template('leaderboard.html', top_players=top_players, top_earners=top_earners)

@app.route('/match_history')
def match_history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get match history
    c.execute('''SELECT m.*, u1.username as p1_name, u1.phone as p1_phone,
                        u2.username as p2_name, u2.phone as p2_phone
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE (m.player1_id = ? OR m.player2_id = ?) AND m.status != 'pending'
                 ORDER BY m.id DESC''', (session['user_id'], session['user_id']))
    match_history = c.fetchall()
    
    # Get transaction history
    c.execute('''SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC''', (session['user_id'],))
    transactions = c.fetchall()
    
    # Get withdrawal history
    c.execute('''SELECT * FROM withdrawals WHERE user_id = ? ORDER BY created_at DESC''', (session['user_id'],))
    withdrawals = c.fetchall()
    
    conn.close()
    return render_template('match_history.html', matches=match_history, transactions=transactions, withdrawals=withdrawals)

@app.route('/match_chat/<int:match_id>')
def match_chat(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Verify user is part of this match
    c.execute('SELECT * FROM matches WHERE id = ? AND (player1_id = ? OR player2_id = ?)',
             (match_id, session['user_id'], session['user_id']))
    match = c.fetchone()
    
    if not match:
        flash('Access denied!', 'error')
        return redirect(url_for('matches'))
    
    # Get chat messages
    c.execute('''SELECT mc.message, mc.created_at, u.username
                 FROM match_chat mc
                 JOIN users u ON mc.user_id = u.id
                 WHERE mc.match_id = ?
                 ORDER BY mc.created_at ASC''', (match_id,))
    messages = c.fetchall()
    
    conn.close()
    return render_template('match_chat.html', match=match, messages=messages, match_id=match_id)

@app.route('/send_message/<int:match_id>', methods=['POST'])
def send_message(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Verify user is part of this match
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    c.execute('SELECT * FROM matches WHERE id = ? AND (player1_id = ? OR player2_id = ?)',
             (match_id, session['user_id'], session['user_id']))
    match = c.fetchone()
    
    if not match:
        flash('Access denied!', 'error')
        conn.close()
        return redirect(url_for('matches'))
    
    message = request.form.get('message', '').strip()
    if message:
        c.execute('INSERT INTO match_chat (match_id, user_id, message) VALUES (?, ?, ?)',
                 (match_id, session['user_id'], message))
        conn.commit()
        flash('Message sent!', 'success')
    else:
        flash('Message cannot be empty!', 'error')
    
    conn.close()
    return redirect(url_for('match_chat', match_id=match_id))

@app.route('/check_match_timeouts')
def check_match_timeouts():
    """Auto-timeout matches after 2 hours of inactivity"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Find active matches older than 2 hours
    c.execute('''SELECT id, player1_id, player2_id, bet_amount 
                 FROM matches 
                 WHERE status = 'active' 
                 AND datetime(created_at, '+2 hours') < datetime('now')''')
    
    timed_out_matches = c.fetchall()
    
    for match in timed_out_matches:
        match_id, player1_id, player2_id, bet_amount = match
        
        # Refund both players
        c.execute('UPDATE users SET balance = balance + ? WHERE id IN (?, ?)', 
                 (bet_amount, player1_id, player2_id))
        
        # Mark match as timed out
        c.execute('UPDATE matches SET status = "timed_out" WHERE id = ?', (match_id,))
        
        # Log transactions
        c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                     VALUES (?, ?, ?, ?)''',
                 (player1_id, 'timeout_refund', bet_amount, f'Match {match_id} timed out - refund'))
        c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                     VALUES (?, ?, ?, ?)''',
                 (player2_id, 'timeout_refund', bet_amount, f'Match {match_id} timed out - refund'))
    
    conn.commit()
    conn.close()
    
    return f'Processed {len(timed_out_matches)} timed out matches'

@app.route('/match_result/<int:match_id>')
def match_result(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Check if match has timed out
    c.execute('''SELECT *, datetime(created_at, '+2 hours') < datetime('now') as is_expired 
                 FROM matches WHERE id = ? AND (player1_id = ? OR player2_id = ?)''',
             (match_id, session['user_id'], session['user_id']))
    match = c.fetchone()
    
    if not match:
        flash('Match not found!', 'error')
        conn.close()
        return redirect(url_for('matches'))
    
    # Auto-timeout if expired
    if match[-1] and match[7] == 'active':  # is_expired and status is active
        bet_amount = match[4]
        player1_id, player2_id = match[2], match[3]
        
        # Refund both players
        c.execute('UPDATE users SET balance = balance + ? WHERE id IN (?, ?)', 
                 (bet_amount, player1_id, player2_id))
        c.execute('UPDATE matches SET status = "timed_out" WHERE id = ?', (match_id,))
        
        conn.commit()
        flash('Match timed out after 2 hours. Both players refunded.', 'error')
        conn.close()
        return redirect(url_for('matches'))
    
    conn.close()
    return render_template('match_result.html', match=match)

@app.route('/submit_result/<int:match_id>', methods=['POST'])
def submit_result(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    result = request.form['result']
    screenshot = None
    
    # Handle screenshot upload and AI verification
    screenshot = None
    ai_analysis = {'validity': 'VALID', 'confidence': 0.8}  # Simplified for now
    
    if 'screenshot' in request.files:
        file = request.files['screenshot']
        if file and file.filename:
            import base64
            screenshot_data = file.read()
            screenshot = base64.b64encode(screenshot_data).decode('utf-8')
            
            # AI Analysis of screenshot
            ai_analysis = analyze_screenshot(screenshot_data, result)
        else:
            flash('Screenshot is required!', 'error')
            conn.close()
            return redirect(url_for('match_result', match_id=match_id))
    else:
        flash('Screenshot is required!', 'error')
        conn.close()
        return redirect(url_for('match_result', match_id=match_id))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Check if user already submitted for this match
    c.execute('SELECT id FROM match_results WHERE match_id = ? AND submitter_id = ?', (match_id, session['user_id']))
    existing = c.fetchone()
    
    if existing:
        # Update existing submission
        c.execute('UPDATE match_results SET claimed_result = ?, screenshot = ?, ai_analysis = ?, status = ? WHERE id = ?',
                 (result, screenshot, str(ai_analysis), 'pending_verification', existing[0]))
    else:
        # Create new submission
        c.execute('''INSERT INTO match_results (match_id, submitter_id, claimed_result, screenshot, ai_analysis, status)
                     VALUES (?, ?, ?, ?, ?, ?)''', 
                    (match_id, session['user_id'], result, screenshot, str(ai_analysis), 'pending_verification'))
    
    # Check if opponent already submitted
    c.execute('''SELECT claimed_result, submitter_id FROM match_results 
                 WHERE match_id = ? AND submitter_id != ? AND status = 'pending_verification' ''', 
                (match_id, session['user_id']))
    opponent_result = c.fetchone()
    
    # Check AI analysis before proceeding
    if ai_analysis['validity'] != 'VALID':
        flash(f'Screenshot rejected: {ai_analysis.get("reason", "Invalid game screenshot")}', 'error')
        conn.commit()
        conn.close()
        return redirect(url_for('match_result', match_id=match_id))
    
    if opponent_result:
        # Get opponent's AI analysis
        c.execute('SELECT ai_analysis FROM match_results WHERE match_id = ? AND submitter_id = ?', 
                 (match_id, opponent_result[1]))
        opponent_ai = c.fetchone()
        
        # Check if both screenshots are valid
        opponent_ai_data = eval(opponent_ai[0]) if opponent_ai and opponent_ai[0] else {'validity': 'NOT_GAME_SCREENSHOT'}
        
        if opponent_ai_data['validity'] != 'VALID':
            # Opponent has invalid screenshot - mark for admin review
            c.execute('UPDATE matches SET status = "disputed" WHERE id = ?', (match_id,))
            c.execute('UPDATE match_results SET status = "disputed" WHERE match_id = ?', (match_id,))
            flash('Match disputed - opponent has invalid screenshot. Admin will review.', 'error')
        elif (result == 'won' and opponent_result[0] == 'lost') or (result == 'lost' and opponent_result[0] == 'won'):
            # Both have valid screenshots and results agree - auto-complete match
            winner_id = session['user_id'] if result == 'won' else opponent_result[1]
            loser_id = opponent_result[1] if result == 'won' else session['user_id']
            
            c.execute('SELECT bet_amount FROM matches WHERE id = ?', (match_id,))
            bet_amount = c.fetchone()[0]
            
            c.execute('UPDATE matches SET winner_id = ?, status = "completed" WHERE id = ?', (winner_id, match_id))
            
            winnings = bet_amount * 1.68
            c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1, total_earnings = total_earnings + ? WHERE id = ?', 
                     (winnings, winnings, winner_id))
            c.execute('UPDATE users SET losses = losses + 1 WHERE id = ?', (loser_id,))
            
            c.execute('UPDATE match_results SET status = "accepted" WHERE match_id = ?', (match_id,))
            flash('Match completed! Valid screenshots and results agreed.', 'success')
        else:
            # Results conflict - mark for admin review
            c.execute('UPDATE matches SET status = "disputed" WHERE id = ?', (match_id,))
            c.execute('UPDATE match_results SET status = "disputed" WHERE match_id = ?', (match_id,))
            flash('Results conflict! Admin will review with screenshots.', 'error')
    else:
        flash('Valid screenshot submitted! Waiting for opponent to submit their result.', 'success')
    
    conn.commit()
    conn.close()
    return redirect(url_for('matches'))

@app.route('/match_lobby/<int:match_id>')
def match_lobby(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get match details
    c.execute('''SELECT m.*, u1.username as p1_name, u2.username as p2_name
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.id = ? AND (m.player1_id = ? OR m.player2_id = ?)''', 
                (match_id, session['user_id'], session['user_id']))
    match = c.fetchone()
    
    if not match:
        flash('Match not found!', 'error')
        conn.close()
        return redirect(url_for('matches'))
    
    # Check confirmation status for each specific player
    c.execute('SELECT COUNT(*) FROM match_confirmations WHERE match_id = ? AND player_id = ?', (match_id, match[2]))
    p1_confirmed = c.fetchone()[0] > 0
    
    c.execute('SELECT COUNT(*) FROM match_confirmations WHERE match_id = ? AND player_id = ?', (match_id, match[3]))
    p2_confirmed = c.fetchone()[0] > 0 if match[3] else False
    
    c.execute('SELECT COUNT(*) FROM match_confirmations WHERE match_id = ? AND player_id = ?', (match_id, session['user_id']))
    user_confirmed = c.fetchone()[0] > 0
    
    # Debug info
    print(f"Match ID: {match_id}")
    print(f"Player1 ID: {match[2]}, Player2 ID: {match[3]}")
    print(f"P1 confirmed: {p1_confirmed}, P2 confirmed: {p2_confirmed}")
    
    conn.close()
    
    return render_template('match_lobby.html', match=match, 
                         p1_name=match[11], p2_name=match[12],
                         p1_confirmed=p1_confirmed, p2_confirmed=p2_confirmed,
                         user_confirmed=user_confirmed, p1_id=match[2], p2_id=match[3],
                         debug_info=f"P1:{match[2]} P2:{match[3]} P1_conf:{p1_confirmed} P2_conf:{p2_confirmed}")

@app.route('/confirm_ready/<int:match_id>', methods=['POST'])
def confirm_ready(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Add confirmation
    c.execute('INSERT OR IGNORE INTO match_confirmations (match_id, player_id) VALUES (?, ?)', 
             (match_id, session['user_id']))
    
    # Check if both players confirmed
    c.execute('SELECT COUNT(*) FROM match_confirmations WHERE match_id = ?', (match_id,))
    confirmed_count = c.fetchone()[0]
    
    if confirmed_count == 2:
        # Both confirmed - activate match
        c.execute('UPDATE matches SET status = "active" WHERE id = ?', (match_id,))
        flash('Match is now active! Good luck!', 'success')
    else:
        flash('Confirmation recorded! Waiting for opponent...', 'success')
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('match_lobby', match_id=match_id))

@app.route('/tournaments')
def tournaments():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get active tournaments with participant count
    c.execute('''SELECT t.*, COUNT(tp.id) as participant_count
                 FROM tournaments t
                 LEFT JOIN tournament_participants tp ON t.id = tp.tournament_id
                 WHERE t.status IN ('open', 'full', 'active')
                 GROUP BY t.id
                 ORDER BY t.created_at DESC''')
    tournaments = c.fetchall()
    
    # Get user's tournament history
    c.execute('''SELECT t.name, t.game, t.entry_fee, tp.position, tp.prize_won, tp.created_at
                 FROM tournament_participants tp
                 JOIN tournaments t ON tp.tournament_id = t.id
                 WHERE tp.user_id = ?
                 ORDER BY tp.created_at DESC LIMIT 10''', (session['user_id'],))
    my_tournaments = c.fetchall()
    
    conn.close()
    # Auto-create tournaments if needed (every 4 hours)
    auto_create_tournament()
    
    return render_template('tournaments.html', tournaments=tournaments, my_tournaments=my_tournaments)

@app.route('/join_tournament/<int:tournament_id>')
def join_tournament(tournament_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get tournament details
    c.execute('SELECT * FROM tournaments WHERE id = ? AND status = "open"', (tournament_id,))
    tournament = c.fetchone()
    
    if not tournament:
        flash('Tournament not available!', 'error')
        conn.close()
        return redirect(url_for('tournaments'))
    
    entry_fee = tournament[3]
    max_players = tournament[4]
    
    # Check if user has enough balance
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()[0]
    
    if balance < entry_fee:
        flash(f'Insufficient balance! Need KSh {entry_fee} to join.', 'error')
        conn.close()
        return redirect(url_for('tournaments'))
    
    # Check if already joined
    c.execute('SELECT id FROM tournament_participants WHERE tournament_id = ? AND user_id = ?', 
             (tournament_id, session['user_id']))
    if c.fetchone():
        flash('You already joined this tournament!', 'error')
        conn.close()
        return redirect(url_for('tournaments'))
    
    # Check if tournament is full
    c.execute('SELECT COUNT(*) FROM tournament_participants WHERE tournament_id = ?', (tournament_id,))
    current_players = c.fetchone()[0]
    
    if current_players >= max_players:
        flash('Tournament is full!', 'error')
        conn.close()
        return redirect(url_for('tournaments'))
    
    # Join tournament
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (entry_fee, session['user_id']))
    c.execute('INSERT INTO tournament_participants (tournament_id, user_id) VALUES (?, ?)', 
             (tournament_id, session['user_id']))
    
    # Update prize pool - 85% to players, 15% to admin
    new_prize_pool = tournament[5] + (entry_fee * 0.85)
    admin_commission = entry_fee * 0.15
    
    c.execute('UPDATE tournaments SET prize_pool = ? WHERE id = ?', (new_prize_pool, tournament_id))
    
    # Create admin_profits table if not exists and log commission
    c.execute('''CREATE TABLE IF NOT EXISTS admin_profits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT,
        amount REAL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''INSERT INTO admin_profits (source, amount, description, created_at) 
                 VALUES (?, ?, ?, datetime('now'))''',
             ('tournament_entry', admin_commission, f'Tournament entry commission from {session["username"]}'))
    
    if current_players + 1 >= max_players:
        c.execute('UPDATE tournaments SET status = "full" WHERE id = ?', (tournament_id,))
    
    session['balance'] = balance - entry_fee
    conn.commit()
    conn.close()
    
    flash(f'Joined tournament! KSh {entry_fee} deducted. Tournament starts when full.', 'success')
    return redirect(url_for('tournaments'))

@app.route('/create_tournament', methods=['POST'])
def create_tournament():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    name = request.form['name']
    game = request.form['game']
    entry_fee = float(request.form['entry_fee'])
    max_players = int(request.form['max_players'])
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('''INSERT INTO tournaments (name, game, entry_fee, max_players, prize_pool)
                 VALUES (?, ?, ?, ?, ?)''', (name, game, entry_fee, max_players, 0))
    
    conn.commit()
    conn.close()
    
    flash('Tournament created!', 'success')
    return redirect(url_for('admin_dashboard'))



@app.route('/support')
def support_chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('support_chat.html')

@app.route('/escalate_support', methods=['POST'])
def escalate_support():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Create table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS support_escalations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        message TEXT,
        status TEXT DEFAULT 'pending',
        admin_response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''INSERT INTO support_escalations (user_id, username, message, status, created_at) 
                 VALUES (?, ?, ?, ?, datetime('now'))''',
             (session['user_id'], session['username'], data['message'], 'pending'))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/support_center')
def admin_support_center():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Create table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS support_escalations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        message TEXT,
        status TEXT DEFAULT 'pending',
        admin_response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Get pending escalations
    c.execute('SELECT * FROM support_escalations WHERE status = "pending" ORDER BY created_at DESC')
    pending_escalations = c.fetchall()
    
    # Get resolved today count
    c.execute('SELECT COUNT(*) FROM support_escalations WHERE status = "resolved" AND date(created_at) = date("now")')
    resolved_today = c.fetchone()[0]
    
    conn.close()
    
    return render_template('admin_support.html', 
                         pending_escalations=pending_escalations,
                         active_chats=[],
                         resolved_today=resolved_today)

@app.route('/admin/respond_support', methods=['POST'])
def admin_respond_support():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('UPDATE support_escalations SET admin_response = ?, status = "responded" WHERE id = ?',
             (data['response'], data['escalation_id']))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/adjust_balance', methods=['POST'])
def admin_adjust_balance():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('UPDATE users SET balance = balance + ? WHERE username = ?',
             (data['amount'], data['username']))
    
    # Log the adjustment
    c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES ((SELECT id FROM users WHERE username = ?), ?, ?, ?)',
             (data['username'], 'admin_adjustment', data['amount'], f'Admin balance adjustment: {data["amount"]}'))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/tournament/<int:tournament_id>')
def tournament_details(tournament_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get tournament details
    c.execute('SELECT * FROM tournaments WHERE id = ?', (tournament_id,))
    tournament = c.fetchone()
    
    if not tournament:
        flash('Tournament not found!', 'error')
        conn.close()
        return redirect(url_for('tournaments'))
    
    # Get participant count
    c.execute('SELECT COUNT(*) FROM tournament_participants WHERE tournament_id = ?', (tournament_id,))
    participants = c.fetchone()[0]
    
    conn.close()
    
    return render_template('tournament_details.html', tournament=tournament, participants=participants)

@app.route('/tournament/<int:tournament_id>/submit_result', methods=['GET', 'POST'])
def tournament_submit_result(tournament_id):
    """Submit tournament result - exactly like match system"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Check if user is in this tournament
    c.execute('SELECT * FROM tournament_participants WHERE tournament_id = ? AND user_id = ?', 
             (tournament_id, session['user_id']))
    participant = c.fetchone()
    
    if not participant:
        flash('You are not in this tournament!', 'error')
        conn.close()
        return redirect(url_for('tournaments'))
    
    # Get tournament info
    c.execute('SELECT name, game FROM tournaments WHERE id = ?', (tournament_id,))
    tournament = c.fetchone()
    
    if request.method == 'POST':
        result = request.form['result']  # 'won' or 'lost'
        screenshot = request.files.get('screenshot')
        
        if screenshot:
            import base64, time
            screenshot_data = screenshot.read()
            screenshot_b64 = base64.b64encode(screenshot_data).decode('utf-8')
            
            # Create tournament_results table if not exists
            c.execute('''CREATE TABLE IF NOT EXISTS tournament_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tournament_id INTEGER,
                user_id INTEGER,
                claimed_result TEXT,
                screenshot TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # Check if already submitted
            c.execute('SELECT id FROM tournament_results WHERE tournament_id = ? AND user_id = ?', 
                     (tournament_id, session['user_id']))
            existing = c.fetchone()
            
            if existing:
                # Update existing submission
                c.execute('UPDATE tournament_results SET claimed_result = ?, screenshot = ?, status = ? WHERE id = ?',
                         (result, screenshot_b64, 'pending', existing[0]))
            else:
                # Create new submission
                c.execute('''INSERT INTO tournament_results (tournament_id, user_id, claimed_result, screenshot, status)
                             VALUES (?, ?, ?, ?, ?)''',
                         (tournament_id, session['user_id'], result, screenshot_b64, 'pending'))
            
            # Check if we can auto-determine winners (like matches)
            c.execute('SELECT COUNT(*) FROM tournament_results WHERE tournament_id = ? AND status = "pending"', (tournament_id,))
            total_submissions = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM tournament_participants WHERE tournament_id = ?', (tournament_id,))
            total_participants = c.fetchone()[0]
            
            if total_submissions >= total_participants:
                # All players submitted - auto-determine winners
                c.execute('''SELECT tr.user_id, tr.claimed_result, u.username 
                             FROM tournament_results tr
                             JOIN users u ON tr.user_id = u.id
                             WHERE tr.tournament_id = ? AND tr.status = "pending"
                             ORDER BY 
                                CASE WHEN tr.claimed_result = 'won' THEN 1 ELSE 2 END,
                                tr.created_at ASC''', (tournament_id,))
                all_results = c.fetchall()
                
                # Auto-award prizes to "won" claimers first
                winners = [r for r in all_results if r[1] == 'won'][:4]  # Top 4 winners
                
                if len(winners) > 0:
                    # Get prize pool
                    c.execute('SELECT prize_pool FROM tournaments WHERE id = ?', (tournament_id,))
                    prize_pool = c.fetchone()[0]
                    
                    # Prize distribution: 40%, 25%, 12%, 8%
                    prize_percentages = [0.40, 0.25, 0.12, 0.08]
                    
                    for i, winner in enumerate(winners):
                        if i < len(prize_percentages):
                            prize = prize_pool * prize_percentages[i]
                            user_id = winner[0]
                            
                            # Award prize automatically
                            c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1, total_earnings = total_earnings + ? WHERE id = ?',
                                     (prize, prize, user_id))
                            
                            # Record transaction
                            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                                         VALUES (?, ?, ?, ?)''',
                                     (user_id, 'tournament_win', prize, f'Tournament auto-win - Position {i+1}'))
                            
                            # Update participant record
                            c.execute('UPDATE tournament_participants SET position = ?, prize_won = ? WHERE tournament_id = ? AND user_id = ?',
                                     (i+1, prize, tournament_id, user_id))
                    
                    # Mark tournament as completed
                    c.execute('UPDATE tournaments SET status = "completed" WHERE id = ?', (tournament_id,))
                    c.execute('UPDATE tournament_results SET status = "auto_resolved" WHERE tournament_id = ?', (tournament_id,))
                    
                    flash('Tournament completed automatically! Winners determined by claims.', 'success')
                else:
                    # No clear winners - admin review needed
                    flash('Result submitted! Admin will review (no clear winners).', 'success')
            else:
                flash('Result submitted! Waiting for other players...', 'success')
            
            conn.commit()
            conn.close()
            return redirect(url_for('tournaments'))
        else:
            flash('Screenshot is required!', 'error')
    
    conn.close()
    return render_template('tournament_submit_result.html', tournament_id=tournament_id, tournament=tournament)

@app.route('/admin/tournament_results')
def admin_tournament_results():
    """Admin reviews tournament results - exactly like match disputes"""
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get tournaments with pending results
    c.execute('''SELECT DISTINCT t.id, t.name, t.game, t.prize_pool, COUNT(tr.id) as submissions
                 FROM tournaments t
                 JOIN tournament_results tr ON t.id = tr.tournament_id
                 WHERE tr.status = 'pending' AND t.status = 'active'
                 GROUP BY t.id
                 ORDER BY t.created_at DESC''')
    tournaments_with_results = c.fetchall()
    
    conn.close()
    return render_template('admin_tournament_results.html', tournaments=tournaments_with_results)

@app.route('/admin/tournament/<int:tournament_id>/review')
def admin_review_tournament(tournament_id):
    """Admin reviews specific tournament results"""
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get tournament info
    c.execute('SELECT * FROM tournaments WHERE id = ?', (tournament_id,))
    tournament = c.fetchone()
    
    # Get all results for this tournament
    c.execute('''SELECT tr.*, u.username FROM tournament_results tr
                 JOIN users u ON tr.user_id = u.id
                 WHERE tr.tournament_id = ? AND tr.status = 'pending'
                 ORDER BY tr.created_at''', (tournament_id,))
    results = c.fetchall()
    
    conn.close()
    return render_template('admin_review_tournament.html', tournament=tournament, results=results)

@app.route('/admin/tournament/<int:tournament_id>/declare_winners', methods=['POST'])
def admin_declare_tournament_winners(tournament_id):
    """Admin declares tournament winners - exactly like match resolution"""
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    # Get winners in order (1st, 2nd, 3rd, 4th)
    winner_1 = request.form.get('winner_1')
    winner_2 = request.form.get('winner_2')
    winner_3 = request.form.get('winner_3')
    winner_4 = request.form.get('winner_4')
    
    winners = [winner_1, winner_2, winner_3, winner_4]
    winners = [w for w in winners if w]  # Remove empty values
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get tournament prize pool
    c.execute('SELECT prize_pool FROM tournaments WHERE id = ?', (tournament_id,))
    prize_pool = c.fetchone()[0]
    
    # Prize distribution: 40%, 25%, 12%, 8%
    prize_percentages = [0.40, 0.25, 0.12, 0.08]
    
    for i, winner_id in enumerate(winners):
        if i < len(prize_percentages) and winner_id:
            prize = prize_pool * prize_percentages[i]
            
            # Award prize (exactly like match system)
            c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1, total_earnings = total_earnings + ? WHERE id = ?',
                     (prize, prize, int(winner_id)))
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (int(winner_id), 'tournament_win', prize, f'Tournament prize - Position {i+1}'))
            
            # Update participant record
            c.execute('UPDATE tournament_participants SET position = ?, prize_won = ? WHERE tournament_id = ? AND user_id = ?',
                     (i+1, prize, tournament_id, int(winner_id)))
    
    # Mark tournament as completed
    c.execute('UPDATE tournaments SET status = "completed" WHERE id = ?', (tournament_id,))
    c.execute('UPDATE tournament_results SET status = "resolved" WHERE tournament_id = ?', (tournament_id,))
    
    conn.commit()
    conn.close()
    
    flash('Tournament winners declared and prizes awarded!', 'success')
    return redirect(url_for('admin_tournament_results'))

@app.route('/admin/create_tournament', methods=['GET', 'POST'])
def admin_create_tournament():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        game = request.form['game']
        entry_fee = float(request.form['entry_fee'])
        max_players = int(request.form['max_players'])
        
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        
        c.execute('''INSERT INTO tournaments (name, game, entry_fee, max_players, prize_pool)
                     VALUES (?, ?, ?, ?, ?)''', (name, game, entry_fee, max_players, 0))
        
        conn.commit()
        conn.close()
        
        flash('Tournament created successfully!', 'success')
        return redirect(url_for('tournaments'))
    
    return render_template('admin_create_tournament.html')

@app.route('/referrals')
def referrals():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get or create referral info
    c.execute('SELECT referral_code, referral_earnings FROM users WHERE id = ?', (session['user_id'],))
    user_info = c.fetchone()
    
    # If no referral code exists, generate one
    if not user_info or not user_info[0]:
        import random, string
        code = session['username'][:3].upper() + ''.join(random.choices(string.digits, k=4))
        c.execute('UPDATE users SET referral_code = ?, referral_earnings = 0 WHERE id = ?', (code, session['user_id']))
        conn.commit()
        user_info = (code, 0)
    
    # Get referred users
    try:
        c.execute('SELECT username, created_at FROM users WHERE referred_by = ? ORDER BY created_at DESC', (session['user_id'],))
        referred_users = c.fetchall()
    except:
        referred_users = []
    
    conn.close()
    
    return render_template('referrals.html', 
                         referral_code=user_info[0] if user_info else 'Loading...',
                         referral_earnings=user_info[1] if user_info else 0,
                         referred_users=referred_users)

@app.route('/auto_create_tournament')
def auto_create_tournament():
    """Auto-create tournaments - 6 per day at: 6AM, 10AM, 2PM, 6PM, 10PM, 2AM"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Check active tournaments
    c.execute('SELECT COUNT(*) FROM tournaments WHERE status IN ("open", "full")')
    active_count = c.fetchone()[0]
    
    if active_count < 3:  # Always keep 3 tournaments available
        tournaments = [
            ('PUBG Classic Solo', 'pubg_mobile', 100, 16),
            ('FIFA Head to Head', 'fifa_mobile', 150, 8),
            ('COD Battle Royale', 'cod_mobile', 120, 16),
            ('eFootball Online Match', 'efootball', 80, 8),
            ('PES myClub Tournament', 'pes', 90, 8),
        ]
        
        import random
        tournament = random.choice(tournaments)
        
        c.execute('''INSERT INTO tournaments (name, game, entry_fee, max_players, prize_pool, status)
                     VALUES (?, ?, ?, ?, ?, ?)''', 
                 (tournament[0], tournament[1], tournament[2], tournament[3], 0, 'open'))
        
        conn.commit()
        flash(f'New tournament created: {tournament[0]}', 'success')
    
    conn.close()
    return 'Tournament created'

@app.route('/init_db')
def init_db():
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Add missing columns to users table
    try:
        c.execute('ALTER TABLE users ADD COLUMN phone TEXT')
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute('ALTER TABLE users ADD COLUMN wins INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute('ALTER TABLE users ADD COLUMN losses INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute('ALTER TABLE users ADD COLUMN total_earnings REAL DEFAULT 0.0')
    except sqlite3.OperationalError:
        pass
    
    # Create new tables
    c.execute('''CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        friend_id INTEGER,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (friend_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS match_chat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER,
        user_id INTEGER,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (match_id) REFERENCES matches (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Drop and recreate match_results table to fix column issues
    c.execute('DROP TABLE IF EXISTS match_results')
    c.execute('''CREATE TABLE match_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER,
        submitter_id INTEGER,
        claimed_result TEXT,
        screenshot TEXT,
        ai_analysis TEXT,
        status TEXT DEFAULT 'pending_verification',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (match_id) REFERENCES matches (id),
        FOREIGN KEY (submitter_id) REFERENCES users (id)
    )''')
    
    # Add lobby_code column to matches table
    try:
        c.execute('ALTER TABLE matches ADD COLUMN lobby_code TEXT')
    except sqlite3.OperationalError:
        pass
    
    # Create withdrawals table
    c.execute('''CREATE TABLE IF NOT EXISTS withdrawals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount REAL,
        mpesa_number TEXT,
        status TEXT DEFAULT 'pending',
        payment_proof TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Create match confirmations table
    c.execute('''CREATE TABLE IF NOT EXISTS match_confirmations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER,
        player_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (match_id) REFERENCES matches (id),
        FOREIGN KEY (player_id) REFERENCES users (id),
        UNIQUE(match_id, player_id)
    )''')
    
    # Create tournaments table
    c.execute('''CREATE TABLE IF NOT EXISTS tournaments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        game TEXT,
        entry_fee REAL,
        max_players INTEGER,
        prize_pool REAL,
        status TEXT DEFAULT 'open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Create tournament participants table
    c.execute('''CREATE TABLE IF NOT EXISTS tournament_participants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tournament_id INTEGER,
        user_id INTEGER,
        position INTEGER,
        prize_won REAL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tournament_id) REFERENCES tournaments (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Create support escalations table
    c.execute('''CREATE TABLE IF NOT EXISTS support_escalations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        message TEXT,
        status TEXT DEFAULT 'pending',
        admin_response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Add referral system columns
    try:
        c.execute('ALTER TABLE users ADD COLUMN referral_code TEXT UNIQUE')
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute('ALTER TABLE users ADD COLUMN referred_by INTEGER')
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute('ALTER TABLE users ADD COLUMN referral_earnings REAL DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    
    # Add payment_proof column if it doesn't exist
    try:
        c.execute('ALTER TABLE withdrawals ADD COLUMN payment_proof TEXT')
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    conn.close()
    
    return 'Database updated successfully!'

@app.route('/admin/resolve_dispute/<int:match_id>/<winner>')
def resolve_dispute(match_id, winner):
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    c.execute('SELECT player1_id, player2_id, bet_amount FROM matches WHERE id = ?', (match_id,))
    match = c.fetchone()
    
    if match:
        player1_id, player2_id, bet_amount = match
        
        if winner == 'player1':
            winner_id, loser_id = player1_id, player2_id
            winnings = bet_amount * 1.68
            c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1, total_earnings = total_earnings + ? WHERE id = ?', 
                     (winnings, winnings, winner_id))
            c.execute('UPDATE users SET losses = losses + 1 WHERE id = ?', (loser_id,))
            c.execute('UPDATE matches SET winner_id = ?, status = "completed" WHERE id = ?', (winner_id, match_id))
            flash('Dispute resolved - Player 1 wins!', 'success')
        elif winner == 'player2':
            winner_id, loser_id = player2_id, player1_id
            winnings = bet_amount * 1.68
            c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1, total_earnings = total_earnings + ? WHERE id = ?', 
                     (winnings, winnings, winner_id))
            c.execute('UPDATE users SET losses = losses + 1 WHERE id = ?', (loser_id,))
            c.execute('UPDATE matches SET winner_id = ?, status = "completed" WHERE id = ?', (winner_id, match_id))
            flash('Dispute resolved - Player 2 wins!', 'success')
        else:  # draw/refund
            c.execute('UPDATE users SET balance = balance + ? WHERE id IN (?, ?)', (bet_amount, player1_id, player2_id))
            c.execute('UPDATE matches SET status = "refunded" WHERE id = ?', (match_id,))
            flash('Dispute resolved - Both players refunded!', 'success')
        
        c.execute('UPDATE match_results SET status = "resolved" WHERE match_id = ?', (match_id,))
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)