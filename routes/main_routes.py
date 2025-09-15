from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from database_manager import db_manager
from database import get_db_connection

main_bp = Blueprint('main', __name__)

def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@main_bp.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('main.dashboard'))
    return render_template('home.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            c.execute('SELECT id, username, balance FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            
            if not user:
                session.clear()
                flash('User not found. Please login again.', 'error')
                return redirect(url_for('auth.login'))
            
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
        return redirect(url_for('auth.login'))

@main_bp.route('/profile')
@login_required
def profile():
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT username, email, phone, balance, created_at FROM users WHERE id = ?', (session['user_id'],))
            user = c.fetchone()
            return render_template('profile.html', user=user)
    except:
        return render_template('profile.html', user=None)

@main_bp.route('/leaderboard')
@login_required
def leaderboard():
    return render_template('leaderboard.html')

@main_bp.route('/friends')
@login_required
def friends():
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT id, username, phone FROM users WHERE id != ? AND username != "admin"', (session['user_id'],))
            all_users = c.fetchall()
        return render_template('friends.html', all_users=all_users, friends=[], requests=[])
    except:
        return render_template('friends.html', all_users=[], friends=[], requests=[])

@main_bp.route('/referrals')
@login_required
def referrals():
    try:
        with db_manager.get_connection() as conn:
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

@main_bp.route('/match_history')
@login_required
def match_history():
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM game_matches WHERE creator_id = ? OR opponent_id = ? ORDER BY created_at DESC LIMIT 20', 
                     (session['user_id'], session['user_id']))
            matches = c.fetchall()
            
            c.execute('SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', (session['user_id'],))
            transactions = c.fetchall()
            
        return render_template('match_history.html', matches=matches, transactions=transactions, withdrawals=[])
    except:
        return render_template('match_history.html', matches=[], transactions=[], withdrawals=[])

@main_bp.route('/support_chat')
@login_required
def support_chat():
    return render_template('support_chat.html')

@main_bp.route('/user_bonuses_page')
@login_required
def user_bonuses_page():
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM transactions WHERE user_id = ? AND type = "daily_bonus" ORDER BY created_at DESC LIMIT 10', (session['user_id'],))
            bonus_history = c.fetchall()
        return render_template('user_bonuses.html', bonus_history=bonus_history, can_claim_today=True)
    except:
        return render_template('user_bonuses.html', bonus_history=[], can_claim_today=True)

@main_bp.route('/claim_bonus', methods=['POST'])
@login_required
def claim_bonus():
    # Add 75 KSh to user balance
    try:
        with db_manager.get_connection() as conn:
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
    return redirect(url_for('main.user_bonuses_page'))

@main_bp.route('/api/daily_bonus_status')
@login_required
def daily_bonus_status():
    return jsonify({'can_claim': True, 'next_claim': 'tomorrow'})

@main_bp.route('/api/user_balance')
@login_required
def api_user_balance():
    return jsonify({'balance': session.get('balance', 0), 'username': session.get('username', 'User')})