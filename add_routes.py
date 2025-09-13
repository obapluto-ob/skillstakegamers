# Add unique feature routes to main app
import sqlite3
from datetime import datetime
import random

def get_db_connection():
    return sqlite3.connect('gamebet.db')

# Add these routes to your app.py file

ROUTES_TO_ADD = '''

# UNIQUE SKILLSTAKE FEATURES ROUTES

@app.route('/unique_dashboard')
@login_required
def unique_dashboard():
    return render_template('unique_dashboard.html')

@app.route('/claim_daily_bonus', methods=['POST'])
@login_required
def claim_daily_bonus():
    try:
        user_id = session['user_id']
        today = datetime.now().date()
        
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Check if already claimed today
            c.execute('''SELECT * FROM transactions WHERE user_id = ? AND type = 'daily_bonus' 
                       AND DATE(created_at) = ?''', (user_id, today))
            
            if c.fetchone():
                return jsonify({'success': False, 'message': 'Daily bonus already claimed today!'})
            
            # Award bonus
            bonus_amount = random.randint(50, 100)
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bonus_amount, user_id))
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                       VALUES (?, ?, ?, ?)''',
                     (user_id, 'daily_bonus', bonus_amount, f'Daily login bonus: KSh {bonus_amount}'))
            
            # Award skill tokens
            c.execute('''INSERT INTO skill_tokens (user_id, token_type, amount, source) 
                       VALUES (?, ?, ?, ?)''', (user_id, 'daily', 10, 'daily_login'))
            
            # Update session balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            session['balance'] = c.fetchone()[0]
            
            conn.commit()
            return jsonify({'success': True, 'message': f'Daily bonus claimed: KSh {bonus_amount} + 10 tokens!'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/buy_insurance/<int:match_id>', methods=['POST'])
@login_required
def buy_insurance(match_id):
    try:
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Check user balance
            if session.get('balance', 0) < 50:
                return jsonify({'success': False, 'message': 'Insufficient balance for insurance'})
            
            # Deduct insurance fee
            c.execute('UPDATE users SET balance = balance - 50 WHERE id = ?', (user_id,))
            
            # Add insurance record
            c.execute('''INSERT INTO skill_insurance (match_id, user_id, insurance_fee) 
                       VALUES (?, ?, 50)''', (match_id, user_id))
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                       VALUES (?, ?, ?, ?)''',
                     (user_id, 'insurance_fee', -50, f'Skill Insurance for Match #{match_id}'))
            
            # Update session balance
            session['balance'] = session.get('balance', 0) - 50
            
            conn.commit()
            return jsonify({'success': True, 'message': 'Insurance purchased! Get 50% back if you lose by 1 goal only'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/user_stats_unique')
@login_required
def user_stats_unique():
    try:
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get skill rating
            c.execute('SELECT * FROM skill_ratings WHERE user_id = ?', (user_id,))
            rating = c.fetchone()
            
            # Get skill tokens
            c.execute('''SELECT token_type, SUM(amount) FROM skill_tokens 
                       WHERE user_id = ? GROUP BY token_type''', (user_id,))
            tokens = dict(c.fetchall())
            
            # Get insurance history
            c.execute('''SELECT COUNT(*), SUM(insurance_fee) FROM skill_insurance 
                       WHERE user_id = ?''', (user_id,))
            insurance_stats = c.fetchone()
            
            # Get daily bonus streak
            c.execute('''SELECT COUNT(*) FROM transactions 
                       WHERE user_id = ? AND type = 'daily_bonus' 
                       AND created_at >= date('now', '-7 days')''', (user_id,))
            weekly_bonuses = c.fetchone()[0]
            
            return jsonify({
                'success': True,
                'rating': rating,
                'tokens': tokens,
                'insurance_bought': insurance_stats[0] or 0,
                'insurance_spent': insurance_stats[1] or 0,
                'weekly_bonuses': weekly_bonuses,
                'balance': session.get('balance', 0)
            })
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

'''

print("COPY AND PASTE THESE ROUTES TO YOUR app.py FILE:")
print("=" * 60)
print(ROUTES_TO_ADD)
print("=" * 60)
print("THEN ADD THIS LINK TO YOUR DASHBOARD:")
print('<a href="/unique_dashboard" class="btn">🚀 Unique Features</a>')