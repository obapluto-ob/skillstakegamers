# Add unique features routes to app.py with proper encoding
with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Check if routes already exist
if 'get_skill_rating' in content:
    print("Routes already exist")
    exit()

# Add new routes before the last function
new_routes = '''
@app.route('/unique_dashboard')
@login_required
def unique_dashboard():
    """Show unique features dashboard"""
    return render_template('unique_dashboard.html')

@app.route('/get_skill_rating')
@login_required
def get_skill_rating():
    try:
        user_id = session['user_id']
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM skill_ratings WHERE user_id = ?', (user_id,))
            rating = c.fetchone()
            if not rating:
                c.execute('INSERT INTO skill_ratings (user_id, rating, wins, losses, draws) VALUES (?, ?, ?, ?, ?)', (user_id, 1000, 0, 0, 0))
                conn.commit()
                rating = (None, user_id, 1000, 0, 0, 0, None)
            return jsonify({'success': True, 'rating': rating[2], 'wins': rating[3], 'losses': rating[4], 'draws': rating[5]})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/earn_skill_tokens', methods=['POST'])
@login_required
def earn_skill_tokens():
    try:
        user_id = session['user_id']
        tokens_earned = 10
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT token_balance FROM skill_tokens WHERE user_id = ?', (user_id,))
            result = c.fetchone()
            if result:
                c.execute('UPDATE skill_tokens SET token_balance = token_balance + ? WHERE user_id = ?', (tokens_earned, user_id))
                total = result[0] + tokens_earned
            else:
                c.execute('INSERT INTO skill_tokens (user_id, token_balance) VALUES (?, ?)', (user_id, tokens_earned))
                total = tokens_earned
            conn.commit()
        return jsonify({'success': True, 'message': f'Earned {tokens_earned} tokens!', 'total_tokens': total})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/get_live_matches')
@login_required
def get_live_matches():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT m.id, u1.username, u2.username, m.bet_amount FROM matches m JOIN users u1 ON m.player1_id = u1.id JOIN users u2 ON m.player2_id = u2.id WHERE m.status = 'active' LIMIT 5")
            matches = [{'id': m[0], 'player1': m[1], 'player2': m[2], 'bet_amount': m[3]} for m in c.fetchall()]
        return jsonify({'success': True, 'matches': matches})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/buy_skill_insurance', methods=['POST'])
@login_required
def buy_skill_insurance():
    try:
        data = request.get_json()
        match_id = data.get('match_id')
        insurance_cost = 50
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            balance = c.fetchone()[0]
            
            if balance < insurance_cost:
                return jsonify({'success': False, 'message': 'Insufficient balance for insurance'})
            
            c.execute('SELECT id FROM skill_insurance WHERE user_id = ? AND match_id = ?', (user_id, match_id))
            if c.fetchone():
                return jsonify({'success': False, 'message': 'Insurance already purchased for this match'})
            
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (insurance_cost, user_id))
            c.execute('INSERT INTO skill_insurance (user_id, match_id, insurance_cost, coverage_amount) VALUES (?, ?, ?, ?)', 
                     (user_id, match_id, insurance_cost, insurance_cost))
            c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                     (user_id, 'insurance_purchase', -insurance_cost, f'Skill insurance for match #{match_id}'))
            
            session['balance'] = balance - insurance_cost
            conn.commit()
            
        return jsonify({'success': True, 'message': 'Skill insurance purchased successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/create_revenge_match', methods=['POST'])
@login_required
def create_revenge_match():
    try:
        data = request.get_json()
        opponent_id = data.get('opponent_id')
        original_match_id = data.get('original_match_id')
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT bet_amount FROM matches WHERE id = ? AND (player1_id = ? OR player2_id = ?)', 
                     (original_match_id, user_id, user_id))
            match = c.fetchone()
            
            if not match:
                return jsonify({'success': False, 'message': 'Original match not found'})
            
            revenge_bet = int(match[0] * 1.5)
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            balance = c.fetchone()[0]
            
            if balance < revenge_bet:
                return jsonify({'success': False, 'message': f'Need KSh {revenge_bet} for revenge match'})
            
            c.execute('INSERT INTO revenge_matches (challenger_id, opponent_id, original_match_id, revenge_bet, status) VALUES (?, ?, ?, ?, ?)',
                     (user_id, opponent_id, original_match_id, revenge_bet, 'pending'))
            conn.commit()
            
        return jsonify({'success': True, 'message': f'Revenge match created! Bet: KSh {revenge_bet}'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/place_live_bet', methods=['POST'])
@login_required
def place_live_bet():
    try:
        data = request.get_json()
        match_id = data.get('match_id')
        bet_amount = float(data.get('bet_amount'))
        predicted_winner = data.get('predicted_winner')
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            balance = c.fetchone()[0]
            
            if balance < bet_amount:
                return jsonify({'success': False, 'message': 'Insufficient balance'})
            
            c.execute('SELECT status FROM matches WHERE id = ?', (match_id,))
            match = c.fetchone()
            
            if not match or match[0] != 'active':
                return jsonify({'success': False, 'message': 'Match not available for betting'})
            
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (bet_amount, user_id))
            c.execute('INSERT INTO live_bets (user_id, match_id, bet_amount, predicted_winner, status) VALUES (?, ?, ?, ?, ?)',
                     (user_id, match_id, bet_amount, predicted_winner, 'active'))
            c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                     (user_id, 'live_bet', -bet_amount, f'Live bet on match #{match_id}'))
            
            session['balance'] = balance - bet_amount
            conn.commit()
            
        return jsonify({'success': True, 'message': f'Live bet of KSh {bet_amount} placed successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

'''

# Find position to insert (before if __name__)
pos = content.rfind('if __name__')
if pos == -1:
    pos = len(content)

content = content[:pos] + new_routes + '\n' + content[pos:]

# Write back to app.py
with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Added all unique features routes to app.py")