# Fix duplicate routes in app.py
import re

def fix_app_file():
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Remove duplicate check_payment_status route (keep only first occurrence)
    pattern1 = r"@app\.route\('/check_payment_status/<payment_id>'\).*?return jsonify\(\{'completed': bool\(completed\)\}\)"
    matches1 = list(re.finditer(pattern1, content, re.DOTALL))
    if len(matches1) > 1:
        # Remove all but the first occurrence
        for match in reversed(matches1[1:]):
            content = content[:match.start()] + content[match.end():]
    
    # Remove duplicate admin_game_matches route (keep only first occurrence)  
    pattern2 = r"@app\.route\('/admin/game_matches'\).*?return f'<h1>Game Matches</h1><p>Error: \{str\(e\)\}</p><a href=\"/admin_dashboard\">Back</a>'"
    matches2 = list(re.finditer(pattern2, content, re.DOTALL))
    if len(matches2) > 1:
        # Remove all but the first occurrence
        for match in reversed(matches2[1:]):
            content = content[:match.start()] + content[match.end():]
    
    # Add unique features before if __name__ == '__main__':
    unique_features = '''
# UNIQUE SKILLSTAKE FEATURES
@app.route('/unique_dashboard')
@login_required
def unique_dashboard():
    return render_template('unique_dashboard.html')

@app.route('/claim_daily_bonus', methods=['POST'])
@login_required
def claim_daily_bonus():
    try:
        user_id = session['user_id']
        bonus_amount = 75
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bonus_amount, user_id))
            c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                     (user_id, 'daily_bonus', bonus_amount, f'Daily bonus: KSh {bonus_amount}'))
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            session['balance'] = c.fetchone()[0]
            conn.commit()
            
        return jsonify({'success': True, 'message': f'Bonus claimed: KSh {bonus_amount}!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

'''
    
    # Insert unique features before if __name__ == '__main__':
    if "if __name__ == '__main__':" in content and unique_features.strip() not in content:
        content = content.replace("if __name__ == '__main__':", unique_features + "if __name__ == '__main__':")
    
    # Write fixed content back
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("Fixed duplicate routes and added unique features!")

if __name__ == "__main__":
    fix_app_file()