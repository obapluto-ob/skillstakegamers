# Simple unique features that work
from flask import Flask, jsonify, session, render_template_string
import sqlite3

# Add these 2 routes to the END of your app.py file (before if __name__ == '__main__':)

SIMPLE_ROUTES = '''
@app.route('/unique_dashboard')
@login_required
def unique_dashboard():
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Unique Features</title>
    <style>
        body { font-family: Arial; background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        .card { background: rgba(255,255,255,0.1); padding: 20px; margin: 20px 0; border-radius: 10px; }
        .btn { background: #00ff88; color: #000; padding: 15px 30px; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; margin: 10px; }
        .btn:hover { background: #00cc6a; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 UNIQUE FEATURES</h1>
        <div class="card">
            <h3>🎁 Daily Bonus</h3>
            <p>Claim KSh 75 every day!</p>
            <button class="btn" onclick="claimBonus()">CLAIM NOW</button>
        </div>
        <div class="card">
            <h3>🛡️ More Features Coming Soon</h3>
            <p>Skill Insurance, Revenge Matches, Skill Tokens, and more!</p>
        </div>
        <a href="/dashboard" style="color: white;">← Back to Dashboard</a>
    </div>
    <script>
        function claimBonus() {
            fetch('/claim_daily_bonus', {method: 'POST'})
            .then(r => r.json())
            .then(d => {
                alert(d.message);
                if (d.success) location.reload();
            });
        }
    </script>
</body>
</html>
    """)

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

print("COPY AND PASTE THIS TO THE END OF YOUR app.py FILE:")
print("=" * 60)
print(SIMPLE_ROUTES)
print("=" * 60)
print("THEN RESTART YOUR FLASK APP!")
print("USERS WILL SEE:")
print("1. Dashboard has 'UNIQUE FEATURES' button")
print("2. Click it to see unique features page")
print("3. Click 'CLAIM NOW' to get KSh 75 instantly")
print("4. Balance updates immediately")
print("5. Transaction shows in wallet")