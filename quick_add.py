# Quick way to add unique features to your app

# 1. ADD THIS TO YOUR DASHBOARD TEMPLATE:
dashboard_link = '''
<a href="/unique_dashboard" style="background: linear-gradient(135deg, #00ff88, #00cc6a); color: #000; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: 600; margin: 10px;">
    🚀 Unique Features
</a>
'''

# 2. ADD THESE ROUTES TO THE END OF YOUR app.py FILE:
routes_code = '''
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
            c.execute("SELECT * FROM transactions WHERE user_id = ? AND type = 'daily_bonus' AND DATE(created_at) = ?", (user_id, today))
            
            if c.fetchone():
                return jsonify({'success': False, 'message': 'Daily bonus already claimed today!'})
            
            # Award bonus
            bonus_amount = random.randint(50, 100)
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bonus_amount, user_id))
            
            # Record transaction
            c.execute("INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)",
                     (user_id, 'daily_bonus', bonus_amount, f'Daily login bonus: KSh {bonus_amount}'))
            
            # Update session balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            session['balance'] = c.fetchone()[0]
            
            conn.commit()
            return jsonify({'success': True, 'message': f'Daily bonus claimed: KSh {bonus_amount}!'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})
'''

print("STEP 1: Add this link to your dashboard template:")
print(dashboard_link)
print("\nSTEP 2: Add these routes to the end of your app.py file:")
print(routes_code)
print("\nSTEP 3: Visit /unique_dashboard to see the new features!")
print("\nSTEP 4: Test daily bonus - users get KSh 50-100 every day!")