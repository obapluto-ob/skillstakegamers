# Fix duplicate routes and add unique features properly

# 1. REMOVE these duplicate routes from your app.py:
# - Any route that says @app.route('/check_payment_status/<payment_id>')
# - Any route that says @app.route('/admin/game_matches')

# 2. ADD these routes to the END of app.py (before if __name__ == '__main__':)

FIXED_ROUTES = '''
# UNIQUE SKILLSTAKE FEATURES - ADD THESE TO END OF APP.PY
@app.route('/unique_dashboard')
@login_required
def unique_dashboard():
    return render_template('unique_dashboard.html')

@app.route('/claim_daily_bonus', methods=['POST'])
@login_required
def claim_daily_bonus():
    try:
        user_id = session['user_id']
        bonus_amount = 75  # Fixed bonus for testing
        
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

print("STEP 1: Remove duplicate routes from app.py")
print("STEP 2: Add these routes to END of app.py:")
print(FIXED_ROUTES)
print("\nSTEP 3: Add this button to your dashboard template:")
print('<a href="/unique_dashboard" style="background:#00ff88;color:#000;padding:12px 24px;text-decoration:none;border-radius:8px;font-weight:600;margin:10px;">Unique Features</a>')
print("\nSTEP 4: Restart Flask app")
print("STEP 5: Login and click 'Unique Features' button")