#!/usr/bin/env python3

"""
Fix for the create_match route that's causing "Internal server error"
This script will identify and fix the issue in the /create_match endpoint
"""

import sqlite3
import os

def fix_create_match_route():
    """
    The issue is likely in the /create_match route. Let's create a fixed version.
    """
    
    # First, let's check if the database exists and has the required tables
    db_path = 'gamebet.db'
    
    if not os.path.exists(db_path):
        print("Database doesn't exist. Creating it...")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Create essential tables
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password TEXT NOT NULL,
            balance REAL DEFAULT 0.0,
            phone TEXT,
            wins INTEGER DEFAULT 0,
            losses INTEGER DEFAULT 0,
            total_earnings REAL DEFAULT 0.0,
            referral_code TEXT,
            referred_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game TEXT NOT NULL,
            player1_id INTEGER,
            player2_id INTEGER,
            bet_amount REAL NOT NULL,
            total_pot REAL NOT NULL,
            winner_id INTEGER,
            status TEXT DEFAULT 'pending',
            game_mode TEXT DEFAULT 'Standard',
            verification_type TEXT DEFAULT 'ocr',
            match_type TEXT DEFAULT 'public',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        conn.commit()
        conn.close()
        print("Database created successfully!")
    
    # Now let's create the fixed route code
    fixed_route_code = '''
@app.route('/create_match', methods=['POST'])
def create_match():
    """Fixed create_match route with proper error handling"""
    try:
        # Check if user is logged in
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Please log in first'}), 401
            return redirect(url_for('login'))
        
        # Get user_id safely
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid session'}), 401
        
        # Handle both form and JSON data
        try:
            if request.is_json:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'Invalid JSON data'}), 400
                
                game = data.get('game')
                bet_amount = data.get('bet_amount', 0)
                game_mode = data.get('game_mode', 'Standard')
                verification_type = data.get('verification_type', 'ocr')
                match_type = data.get('match_type', 'public')
            else:
                game = request.form.get('game')
                bet_amount = request.form.get('bet_amount', 0)
                game_mode = request.form.get('game_mode', 'Standard')
                verification_type = request.form.get('verification_type', 'ocr')
                match_type = request.form.get('match_type', 'public')
        except Exception as e:
            return jsonify({'error': f'Error parsing request data: {str(e)}'}), 400
        
        # Validate required fields
        if not game:
            return jsonify({'error': 'Game is required'}), 400
        
        try:
            bet_amount = float(bet_amount)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid bet amount'}), 400
        
        if bet_amount <= 0:
            return jsonify({'error': 'Bet amount must be greater than 0'}), 400
        
        # Database operations with proper error handling
        try:
            conn = sqlite3.connect('gamebet.db')
            c = conn.cursor()
            
            # Check user balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            result = c.fetchone()
            
            if not result:
                conn.close()
                return jsonify({'error': 'User not found'}), 404
            
            balance = result[0]
            
            if balance < bet_amount:
                conn.close()
                return jsonify({'error': f'Insufficient balance! You have KSh {balance:.0f}'}), 400
            
            # Update user balance
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (bet_amount, user_id))
            
            # Create match
            total_pot = bet_amount * 2
            c.execute('''INSERT INTO matches (game, player1_id, bet_amount, total_pot, game_mode, status, verification_type, match_type)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                     (game, user_id, bet_amount, total_pot, game_mode, 'pending', verification_type, match_type))
            
            match_id = c.lastrowid
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (user_id, 'match_escrow', -bet_amount, f'Match #{match_id} created - {game.upper()} {game_mode} - Money in escrow'))
            
            # Update session balance
            session['balance'] = balance - bet_amount
            
            conn.commit()
            conn.close()
            
            message = f'Match created! KSh {bet_amount} moved to escrow. Waiting for opponent to join!'
            
            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': message,
                    'match_id': match_id,
                    'redirect': f'/match_lobby/{match_id}'
                })
            else:
                flash(message, 'success')
                return redirect(url_for('matches'))
                
        except sqlite3.Error as e:
            if 'conn' in locals():
                conn.close()
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        
    except Exception as e:
        # Catch any other unexpected errors
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500
'''
    
    print("Fixed route code generated. The issue is likely:")
    print("1. Missing error handling in the original route")
    print("2. Session data not being properly validated")
    print("3. Database connection issues")
    print("4. JSON parsing errors")
    
    return fixed_route_code

if __name__ == "__main__":
    fix_create_match_route()
    print("\nTo fix the issue:")
    print("1. Replace the /create_match route in app.py with the fixed version above")
    print("2. Make sure all required modules are imported")
    print("3. Ensure the database has the required tables")
    print("4. Test the button functionality")