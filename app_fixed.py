@app.route('/api/user_balance')
@login_required
def api_user_balance():
    """API endpoint to get current user balance"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
            result = c.fetchone()
            
            if result:
                balance = result[0]
                session['balance'] = balance  # Update session
                return jsonify({'success': True, 'balance': f'{balance:.0f}'})
            else:
                return jsonify({'error': 'User not found'}), 404
                
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/user_stats')
@login_required  
def api_user_stats():
    """API endpoint to get current user stats"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Get updated user data
            c.execute('SELECT balance, wins, losses, total_earnings FROM users WHERE id = ?', (user_id,))
            user_data = c.fetchone()
            
            if user_data:
                return jsonify({
                    'success': True,
                    'balance': user_data[0],
                    'wins': user_data[1] or 0,
                    'losses': user_data[2] or 0,
                    'earnings': user_data[3] or 0
                })
            else:
                return jsonify({'error': 'User not found'}), 404
                
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)