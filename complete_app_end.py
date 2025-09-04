# Complete the truncated app.py file - add this to the end

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

# Add favicon route to prevent 404 errors
@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico') if os.path.exists('static/favicon.ico') else ('', 404)

# WebRTC signaling for real streaming
@app.route('/webrtc_offer', methods=['POST'])
def webrtc_offer():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    stream_id = data.get('stream_id')
    offer = data.get('offer')
    
    # Store offer for viewers to retrieve
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS webrtc_signals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stream_id INTEGER,
            user_id INTEGER,
            signal_type TEXT,
            signal_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        c.execute('INSERT INTO webrtc_signals (stream_id, user_id, signal_type, signal_data) VALUES (?, ?, ?, ?)',
                 (stream_id, session['user_id'], 'offer', str(offer)))
        conn.commit()
    
    return jsonify({'success': True})

@app.route('/webrtc_answer', methods=['POST'])
def webrtc_answer():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    stream_id = data.get('stream_id')
    answer = data.get('answer')
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        c.execute('INSERT INTO webrtc_signals (stream_id, user_id, signal_type, signal_data) VALUES (?, ?, ?, ?)',
                 (stream_id, session['user_id'], 'answer', str(answer)))
        conn.commit()
    
    return jsonify({'success': True})

@app.route('/get_webrtc_signals/<int:stream_id>')
def get_webrtc_signals(stream_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        c.execute('SELECT signal_type, signal_data FROM webrtc_signals WHERE stream_id = ? ORDER BY created_at DESC LIMIT 10',
                 (stream_id,))
        signals = c.fetchall()
    
    return jsonify({'signals': [{'type': s[0], 'data': s[1]} for s in signals]})

# Enhanced error handling
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# Health check endpoint
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'version': '1.0.0'
    })

# Database cleanup task
@app.route('/admin/cleanup_db')
@admin_required
def cleanup_database():
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        # Clean old WebRTC signals (older than 1 hour)
        c.execute("DELETE FROM webrtc_signals WHERE created_at < datetime('now', '-1 hour')")
        
        # Clean old stream chat (older than 7 days)
        c.execute("DELETE FROM stream_chat WHERE created_at < datetime('now', '-7 days')")
        
        # Clean ended streams older than 24 hours
        c.execute("DELETE FROM streams WHERE status = 'ended' AND created_at < datetime('now', '-1 day')")
        
        conn.commit()
    
    return jsonify({'success': True, 'message': 'Database cleaned'})

if __name__ == '__main__':
    # Initialize database on startup
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        # Ensure all required tables exist
        c.execute('''CREATE TABLE IF NOT EXISTS stream_chat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stream_id INTEGER,
            user_id INTEGER,
            username TEXT,
            message TEXT,
            mentions TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS webrtc_signals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stream_id INTEGER,
            user_id INTEGER,
            signal_type TEXT,
            signal_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        conn.commit()
    
    app.run(debug=True, host='0.0.0.0', port=5000)