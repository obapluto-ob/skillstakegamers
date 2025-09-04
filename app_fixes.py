# Fix for duplicate send_gift function and missing functionality

# Remove the duplicate send_gift function around line 3800+ and replace with this:

@app.route('/send_gift', methods=['POST'])
@login_required
def send_gift():
    """Send virtual gift to streamer"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        stream_id = data.get('stream_id')
        gift_type = data.get('gift_type', 'heart')
        amount = data.get('amount', 1)
        
        if not stream_id:
            return jsonify({'error': 'Stream ID required'}), 400
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Get stream info
            c.execute('SELECT user_id, status FROM streams WHERE id = ?', (stream_id,))
            stream = c.fetchone()
            
            if not stream:
                return jsonify({'error': 'Stream not found'}), 404
            
            streamer_id, status = stream
            
            if status != 'live':
                return jsonify({'error': 'Stream is not live'}), 400
            
            if streamer_id == session['user_id']:
                return jsonify({'error': 'Cannot send gift to yourself'}), 400
            
            # Gift costs (in KSh)
            gift_costs = {
                'heart': 5,
                'star': 10,
                'diamond': 25,
                'crown': 50,
                'rocket': 100
            }
            
            cost = gift_costs.get(gift_type, 5) * amount
            
            # Check sender balance
            c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
            sender_balance = c.fetchone()[0]
            
            if sender_balance < cost:
                return jsonify({'error': f'Insufficient balance. Need KSh {cost}'}), 400
            
            # Process gift transaction
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (cost, session['user_id']))
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (cost * 0.7, streamer_id))  # 70% to streamer
            
            # Record transactions
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (session['user_id'], 'gift_sent', -cost, f'Sent {amount}x {gift_type} to stream #{stream_id}'))
            
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (streamer_id, 'gift_received', cost * 0.7, f'Received {amount}x {gift_type} from {session["username"]}'))
            
            # Admin commission (30%)
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (1, 'gift_commission', cost * 0.3, f'Commission from gift - Stream #{stream_id}'))
            
            # Store gift in chat for display
            gift_message = f"🎁 {session['username']} sent {amount}x {gift_type} (KSh {cost})"
            c.execute('INSERT INTO stream_chat (stream_id, user_id, username, message) VALUES (?, ?, ?, ?)',
                     (stream_id, session['user_id'], 'SYSTEM', gift_message))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': f'Sent {amount}x {gift_type}!',
                'cost': cost,
                'new_balance': sender_balance - cost
            })
            
    except Exception as e:
        return jsonify({'error': f'Gift sending failed: {str(e)}'}), 500

# Enhanced chat with mentions
@app.route('/send_stream_chat', methods=['POST'])
@login_required
def send_stream_chat():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        stream_id = data.get('stream_id')
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'error': 'Empty message'}), 400
        
        # Process mentions (@username)
        import re
        mentions = re.findall(r'@(\w+)', message)
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Verify mentioned users exist
            for mention in mentions:
                c.execute('SELECT id FROM users WHERE username = ?', (mention,))
                if not c.fetchone():
                    message = message.replace(f'@{mention}', f'@{mention}(not found)')
            
            c.execute('''CREATE TABLE IF NOT EXISTS stream_chat (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stream_id INTEGER,
                user_id INTEGER,
                username TEXT,
                message TEXT,
                mentions TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # Store mentions as JSON string
            mentions_json = ','.join(mentions) if mentions else ''
            
            c.execute('INSERT INTO stream_chat (stream_id, user_id, username, message, mentions) VALUES (?, ?, ?, ?, ?)',
                     (stream_id, session['user_id'], session['username'], message, mentions_json))
            
            conn.commit()
            return jsonify({'success': True, 'message': 'Message sent'})
        
    except Exception as e:
        return jsonify({'error': f'Failed to send message: {str(e)}'}), 500

# Enhanced chat retrieval with mention highlighting
@app.route('/get_stream_chat/<int:stream_id>')
def get_stream_chat(stream_id):
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
        c.execute('SELECT username, message, created_at, mentions FROM stream_chat WHERE stream_id = ? ORDER BY created_at DESC LIMIT 50', (stream_id,))
        messages = c.fetchall()
        
        formatted_messages = []
        for m in reversed(messages):
            username, message, time, mentions = m
            
            # Highlight mentions in message
            if mentions:
                mention_list = mentions.split(',')
                for mention in mention_list:
                    if mention.strip():
                        message = message.replace(f'@{mention}', f'<span class="mention">@{mention}</span>')
            
            formatted_messages.append({
                'username': username,
                'message': message,
                'time': time,
                'has_mentions': bool(mentions)
            })
        
        return jsonify({'messages': formatted_messages})
    except:
        return jsonify({'messages': []})

# Add missing logout route (you have duplicate)
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

# Add favicon route to fix 404 error
@app.route('/favicon.ico')
def favicon():
    return '', 404