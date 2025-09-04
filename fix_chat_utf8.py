# Simple fix for stream chat with UTF-8 encoding
with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the broken function and replace it
broken_start = content.find("@app.route('/send_stream_chat', methods=['POST'])")
if broken_start != -1:
    # Find the end of the function (next @app.route)
    next_route = content.find("@app.route", broken_start + 10)
    if next_route == -1:
        next_route = len(content)
    
    # Replace with fixed function
    fixed_function = """@app.route('/send_stream_chat', methods=['POST'])
def send_stream_chat():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        stream_id = data.get('stream_id')
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'error': 'Empty message'}), 400
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            c.execute('''CREATE TABLE IF NOT EXISTS stream_chat (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stream_id INTEGER,
                user_id INTEGER,
                username TEXT,
                message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            c.execute('INSERT INTO stream_chat (stream_id, user_id, username, message) VALUES (?, ?, ?, ?)',
                     (stream_id, session['user_id'], session['username'], message))
            
            conn.commit()
            return jsonify({'success': True, 'message': 'Message sent'})
        
    except Exception as e:
        return jsonify({'error': 'Failed to send message'}), 500

"""
    
    new_content = content[:broken_start] + fixed_function + content[next_route:]
    
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print("Stream chat function fixed!")
else:
    print("Function not found")