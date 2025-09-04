import re

# Read the app.py file
with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find and replace the broken send_stream_chat function
old_pattern = r"@app\.route\('/send_stream_chat', methods=\['POST'\]\)\ndef send_stream_chat\(\):.*?except Exception as e:\s+flash\(\.\.\."

new_function = '''@app.route('/send_stream_chat', methods=['POST'])
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
        return jsonify({'error': 'Failed to send message'}), 500'''

# Replace the broken function
content = re.sub(old_pattern, new_function, content, flags=re.DOTALL)

# Write back to file
with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed stream chat function")