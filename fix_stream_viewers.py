#!/usr/bin/env python3
"""
Fix the stream_viewers endpoint to allow basic viewer count for everyone
but detailed viewer info only for stream owners
"""

def fix_stream_viewers():
    """Modify the stream_viewers function to be more permissive"""
    
    print("Reading app.py...")
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find the stream_viewers function
    old_function = '''@app.route('/stream_viewers/<int:stream_id>')
def stream_viewers(stream_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Check if user owns the stream
    c.execute('SELECT user_id FROM streams WHERE id = ?', (stream_id,))
    stream = c.fetchone()
    
    if not stream or stream[0] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Not your stream'}), 403
    
    # Get current viewers
    c.execute('''SELECT username, joined_at FROM stream_viewers 
                 WHERE stream_id = ? ORDER BY joined_at DESC''', (stream_id,))
    viewers = c.fetchall()
    
    # Get viewer count
    c.execute('SELECT viewers FROM streams WHERE id = ?', (stream_id,))
    count = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'viewers': [{'username': v[0], 'joined_at': v[1]} for v in viewers],
        'count': count
    })'''
    
    # New function that allows basic viewer count for everyone
    new_function = '''@app.route('/stream_viewers/<int:stream_id>')
def stream_viewers(stream_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Check if stream exists
    c.execute('SELECT user_id FROM streams WHERE id = ?', (stream_id,))
    stream = c.fetchone()
    
    if not stream:
        conn.close()
        return jsonify({'error': 'Stream not found'}), 404
    
    # Get viewer count (available to everyone)
    c.execute('SELECT viewers FROM streams WHERE id = ?', (stream_id,))
    count_result = c.fetchone()
    count = count_result[0] if count_result else 0
    
    # Check if user owns the stream for detailed info
    is_owner = stream[0] == session['user_id']
    
    if is_owner:
        # Stream owner gets detailed viewer list
        c.execute('''SELECT username, joined_at FROM stream_viewers 
                     WHERE stream_id = ? ORDER BY joined_at DESC''', (stream_id,))
        viewers = c.fetchall()
        
        conn.close()
        return jsonify({
            'viewers': [{'username': v[0], 'joined_at': v[1]} for v in viewers],
            'count': count,
            'is_owner': True
        })
    else:
        # Non-owners only get viewer count
        conn.close()
        return jsonify({
            'viewers': [],
            'count': count,
            'is_owner': False,
            'message': 'Only stream owner can see detailed viewer list'
        })'''
    
    if old_function not in content:
        print("Could not find the exact stream_viewers function to replace")
        print("The function might have been modified. Please check manually.")
        return False
    
    # Replace the function
    new_content = content.replace(old_function, new_function)
    
    # Create backup
    print("Creating backup...")
    with open('app.py.stream_fix_backup', 'w', encoding='utf-8') as f:
        f.write(content)
    
    # Write the fixed content
    print("Writing fixed app.py...")
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print("SUCCESS: Fixed stream_viewers function!")
    print("- Everyone can now see viewer counts")
    print("- Only stream owners see detailed viewer lists")
    print("- No more 403 errors for basic viewer info")
    
    return True

def verify_fix():
    """Verify the fix worked"""
    print("\nVerifying fix...")
    
    try:
        import py_compile
        py_compile.compile('app.py', doraise=True)
        print("SUCCESS: app.py compiles without errors!")
        return True
    except Exception as e:
        print(f"ERROR: {e}")
        return False

if __name__ == '__main__':
    print("Stream Viewers 403 Error Fix")
    print("=" * 30)
    
    if fix_stream_viewers():
        if verify_fix():
            print("\nFIX COMPLETED!")
            print("Restart your app with: python app.py")
            print("The 403 errors should be resolved.")
        else:
            print("\nFix may have syntax issues.")
    else:
        print("\nFix failed. Check the function manually.")