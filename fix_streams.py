import sqlite3

# Connect to database
conn = sqlite3.connect('gamebet.db')
c = conn.cursor()

# Check for phantom streams
print("=== CHECKING PHANTOM STREAMS ===")
c.execute('SELECT * FROM streams WHERE status IN ("live", "pending")')
streams = c.fetchall()
print(f"Found {len(streams)} active streams:")
for stream in streams:
    print(f"Stream ID: {stream[0]}, User: {stream[1]}, Status: {stream[6]}, Title: {stream[4]}")

# Clean up phantom streams
print("\n=== CLEANING PHANTOM STREAMS ===")
c.execute('UPDATE streams SET status = "ended" WHERE status IN ("live", "pending")')
cleaned = c.rowcount
print(f"Cleaned {cleaned} phantom streams")

# Check admin controls
print("\n=== ADMIN STREAM CONTROLS ===")
c.execute('SELECT COUNT(*) FROM streams')
total_streams = c.fetchone()[0]
print(f"Total streams in database: {total_streams}")

# Add admin stream control route
print("\n=== ADDING ADMIN CONTROLS ===")
admin_controls = """
# Add to app.py after other admin routes

@app.route('/admin/force_end_stream/<int:stream_id>', methods=['POST'])
def admin_force_end_stream(stream_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Force end stream and clean up
    c.execute('UPDATE streams SET status = "ended" WHERE id = ?', (stream_id,))
    c.execute('DELETE FROM stream_viewers WHERE stream_id = ?', (stream_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Stream forcefully ended'})

@app.route('/admin/clean_all_streams', methods=['POST'])
def admin_clean_all_streams():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # End all active streams
    c.execute('UPDATE streams SET status = "ended" WHERE status IN ("live", "pending")')
    cleaned = c.rowcount
    
    # Clean viewers
    c.execute('DELETE FROM stream_viewers')
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': f'Cleaned {cleaned} streams'})
"""

print("Admin controls code generated - add to app.py")

conn.commit()
conn.close()
print("\n=== CLEANUP COMPLETE ===")