from flask import Blueprint, jsonify, session
import sqlite3

admin_bp = Blueprint('admin_clear', __name__)

@admin_bp.route('/admin/clear_rate_limits', methods=['POST'])
def admin_clear_rate_limits():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        c.execute('DELETE FROM rate_limit_tracking')
        conn.commit()
    
    return jsonify({'success': True, 'message': 'All rate limits cleared'})