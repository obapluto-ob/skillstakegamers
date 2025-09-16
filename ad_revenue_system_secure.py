# Ad Revenue System for SkillStake Platform - Secure Version

import sqlite3
from flask import session, request, jsonify
from security_config import SecureDBConnection

def init_ad_tables():
    """Initialize ad revenue tracking tables with proper resource management"""
    with SecureDBConnection() as conn:
        c = conn.cursor()
        
        # Ad views tracking
        c.execute('''CREATE TABLE IF NOT EXISTS ad_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ad_type TEXT,
            ad_placement TEXT,
            revenue_per_view REAL,
            user_earnings REAL,
            platform_earnings REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Ad revenue settings
        c.execute('''CREATE TABLE IF NOT EXISTS ad_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ad_type TEXT UNIQUE,
            revenue_per_view REAL,
            user_share_percent REAL,
            platform_share_percent REAL
        )''')
        
        # Insert default ad settings
        ad_types = [
            ('banner', 0.50, 30.0, 70.0),
            ('video', 2.00, 40.0, 60.0),
            ('interstitial', 1.50, 35.0, 65.0),
            ('rewarded', 3.00, 50.0, 50.0)
        ]
        
        for ad_type, revenue, user_share, platform_share in ad_types:
            c.execute('''INSERT OR REPLACE INTO ad_settings 
                         (ad_type, revenue_per_view, user_share_percent, platform_share_percent)
                         VALUES (?, ?, ?, ?)''', (ad_type, revenue, user_share, platform_share))

def record_ad_view(user_id, ad_type, ad_placement):
    """Record ad view and calculate earnings with proper resource management"""
    with SecureDBConnection() as conn:
        c = conn.cursor()
        
        # Get ad settings
        c.execute('SELECT revenue_per_view, user_share_percent, platform_share_percent FROM ad_settings WHERE ad_type = ?', (ad_type,))
        settings = c.fetchone()
        
        if not settings:
            return False, 'Invalid ad type'
        
        revenue_per_view, user_share_percent, platform_share_percent = settings
        
        # Calculate earnings
        user_earnings = revenue_per_view * (user_share_percent / 100)
        platform_earnings = revenue_per_view * (platform_share_percent / 100)
        
        # Record ad view
        c.execute('''INSERT INTO ad_views 
                     (user_id, ad_type, ad_placement, revenue_per_view, user_earnings, platform_earnings)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 (user_id, ad_type, ad_placement, revenue_per_view, user_earnings, platform_earnings))
        
        # Add earnings to user balance
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (user_earnings, user_id))
        
        # Record user transaction
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (user_id, 'ad_earnings', user_earnings, 
                  f'{ad_type.title()} ad viewed - {ad_placement} - KSh {user_earnings:.2f} earned'))
        
        # Record admin revenue
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (1, 'ad_revenue', platform_earnings, 
                  f'{ad_type.title()} ad revenue - User {user_id} - KSh {platform_earnings:.2f}'))
        
        return True, user_earnings

def get_user_ad_stats(user_id):
    """Get user's ad viewing statistics with proper resource management"""
    with SecureDBConnection() as conn:
        c = conn.cursor()
        
        # Total ad earnings
        c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type = "ad_earnings"', (user_id,))
        total_earnings = c.fetchone()[0]
        
        # Ad views by type
        c.execute('''SELECT ad_type, COUNT(*), COALESCE(SUM(user_earnings), 0) 
                     FROM ad_views WHERE user_id = ? 
                     GROUP BY ad_type''', (user_id,))
        ad_stats = c.fetchall()
        
        # Total views
        c.execute('SELECT COUNT(*) FROM ad_views WHERE user_id = ?', (user_id,))
        total_views = c.fetchone()[0]
        
        return {
            'total_earnings': total_earnings,
            'total_views': total_views,
            'ad_stats': ad_stats
        }

def get_admin_ad_stats():
    """Get admin's ad revenue statistics with proper resource management"""
    with SecureDBConnection() as conn:
        c = conn.cursor()
        
        # Total platform ad revenue
        c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = 1 AND type = "ad_revenue"')
        total_revenue = c.fetchone()[0]
        
        # Total user ad earnings (paid out)
        c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "ad_earnings"')
        total_paid_out = c.fetchone()[0]
        
        # Ad views by type
        c.execute('''SELECT ad_type, COUNT(*), COALESCE(SUM(platform_earnings), 0) 
                     FROM ad_views 
                     GROUP BY ad_type''')
        ad_stats = c.fetchall()
        
        # Total views
        c.execute('SELECT COUNT(*) FROM ad_views')
        total_views = c.fetchone()[0]
        
        # Revenue per view average
        avg_revenue = total_revenue / total_views if total_views > 0 else 0
        
        return {
            'total_revenue': total_revenue,
            'total_paid_out': total_paid_out,
            'net_profit': total_revenue - total_paid_out,
            'total_views': total_views,
            'avg_revenue_per_view': avg_revenue,
            'ad_stats': ad_stats
        }

# Flask routes for ad system
def register_ad_routes(app):
    
    @app.route('/api/record_ad_view', methods=['POST'])
    def api_record_ad_view():
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.get_json()
        ad_type = data.get('ad_type')
        ad_placement = data.get('ad_placement', 'unknown')
        
        if not ad_type:
            return jsonify({'error': 'Ad type required'}), 400
        
        success, result = record_ad_view(session['user_id'], ad_type, ad_placement)
        
        if success:
            return jsonify({
                'success': True,
                'earnings': result,
                'message': f'Earned KSh {result:.2f} for viewing ad'
            })
        else:
            return jsonify({'error': result}), 400
    
    @app.route('/api/user_ad_stats')
    def api_user_ad_stats():
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        stats = get_user_ad_stats(session['user_id'])
        return jsonify({'success': True, 'stats': stats})
    
    @app.route('/api/admin_ad_stats')
    def api_admin_ad_stats():
        if 'user_id' not in session or session.get('username') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 401
        
        stats = get_admin_ad_stats()
        return jsonify({'success': True, 'stats': stats})

# Initialize ad system
init_ad_tables()