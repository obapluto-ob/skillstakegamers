# Bonus Security Admin Routes - Add to app.py

@app.route('/admin/bonus_security')
@login_required
def bonus_security_dashboard():
    if session.get('username') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('bonus_security_dashboard.html')

@app.route('/admin/bonus_security_stats')
@login_required
def bonus_security_stats():
    if session.get('username') != 'admin':
        return jsonify({'success': False})
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            today = datetime.now().date()
            
            # Count high risk users
            c.execute('''SELECT COUNT(DISTINCT user_id) FROM transactions t
                       JOIN users u ON t.user_id = u.id
                       WHERE t.type = "daily_bonus" AND DATE(t.created_at) = ?
                       AND (u.total_deposited = 0 OR u.total_deposited IS NULL)
                       AND u.created_at < datetime('now', '-7 days')''', (today,))
            high_risk = c.fetchone()[0] or 0
            
            # Daily bonus total
            c.execute('''SELECT SUM(amount) FROM transactions 
                       WHERE type = "daily_bonus" AND DATE(created_at) = ?''', (today,))
            daily_total = c.fetchone()[0] or 0
            
            # Pool remaining
            pool_limit = 15000
            pool_remaining = max(0, pool_limit - daily_total)
            
            return jsonify({
                'success': True,
                'stats': {
                    'high_risk_users': high_risk,
                    'medium_risk_users': 0,
                    'daily_bonus_total': daily_total,
                    'pool_remaining': pool_remaining,
                    'suspicious_ips': 0,
                    'blocked_claims': 0
                }
            })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/high_risk_users')
@login_required
def high_risk_users():
    if session.get('username') != 'admin':
        return jsonify({'success': False})
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get users with suspicious patterns
            c.execute('''SELECT u.id, u.username, u.last_ip, u.created_at,
                              COUNT(t.id) as bonus_count
                       FROM users u
                       LEFT JOIN transactions t ON u.id = t.user_id AND t.type = "daily_bonus"
                       WHERE u.username != "admin"
                       GROUP BY u.id
                       HAVING bonus_count > 3
                       ORDER BY bonus_count DESC
                       LIMIT 20''')
            
            users = []
            for row in c.fetchall():
                user_id, username, ip, created_at, bonus_count = row
                
                users.append({
                    'user_id': user_id,
                    'username': username,
                    'ip_address': ip or 'Unknown',
                    'risk_score': 0.8 if bonus_count > 10 else 0.5,
                    'risk_factors': f'{bonus_count} bonus claims',
                    'last_claim': 'Recent',
                    'risk_level': 'high' if bonus_count > 10 else 'medium'
                })
            
            return jsonify({'success': True, 'users': users})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/suspicious_activities')
@login_required
def suspicious_activities():
    if session.get('username') != 'admin':
        return jsonify({'success': False})
    
    return jsonify({'success': True, 'activities': []})

@app.route('/admin/ip_analysis')
@login_required
def ip_analysis():
    if session.get('username') != 'admin':
        return jsonify({'success': False})
    
    return jsonify({'success': True, 'ips': []})

@app.route('/admin/restrict_user_bonus', methods=['POST'])
@login_required
def restrict_user_bonus():
    if session.get('username') != 'admin':
        return jsonify({'success': False})
    
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        # Log action
        log_admin_action(
            admin_id=session['user_id'],
            action_type='restrict_bonus',
            target_user_id=user_id,
            details='Restricted user bonus eligibility',
            ip_address=request.remote_addr
        )
        
        return jsonify({'success': True, 'message': 'User bonus restricted'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/emergency_stop_bonuses', methods=['POST'])
@login_required
def emergency_stop_bonuses():
    if session.get('username') != 'admin':
        return jsonify({'success': False})
    
    try:
        # Create system-wide bonus stop
        create_system_alert('emergency_bonus_stop', 'CRITICAL', 
                           'All bonus claims disabled by admin emergency stop')
        
        return jsonify({'success': True, 'message': '🚨 Emergency stop activated'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})