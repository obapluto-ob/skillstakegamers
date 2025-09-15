from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from database_manager import db_manager
from database import get_db_connection
import os

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    def wrapper(*args, **kwargs):
        if session.get('username') != 'admin':
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@admin_bp.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            
            c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
            total_users = c.fetchone()[0] or 0
            
            c.execute('SELECT COUNT(*) FROM transactions')
            total_transactions = c.fetchone()[0] or 0
            
            c.execute('SELECT SUM(balance) FROM users WHERE username != "admin"')
            total_balance = c.fetchone()[0] or 0
            
            stats = {
                'total_users': total_users,
                'total_transactions': total_transactions,
                'total_balance': total_balance,
                'pending_deposits': 0,
                'unresolved_alerts': 0,
                'active_matches': 0,
                'total_deposits': 0,
                'net_earnings': 0
            }
            
            earnings_data = {
                'match_commission': 0,
                'commission_rate': 8,
                'deposit_fees': 0,
                'withdrawal_fees': 0,
                'referral_profits': 0,
                'fraud_commissions': 0,
                'total_battles': 0,
                'bank_fees': 0,
                'gross_earnings': 0,
                'net_earnings': 0,
                'pending_deposits': 0,
                'pending_withdrawals': 0,
                'total_game_matches': 0
            }
            
            return render_template('admin_dashboard.html', 
                                 stats=stats, 
                                 earnings_data=earnings_data,
                                 pending_deposits=[],
                                 pending_withdrawals=[],
                                 active_game_matches=[],
                                 notifications=[],
                                 unread_alerts=0)
            
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}', 'error')
        return render_template('admin_dashboard.html', 
                             stats={'total_users': 0, 'total_transactions': 0, 'total_balance': 0, 'pending_deposits': 0, 'unresolved_alerts': 0, 'active_matches': 0, 'total_deposits': 0, 'net_earnings': 0},
                             earnings_data={'match_commission': 0, 'commission_rate': 8, 'deposit_fees': 0, 'withdrawal_fees': 0, 'referral_profits': 0, 'fraud_commissions': 0, 'total_battles': 0, 'bank_fees': 0, 'gross_earnings': 0, 'net_earnings': 0, 'pending_deposits': 0, 'pending_withdrawals': 0, 'total_game_matches': 0},
                             pending_deposits=[], pending_withdrawals=[], active_game_matches=[], notifications=[], unread_alerts=0)

@admin_bp.route('/admin_users')
@admin_required
def admin_users():
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT id, username, email, balance, created_at FROM users WHERE username != "admin"')
            users = c.fetchall()
        return render_template('admin_users.html', users=users)
    except:
        return render_template('admin_users.html', users=[])

@admin_bp.route('/admin_transactions')
@admin_required
def admin_transactions():
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM transactions ORDER BY created_at DESC LIMIT 100')
            transactions = c.fetchall()
        return render_template('admin_transactions.html', transactions=transactions)
    except:
        return render_template('admin_transactions.html', transactions=[])

@admin_bp.route('/admin_matches')
@admin_required
def admin_matches():
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM game_matches ORDER BY created_at DESC LIMIT 50')
            matches = c.fetchall()
        return render_template('admin_matches.html', matches=matches)
    except:
        return render_template('admin_matches.html', matches=[])

@admin_bp.route('/admin_deposits')
@admin_required
def admin_deposits():
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            c.execute('''SELECT t.*, u.username 
                       FROM transactions t
                       JOIN users u ON t.user_id = u.id
                       WHERE t.type IN ("pending_deposit", "pending_crypto_deposit", "smart_pending_deposit")
                       ORDER BY 
                           CASE 
                               WHEN t.type = "smart_pending_deposit" AND t.description LIKE "%Confidence: 9%" THEN 1
                               WHEN t.type = "smart_pending_deposit" AND t.description LIKE "%Confidence: 8%" THEN 2
                               WHEN t.type = "smart_pending_deposit" THEN 3
                               ELSE 4
                           END,
                           t.created_at DESC''')
            pending_deposits = c.fetchall()
            
            c.execute('''SELECT t.*, u.username 
                       FROM transactions t
                       JOIN users u ON t.user_id = u.id
                       WHERE t.type IN ("deposit", "rejected_deposit", "completed")
                       ORDER BY t.created_at DESC LIMIT 20''')
            processed_deposits = c.fetchall()
            
        return render_template('admin_deposits.html', 
                             pending_deposits=pending_deposits,
                             processed_deposits=processed_deposits)
    except:
        return render_template('admin_deposits.html', 
                             pending_deposits=[],
                             processed_deposits=[])

@admin_bp.route('/approve_deposit/<int:transaction_id>', methods=['POST'])
@admin_required
def approve_deposit(transaction_id):
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            
            # Get transaction details
            c.execute('SELECT * FROM transactions WHERE id = ? AND type IN ("pending_deposit", "pending_crypto_deposit")', (transaction_id,))
            transaction = c.fetchone()
            
            if not transaction:
                return jsonify({'success': False, 'message': 'Transaction not found'})
            
            user_id = transaction[1]
            amount = transaction[3]
            
            # Update user balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            current_balance = c.fetchone()[0] or 0
            new_balance = current_balance + amount
            c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, user_id))
            
            # Update transaction status
            if transaction[2] == 'pending_crypto_deposit':
                c.execute('UPDATE transactions SET type = "crypto_deposit" WHERE id = ?', (transaction_id,))
            else:
                c.execute('UPDATE transactions SET type = "deposit" WHERE id = ?', (transaction_id,))
            
            conn.commit()
            
        return jsonify({'success': True, 'message': f'Deposit approved! KSh {amount} added to user balance.'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error approving deposit'})

@admin_bp.route('/reject_deposit/<int:transaction_id>', methods=['POST'])
@admin_required
def reject_deposit(transaction_id):
    try:
        data = request.get_json()
        reason = data.get('reason', 'No reason provided')
        
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            
            # Update transaction status for both regular and smart deposits
            c.execute('UPDATE transactions SET type = "rejected_deposit", description = description || " - Rejected: " || ? WHERE id = ? AND type IN ("pending_deposit", "smart_pending_deposit")', 
                     (reason, transaction_id))
            
            if c.rowcount == 0:
                return jsonify({'success': False, 'message': 'Transaction not found'})
            
            conn.commit()
            
        return jsonify({'success': True, 'message': 'Deposit rejected successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error rejecting deposit'})

@admin_bp.route('/admin_tournaments')
@admin_required
def admin_tournaments():
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            
            # Get all tournaments with participant count
            c.execute('''SELECT t.*, COUNT(tp.user_id) as participants
                       FROM tournaments t
                       LEFT JOIN tournament_participants tp ON t.id = tp.tournament_id
                       GROUP BY t.id
                       ORDER BY t.created_at DESC''')
            tournaments = c.fetchall()
            
            return render_template('admin_tournaments.html', tournaments=tournaments)
    except:
        return render_template('admin_tournaments.html', tournaments=[])

@admin_bp.route('/create_tournament', methods=['POST'])
@admin_required
def create_tournament():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        game_type = data.get('game_type', '').strip()
        entry_fee = float(data.get('entry_fee', 0))
        max_players = int(data.get('max_players', 16))
        
        if not all([name, game_type]) or entry_fee < 50:
            return jsonify({'success': False, 'message': 'Invalid tournament data'})
        
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO tournaments (name, game_type, entry_fee, max_players, whatsapp_group) 
                       VALUES (?, ?, ?, ?, ?)''',
                     (name, game_type, entry_fee, max_players, os.getenv('TOURNAMENT_WHATSAPP_GROUP', '')))
            conn.commit()
        
        return jsonify({'success': True, 'message': 'Tournament created successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error creating tournament'})

@admin_bp.route('/admin_support_center')
@admin_required
def admin_support_center():
    return render_template('admin_support.html')

@admin_bp.route('/admin_settings')
@admin_required
def admin_settings():
    return render_template('admin_settings.html')

@admin_bp.route('/admin_withdrawals')
@admin_required
def admin_withdrawals():
    return render_template('admin_withdrawals.html')