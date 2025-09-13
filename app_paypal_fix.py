@app.route('/paypal_cancelled', methods=['POST'])
@login_required
def paypal_cancelled():
    try:
        data = request.get_json()
        amount = data.get('amount')
        order_id = data.get('order_id')
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                       VALUES (?, ?, ?, ?)''',
                     (session['user_id'], 'paypal_cancelled', amount, 
                      f'PayPal payment cancelled - KSh {amount} - Order: {order_id}'))
            conn.commit()
        
        return jsonify({'success': True, 'message': 'Cancellation recorded'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})