import sqlite3

# Connect to database
conn = sqlite3.connect('gamebet.db')
c = conn.cursor()

# Find users who may have been double-charged due to duplicate joins
# Look for users with recent balance deductions that don't have corresponding matches
c.execute('''
    SELECT u.id, u.username, u.balance, 
           COUNT(m.id) as matches_as_player2,
           COUNT(t.id) as recent_deductions
    FROM users u
    LEFT JOIN matches m ON u.id = m.player2_id
    LEFT JOIN transactions t ON u.id = t.user_id AND t.type = 'bet' AND t.created_at > datetime('now', '-1 day')
    WHERE u.username != 'admin'
    GROUP BY u.id
    HAVING recent_deductions > matches_as_player2
''')

affected_users = c.fetchall()

print("Users potentially affected by duplicate join bug:")
for user in affected_users:
    print(f"User: {user[1]} (ID: {user[0]}) - Current balance: KSh {user[2]}")
    
    # Check their recent transactions
    c.execute('''SELECT * FROM transactions WHERE user_id = ? AND created_at > datetime('now', '-1 day') ORDER BY created_at DESC''', (user[0],))
    recent_transactions = c.fetchall()
    
    if recent_transactions:
        print("  Recent transactions:")
        for trans in recent_transactions:
            print(f"    {trans[2]}: KSh {trans[3]} - {trans[4]}")
    
    # Refund logic - add back the duplicate deduction
    # Assuming standard bet amounts, refund the most recent deduction
    if recent_transactions:
        last_deduction = abs(recent_transactions[0][3])  # Get absolute value
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (last_deduction, user[0]))
        c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                 (user[0], 'refund', last_deduction, f'Refund for duplicate join bug - KSh {last_deduction}'))
        print(f"  REFUNDED: KSh {last_deduction}")
    
    print()

conn.commit()
conn.close()
print("Refund process completed!")