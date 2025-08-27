"""
TOURNAMENT WINNER DETERMINATION SYSTEM

How the system determines tournament winners:

1. TOURNAMENT SCHEDULE:
   - 6 tournaments created per day (every 4 hours)
   - Always keeps 3 active tournaments available
   - Auto-creates when users visit tournaments page

2. WINNER DETERMINATION METHODS:

   A) BATTLE ROYALE GAMES (PUBG, COD, Free Fire):
      - Players submit placement screenshots
      - Winner = Highest placement (1st place beats 2nd, etc.)
      - Tie-breaker = Kills/damage if same placement
      - Admin verifies screenshots for authenticity

   B) SPORTS GAMES (FIFA, eFootball):
      - Players submit match result screenshots
      - Winner = Most goals scored in head-to-head
      - Tie-breaker = Penalty shootout screenshot
      - Admin verifies final scores

   C) MOBA GAMES (Mobile Legends):
      - Players submit victory screen
      - Winner = Victory vs Defeat
      - Tie-breaker = KDA ratio from screenshot
      - Admin verifies match results

3. TOURNAMENT FLOW:
   - Tournament fills up (8-16 players)
   - Single elimination bracket
   - Players play their matches
   - Submit screenshot proof within 30 minutes
   - Admin reviews and declares winners
   - Prizes distributed automatically

4. ADMIN VERIFICATION PROCESS:
   - Check screenshot authenticity
   - Verify game mode matches tournament rules
   - Confirm results are legitimate
   - Resolve disputes manually
   - Distribute prizes to winners

5. PRIZE DISTRIBUTION:
   - 1st Place: 40% of prize pool
   - 2nd Place: 25% of prize pool  
   - 3rd Place: 12% of prize pool
   - 4th Place: 8% of prize pool
   - Admin keeps: 15% commission

6. DAILY TOURNAMENT SCHEDULE:
   - 6:00 AM - Morning Tournament
   - 10:00 AM - Mid-Morning Tournament  
   - 2:00 PM - Afternoon Tournament
   - 6:00 PM - Evening Tournament
   - 10:00 PM - Night Tournament
   - 2:00 AM - Late Night Tournament

This ensures 24/7 tournament availability with fair winner determination.
"""

import sqlite3
from datetime import datetime

@app.route('/tournament/<int:tournament_id>/submit_result', methods=['GET', 'POST'])
def tournament_submit_result(tournament_id):
    """Submit tournament result - same as match system"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Check if user is in this tournament
    c.execute('SELECT * FROM tournament_participants WHERE tournament_id = ? AND user_id = ?', 
             (tournament_id, session['user_id']))
    participant = c.fetchone()
    
    if not participant:
        flash('You are not in this tournament!', 'error')
        conn.close()
        return redirect(url_for('tournaments'))
    
    if request.method == 'POST':
        result = request.form['result']  # 'won' or 'lost'
        screenshot = request.files.get('screenshot')
        
        if screenshot:
            # Save screenshot
            filename = f"tournament_{tournament_id}_{session['user_id']}_{int(time.time())}.png"
            screenshot.save(f"static/screenshots/{filename}")
            
            # Store result for admin review (same as matches)
            c.execute('''INSERT INTO tournament_results (tournament_id, user_id, result, screenshot, status)
                         VALUES (?, ?, ?, ?, ?)''',
                     (tournament_id, session['user_id'], result, filename, 'pending'))
            
            conn.commit()
            flash('Result submitted! Admin will review and determine winners.', 'success')
        else:
            flash('Screenshot is required!', 'error')
    
    conn.close()
    return render_template('tournament_submit_result.html', tournament_id=tournament_id)

@app.route('/admin/tournament/<int:tournament_id>/review')
def admin_tournament_review(tournament_id):
    """Admin reviews tournament results - same as match review"""
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get all tournament results
    c.execute('''SELECT tr.*, u.username FROM tournament_results tr
                 JOIN users u ON tr.user_id = u.id
                 WHERE tr.tournament_id = ? ORDER BY tr.created_at''',
             (tournament_id,))
    results = c.fetchall()
    
    conn.close()
    return render_template('admin_tournament_review.html', results=results, tournament_id=tournament_id)

@app.route('/admin/tournament/<int:tournament_id>/declare_winner', methods=['POST'])
def admin_declare_tournament_winner(tournament_id):
    """Admin declares tournament winners - same logic as matches"""
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    winners = request.form.getlist('winners')  # List of user_ids in order
    
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Get tournament prize pool
    c.execute('SELECT prize_pool FROM tournaments WHERE id = ?', (tournament_id,))
    prize_pool = c.fetchone()[0]
    
    # Prize distribution: 40%, 25%, 12%, 8%
    prize_percentages = [0.40, 0.25, 0.12, 0.08]
    
    for i, winner_id in enumerate(winners[:4]):
        if i < len(prize_percentages):
            prize = prize_pool * prize_percentages[i]
            
            # Award prize (same as match system)
            c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1, total_earnings = total_earnings + ? WHERE id = ?',
                     (prize, prize, winner_id))
            
            # Record transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (winner_id, 'tournament_win', prize, f'Tournament prize - Position {i+1}'))
    
    # Mark tournament as completed
    c.execute('UPDATE tournaments SET status = "completed" WHERE id = ?', (tournament_id,))
    
    conn.commit()
    conn.close()
    
    flash('Tournament winners declared and prizes awarded!', 'success')
    return redirect(url_for('tournaments'))

if __name__ == "__main__":
    print("Tournament winner determination system loaded!")