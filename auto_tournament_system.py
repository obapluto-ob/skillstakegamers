import sqlite3
import schedule
import time
from datetime import datetime

def create_auto_tournament():
    """Creates tournaments automatically every 2 hours"""
    conn = sqlite3.connect('gamebet.db')
    c = conn.cursor()
    
    # Check if there are active tournaments
    c.execute('SELECT COUNT(*) FROM tournaments WHERE status IN ("open", "full")')
    active_count = c.fetchone()[0]
    
    # Only create if less than 3 active tournaments
    if active_count < 3:
        tournaments = [
            ('PUBG Quick Match', 'pubg_mobile', 100, 16),
            ('FIFA Championship', 'fifa_mobile', 150, 8),
            ('COD Battle Royale', 'cod_mobile', 120, 16),
            ('eFootball Cup', 'efootball', 80, 8),
        ]
        
        # Create random tournament
        import random
        tournament = random.choice(tournaments)
        
        c.execute('''INSERT INTO tournaments (name, game, entry_fee, max_players, prize_pool, status)
                     VALUES (?, ?, ?, ?, ?, ?)''', 
                 (tournament[0], tournament[1], tournament[2], tournament[3], 0, 'open'))
        
        print(f"Auto-created tournament: {tournament[0]}")
    
    conn.commit()
    conn.close()

def run_tournament_scheduler():
    """Run the tournament scheduler"""
    schedule.every(2).hours.do(create_auto_tournament)
    schedule.every().day.at("08:00").do(create_auto_tournament)  # Morning tournament
    schedule.every().day.at("14:00").do(create_auto_tournament)  # Afternoon tournament
    schedule.every().day.at("20:00").do(create_auto_tournament)  # Evening tournament
    
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute

if __name__ == "__main__":
    print("Starting auto tournament system...")
    create_auto_tournament()  # Create one immediately
    run_tournament_scheduler()