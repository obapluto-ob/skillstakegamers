import sqlite3
from datetime import datetime

def get_db_connection():
    return sqlite3.connect('gamebet.db')

def create_daily_tournaments():
    """Create daily tournaments automatically"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Check if today's tournaments already exist
            c.execute('''SELECT COUNT(*) FROM tournaments 
                       WHERE DATE(created_at) = DATE('now') AND status = 'open' AND name LIKE 'Daily%' ''')
            existing_count = c.fetchone()[0]
            if existing_count >= 3:
                print(f'Daily tournaments already exist: {existing_count}')
                return  # Already created today
            
            # Create daily tournaments
            tournaments = [
                (f'Daily FIFA Championship - {datetime.now().strftime("%Y-%m-%d")}', 'FIFA Mobile', 100, 16, 1360),
                (f'Daily eFootball Cup - {datetime.now().strftime("%Y-%m-%d")}', 'eFootball', 100, 16, 1360),
                (f'Daily FPL Battle - {datetime.now().strftime("%Y-%m-%d")}', 'FPL Battle', 150, 12, 1530)
            ]
            
            for name, game, entry_fee, max_players, prize_pool in tournaments:
                c.execute('''INSERT OR IGNORE INTO tournaments 
                           (name, game, entry_fee, max_players, prize_pool, status) 
                           VALUES (?, ?, ?, ?, ?, 'open')''',
                         (name, game, entry_fee, max_players, prize_pool))
            
            conn.commit()
            print(f'Daily tournaments created: {len(tournaments)}')
            
    except Exception as e:
        print(f'Tournament creation error: {e}')

if __name__ == '__main__':
    create_daily_tournaments()