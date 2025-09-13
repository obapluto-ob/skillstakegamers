# Initialize unique features
import sys
sys.path.append('.')

from app import app
from unique_routes import register_unique_routes
from unique_features import init_unique_tables

# Initialize database tables
init_unique_tables()

# Register routes
register_unique_routes(app)

print("✅ Unique SkillStake features initialized!")
print("🚀 New features added:")
print("   - Skill Insurance System")
print("   - Revenge Match Challenges") 
print("   - Live Match Betting")
print("   - Daily Bonuses & Tokens")
print("   - Skill Rating & Bounties")
print("   - Enhanced User Dashboard")
print("\n🎯 Access at: /skill_dashboard")