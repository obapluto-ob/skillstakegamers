# Clean all duplicate routes from app.py
import re

def clean_all_duplicates():
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # List of routes that might be duplicated
    routes_to_check = [
        'check_payment_status',
        'resolve_game_matches', 
        'admin_game_matches',
        'resolve_fpl_battles',
        'admin_fpl_battles'
    ]
    
    for route_name in routes_to_check:
        # Find all occurrences of this route
        pattern = rf"@app\.route\([^)]*{route_name}[^)]*\).*?(?=@app\.route|if __name__|# UNIQUE SKILLSTAKE|$)"
        matches = list(re.finditer(pattern, content, re.DOTALL))
        
        if len(matches) > 1:
            print(f"Found {len(matches)} {route_name} routes - removing duplicates")
            # Keep only the first one, remove the rest
            for match in reversed(matches[1:]):
                content = content[:match.start()] + content[match.end():]
    
    # Write back
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("Cleaned all duplicate routes!")

if __name__ == "__main__":
    clean_all_duplicates()