# Remove all duplicate routes from app.py
with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# List of routes that might be duplicated
routes_to_check = [
    'unique_dashboard',
    'admin_support_center', 
    'get_skill_rating',
    'earn_skill_tokens',
    'get_live_matches',
    'buy_skill_insurance',
    'create_revenge_match',
    'place_live_bet'
]

# Split content into lines
lines = content.split('\n')
new_lines = []
seen_routes = set()
skip_until_next_route = False

i = 0
while i < len(lines):
    line = lines[i]
    
    # Check if this is a route definition
    if line.strip().startswith('@app.route('):
        # Extract route name from the next function definition
        func_line_idx = i + 1
        while func_line_idx < len(lines) and not lines[func_line_idx].strip().startswith('def '):
            func_line_idx += 1
        
        if func_line_idx < len(lines):
            func_line = lines[func_line_idx]
            func_name = func_line.split('def ')[1].split('(')[0].strip()
            
            if func_name in routes_to_check:
                if func_name in seen_routes:
                    # Skip this duplicate route and its function
                    print(f"Removing duplicate route: {func_name}")
                    # Skip until we find the next @app.route or end of function
                    while i < len(lines):
                        if i + 1 < len(lines) and lines[i + 1].strip().startswith('@app.route('):
                            break
                        if lines[i].strip() == '' and i + 1 < len(lines) and lines[i + 1].strip().startswith('@'):
                            break
                        i += 1
                    continue
                else:
                    seen_routes.add(func_name)
    
    new_lines.append(line)
    i += 1

# Write back the cleaned content
with open('app.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(new_lines))

print("Removed all duplicate routes")