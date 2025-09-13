# Ultimate fix for all duplicate routes
with open('app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Track function names we've seen
seen_functions = set()
new_lines = []
i = 0

while i < len(lines):
    line = lines[i]
    
    # Check if this line starts a route definition
    if line.strip().startswith('@app.route('):
        # Look ahead to find the function name
        j = i + 1
        while j < len(lines) and not lines[j].strip().startswith('def '):
            j += 1
        
        if j < len(lines):
            func_line = lines[j]
            func_name = func_line.split('def ')[1].split('(')[0].strip()
            
            if func_name in seen_functions:
                # Skip this entire function
                print(f"Skipping duplicate function: {func_name}")
                # Skip until we find the next @app.route or end
                while i < len(lines):
                    current_line = lines[i]
                    i += 1
                    # Stop if we hit another route or the end
                    if i < len(lines) and lines[i].strip().startswith('@app.route('):
                        i -= 1  # Back up one so we don't skip the next route
                        break
                    if current_line.strip() == '' and i < len(lines) and (lines[i].strip().startswith('if __name__') or lines[i].strip().startswith('@app.route(')):
                        i -= 1
                        break
                continue
            else:
                seen_functions.add(func_name)
    
    new_lines.append(line)
    i += 1

# Write the cleaned file
with open('app.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("Ultimate fix completed - removed all duplicates")