# Remove duplicate unique_dashboard route
with open('app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find and remove the second occurrence of unique_dashboard
found_first = False
new_lines = []
skip_lines = 0

for i, line in enumerate(lines):
    if skip_lines > 0:
        skip_lines -= 1
        continue
        
    if "@app.route('/unique_dashboard')" in line:
        if found_first:
            # Skip this duplicate and the next 3 lines
            skip_lines = 3
            continue
        else:
            found_first = True
    
    new_lines.append(line)

# Write back
with open('app.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("Removed duplicate unique_dashboard route")