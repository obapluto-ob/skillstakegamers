# Clean all duplicate routes from app.py
import re

with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find all route definitions and their function names
route_pattern = r'@app\.route\([^)]+\)\s*(?:@[^@]*\s*)*def\s+(\w+)'
matches = list(re.finditer(route_pattern, content, re.MULTILINE | re.DOTALL))

# Track seen functions and their positions
seen_functions = {}
duplicates_to_remove = []

for match in matches:
    func_name = match.group(1)
    start_pos = match.start()
    
    if func_name in seen_functions:
        # This is a duplicate - mark for removal
        duplicates_to_remove.append((start_pos, func_name))
        print(f"Found duplicate: {func_name}")
    else:
        seen_functions[func_name] = start_pos

# Remove duplicates from end to beginning to preserve positions
duplicates_to_remove.sort(reverse=True)

for start_pos, func_name in duplicates_to_remove:
    # Find the end of this function
    lines = content[start_pos:].split('\n')
    func_lines = []
    in_function = False
    
    for i, line in enumerate(lines):
        if line.strip().startswith('@app.route') or (in_function and line.startswith('def ')):
            in_function = True
        
        if in_function:
            func_lines.append(line)
            
            # Check if we've reached the end of the function
            if i > 0 and line.strip() == '' and i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                if next_line.startswith('@') or next_line.startswith('def ') or next_line.startswith('if __name__'):
                    break
    
    # Remove this function from content
    func_text = '\n'.join(func_lines)
    if func_text in content:
        content = content.replace(func_text, '', 1)
        print(f"Removed duplicate function: {func_name}")

# Write cleaned content back
with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Cleaned all duplicate routes from app.py")