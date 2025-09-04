import re

with open('app.py', 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

for i in range(len(lines)):
    # Fix "c = conn.cursor()" indentation after "with sqlite3.connect"
    if i > 0 and 'with sqlite3.connect' in lines[i-1] and 'c = conn.cursor()' in lines[i]:
        # Count indentation of previous line
        prev_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
        # Add 4 more spaces for proper indentation
        lines[i] = ' ' * (prev_indent + 4) + lines[i].lstrip()

with open('app.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)

print("Fixed all indentation issues")