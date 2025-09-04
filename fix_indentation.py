import re

with open('app.py', 'r') as f:
    content = f.read()

# Fix common indentation issues in the matches function
fixes = [
    (r'(\s+)# Get user\'s matches\n\s+c\.execute', r'\1# Get user\'s matches\n\1c.execute'),
    (r'(\s+)my_matches = c\.fetchall\(\)\n\s+return render_template', r'\1my_matches = c.fetchall()\n\1return render_template'),
]

for pattern, replacement in fixes:
    content = re.sub(pattern, replacement, content)

with open('app.py', 'w') as f:
    f.write(content)

print("Fixed indentation issues")