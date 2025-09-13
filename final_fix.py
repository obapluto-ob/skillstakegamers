# Final fix for duplicate routes
import re

def final_fix():
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find all occurrences of check_payment_status
    pattern = r"@app\.route\('/check_payment_status/<payment_id>'\).*?(?=@app\.route|if __name__|$)"
    matches = list(re.finditer(pattern, content, re.DOTALL))
    
    print(f"Found {len(matches)} check_payment_status routes")
    
    if len(matches) > 1:
        # Keep only the first one, remove the rest
        for match in reversed(matches[1:]):
            content = content[:match.start()] + content[match.end():]
            print(f"Removed duplicate at position {match.start()}")
    
    # Write back
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("Fixed all duplicates!")

if __name__ == "__main__":
    final_fix()