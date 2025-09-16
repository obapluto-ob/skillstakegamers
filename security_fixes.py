# Security fixes for SkillStake Gaming Platform

import re
import os
from werkzeug.utils import secure_filename

# File upload security
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_upload(file):
    """Comprehensive file upload validation"""
    if not file or file.filename == '':
        return False, "No file selected"
    
    if not allowed_file(file.filename):
        return False, "File type not allowed"
    
    # Check file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > MAX_FILE_SIZE:
        return False, "File too large"
    
    return True, "Valid file"

# Input sanitization
def sanitize_input(input_string):
    """Sanitize user input to prevent XSS"""
    if not input_string:
        return ""
    
    # Remove HTML tags and dangerous characters
    clean = re.sub(r'<[^>]*>', '', str(input_string))
    clean = re.sub(r'[<>"\']', '', clean)
    return clean.strip()

def validate_numeric_input(value, min_val=None, max_val=None):
    """Safely validate and convert numeric input"""
    try:
        if isinstance(value, str):
            # Check for NaN injection
            if 'nan' in value.lower() or 'inf' in value.lower():
                return None, "Invalid numeric value"
        
        num_val = float(value)
        
        # Check for NaN or infinity
        if not (num_val == num_val) or num_val == float('inf') or num_val == float('-inf'):
            return None, "Invalid numeric value"
        
        if min_val is not None and num_val < min_val:
            return None, f"Value must be at least {min_val}"
        
        if max_val is not None and num_val > max_val:
            return None, f"Value must be at most {max_val}"
        
        return num_val, "Valid"
    
    except (ValueError, TypeError):
        return None, "Invalid numeric format"

# SQL injection prevention
def safe_sql_query(cursor, query, params=None):
    """Execute SQL query safely with parameterized queries"""
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return True, None
    except Exception as e:
        return False, str(e)