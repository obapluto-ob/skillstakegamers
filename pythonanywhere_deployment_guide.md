# PythonAnywhere Deployment Guide

## Step 1: Create PythonAnywhere Account
1. Go to https://www.pythonanywhere.com
2. Sign up for FREE account
3. Choose username (this will be your domain: username.pythonanywhere.com)

## Step 2: Upload Your Files
1. Go to **Files** tab in PythonAnywhere dashboard
2. Create new folder: `/home/yourusername/mysite/`
3. Upload ALL your files:
   - `app.py`
   - `templates/` folder (all HTML files)
   - `static/` folder (CSS files)
   - Any other Python files

## Step 3: Install Required Packages
1. Go to **Consoles** tab
2. Start a **Bash console**
3. Run these commands:
```bash
pip3.10 install --user flask
pip3.10 install --user werkzeug
```

## Step 4: Create WSGI Configuration
1. Go to **Web** tab
2. Click **Add a new web app**
3. Choose **Flask**
4. Choose **Python 3.10**
5. Set path to: `/home/yourusername/mysite/app.py`

## Step 5: Configure WSGI File
1. In **Web** tab, click on WSGI configuration file
2. Replace content with:
```python
import sys
import os

# Add your project directory to sys.path
sys.path.insert(0, '/home/yourusername/mysite')

from app import app as application

if __name__ == "__main__":
    application.run()
```

## Step 6: Set Up Database
1. Go to **Files** tab
2. Navigate to `/home/yourusername/mysite/`
3. Open **Bash console** in that directory
4. Run: `python3.10 app.py` once to create database
5. Visit: `yourusername.pythonanywhere.com/init_db` to set up tables

## Step 7: Create Admin User
1. In Bash console, run:
```python
python3.10 -c "
import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('gamebet.db')
c = conn.cursor()

# Create admin user
admin_password = generate_password_hash('admin123')
c.execute('INSERT OR REPLACE INTO users (id, username, email, password, balance, phone) VALUES (1, \"admin\", \"admin@gamebet.com\", ?, 0, \"admin\")', (admin_password,))

conn.commit()
conn.close()
print('Admin user created: username=admin, password=admin123')
"
```

## Step 8: Configure Static Files
1. In **Web** tab, scroll to **Static files**
2. Add mapping:
   - URL: `/static/`
   - Directory: `/home/yourusername/mysite/static/`

## Step 9: Reload and Test
1. Click **Reload yourusername.pythonanywhere.com**
2. Visit your site: `https://yourusername.pythonanywhere.com`
3. Test login with: username=`admin`, password=`admin123`

## Step 10: Share with Friends
Your friends can access the site at:
**https://yourusername.pythonanywhere.com**

## Troubleshooting
- Check **Error log** in Web tab if site doesn't load
- Make sure all file paths are correct
- Ensure database file has write permissions
- Check that all required packages are installed

## Important Notes
- FREE account allows 1 web app
- Site will be at: yourusername.pythonanywhere.com
- Database will persist between deployments
- You can update files anytime in Files tab

## Quick Commands for Updates
```bash
# To update your app after changes:
cd /home/yourusername/mysite
# Upload new files via Files tab
# Then reload web app in Web tab
```

Your gaming platform will be live and accessible to friends worldwide!