from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from database_manager import db_manager
from database import get_db_connection

auth_bp = Blueprint('auth', __name__)

# Store verification codes temporarily
verification_codes = {}
reset_codes = {}

def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@auth_bp.route('/send_verification', methods=['POST'])
def send_verification():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'})
        
        # Generate 6-digit code
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        # Store code with expiration (10 minutes)
        verification_codes[email] = {
            'code': code,
            'expires': datetime.now() + timedelta(minutes=10)
        }
        
        # Send email
        gmail_user = os.getenv('GMAIL_USER')
        gmail_pass = os.getenv('GMAIL_PASS')
        
        if not gmail_user or not gmail_pass:
            return jsonify({'success': False, 'message': 'Email service not configured'})
        
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = email
        msg['Subject'] = 'SkillStake - Email Verification Code'
        
        body = f'''
Welcome to SkillStake Gaming Platform!

Your verification code is: {code}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Happy Gaming!
SkillStake Team
        '''
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(gmail_user, gmail_pass)
            text = msg.as_string()
            server.sendmail(gmail_user, email, text)
        
        return jsonify({'success': True, 'message': 'Verification code sent'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to send email: {str(e)}'})

@auth_bp.route('/register_with_verification', methods=['POST'])
def register_with_verification():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')
        code = data.get('code', '').strip()
        
        if not all([username, email, password, code]):
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        # Verify code
        if email not in verification_codes:
            return jsonify({'success': False, 'message': 'No verification code found'})
        
        stored_data = verification_codes[email]
        if datetime.now() > stored_data['expires']:
            del verification_codes[email]
            return jsonify({'success': False, 'message': 'Verification code expired'})
        
        if stored_data['code'] != code:
            return jsonify({'success': False, 'message': 'Invalid verification code'})
        
        # Create user
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            
            # Check if user exists
            c.execute('SELECT id FROM users WHERE username = ?', (username,))
            if c.fetchone():
                return jsonify({'success': False, 'message': 'Username already taken'})
                
            c.execute('SELECT id FROM users WHERE email = ?', (email,))
            if c.fetchone():
                return jsonify({'success': False, 'message': 'Email already registered'})
                
            if phone:
                c.execute('SELECT id FROM users WHERE phone = ?', (phone,))
                if c.fetchone():
                    return jsonify({'success': False, 'message': 'Phone number already registered'})
            
            hashed_password = generate_password_hash(password)
            referral_code = username[:3].upper() + ''.join([str(random.randint(0, 9)) for _ in range(4)])
            
            c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code) 
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     (username, email, hashed_password, 0.0, phone, referral_code))
            conn.commit()
        
        # Clean up verification code
        del verification_codes[email]
        
        return jsonify({'success': True, 'message': 'Registration successful'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'})

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form.get('login_input', '').strip()
        password = request.form.get('password', '')
        
        if not login_input or not password:
            flash('Please enter both username/email and password!', 'error')
            return render_template('login_fixed.html')
        
        try:
            with db_manager.get_connection() as conn:
                c = conn.cursor()
                c.execute('SELECT id, username, email, password, balance FROM users WHERE username = ? OR email = ?', 
                         (login_input, login_input))
                user = c.fetchone()
                
                if user and check_password_hash(user[3], password):
                    # Admin can login directly
                    if user[1] == 'admin':
                        session.clear()
                        session.permanent = True
                        session['user_id'] = user[0]
                        session['username'] = user[1]
                        session['balance'] = user[4]
                        session['is_admin'] = True
                        session['logged_in'] = True
                        return redirect(url_for('admin.admin_dashboard'))
                    
                    # Regular users need email verification
                    session['pending_login'] = {
                        'user_id': user[0],
                        'username': user[1],
                        'email': user[2],
                        'balance': user[4]
                    }
                    
                    # Send login verification code
                    code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                    
                    verification_codes[user[2]] = {
                        'code': code,
                        'expires': datetime.now() + timedelta(minutes=10),
                        'type': 'login'
                    }
                    
                    # Send email
                    gmail_user = os.getenv('GMAIL_USER')
                    gmail_pass = os.getenv('GMAIL_PASS')
                    
                    msg = MIMEMultipart()
                    msg['From'] = gmail_user
                    msg['To'] = user[2]
                    msg['Subject'] = 'SkillStake - Login Verification Code'
                    
                    body = f'''
Login Verification Required

Your login verification code is: {code}

This code will expire in 10 minutes.

If you didn't try to login, please secure your account.

SkillStake Team
                    '''
                    
                    msg.attach(MIMEText(body, 'plain'))
                    
                    with smtplib.SMTP('smtp.gmail.com', 587) as server:
                        server.starttls()
                        server.login(gmail_user, gmail_pass)
                        text = msg.as_string()
                        server.sendmail(gmail_user, user[2], text)
                    
                    return redirect(url_for('auth.verify_login'))
                else:
                    flash('Invalid username/email or password!', 'error')
                    return render_template('login_fixed.html')
        except Exception as e:
            flash('Login error occurred. Please try again.', 'error')
    
    return render_template('login_fixed.html')

@auth_bp.route('/verify_login')
def verify_login():
    if 'pending_login' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('auth.login'))
    return render_template('verify_login.html')

@auth_bp.route('/verify_login_code', methods=['POST'])
def verify_login_code():
    try:
        data = request.get_json()
        code = data.get('code', '').strip()
        
        if 'pending_login' not in session:
            return jsonify({'success': False, 'message': 'Login session expired'})
        
        user_data = session['pending_login']
        email = user_data['email']
        
        # Verify code
        if email not in verification_codes:
            return jsonify({'success': False, 'message': 'No verification code found'})
        
        stored_data = verification_codes[email]
        if datetime.now() > stored_data['expires']:
            del verification_codes[email]
            return jsonify({'success': False, 'message': 'Verification code expired'})
        
        if stored_data['code'] != code or stored_data.get('type') != 'login':
            return jsonify({'success': False, 'message': 'Invalid verification code'})
        
        # Complete login and update last login
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP, email_verified = 1 WHERE id = ?', 
                     (user_data['user_id'],))
            conn.commit()
        
        session.clear()
        session.permanent = True
        session['user_id'] = user_data['user_id']
        session['username'] = user_data['username']
        session['balance'] = user_data['balance']
        session['is_admin'] = False
        session['logged_in'] = True
        
        # Clean up verification code
        del verification_codes[email]
        
        return jsonify({'success': True, 'message': 'Login successful'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Verification failed: {str(e)}'})

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('main.home'))

@auth_bp.route('/register')
def register():
    return redirect(url_for('auth.register_fixed'))

@auth_bp.route('/register_fixed')
def register_fixed():
    return render_template('register_fixed.html')

@auth_bp.route('/register_with_age', methods=['POST'])
def register_with_age():
    age_confirmed = request.form.get('age_confirmed')
    if not age_confirmed:
        flash('You must confirm you are 18+ to register.', 'error')
        return redirect(url_for('auth.register_fixed'))
    
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    phone = request.form.get('phone', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not all([username, email, password]):
        flash('Please fill in all required fields.', 'error')
        return redirect(url_for('auth.register_fixed'))
    
    if password != confirm_password:
        flash('Passwords do not match!', 'error')
        return redirect(url_for('auth.register_fixed'))
    
    if len(password) < 6:
        flash('Password must be at least 6 characters long.', 'error')
        return redirect(url_for('auth.register_fixed'))
    
    try:
        with db_manager.get_connection() as conn:
            c = conn.cursor()
            
            # Check if user exists
            c.execute('SELECT id FROM users WHERE username = ?', (username,))
            if c.fetchone():
                flash('Username is already taken. Please choose a different username.', 'error')
                return redirect(url_for('auth.register_fixed'))
                
            c.execute('SELECT id FROM users WHERE email = ?', (email,))
            if c.fetchone():
                flash('Email is already registered. Please use a different email or try logging in.', 'error')
                return redirect(url_for('auth.register_fixed'))
                
            if phone:
                c.execute('SELECT id FROM users WHERE phone = ?', (phone,))
                if c.fetchone():
                    flash('Phone number is already registered. Please use a different number.', 'error')
                    return redirect(url_for('auth.register_fixed'))
            
            # Create user
            hashed_password = generate_password_hash(password)
            referral_code = username[:3].upper() + ''.join([str(random.randint(0, 9)) for _ in range(4)])
            
            c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code) 
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     (username, email, hashed_password, 0.0, phone, referral_code))
            conn.commit()
            
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('auth.login'))
            
    except Exception as e:
        flash('Registration failed. Please try again.', 'error')
        return redirect(url_for('auth.register_fixed'))