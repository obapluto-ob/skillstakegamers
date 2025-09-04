from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash
import sqlite3

def fixed_login():
    """Fixed login route with proper error handling"""
    if request.method == 'POST':
        try:
            login_input = request.form.get('login_input', '').strip()
            password = request.form.get('password', '')
            
            if not login_input or not password:
                flash('Please enter both username/phone and password!', 'error')
                return render_template('login.html')
            
            with sqlite3.connect("gamebet.db") as conn:
                c = conn.cursor()
                
                # Check if user exists
                c.execute('SELECT id, username, email, password, balance FROM users WHERE username = ? OR phone = ?', 
                         (login_input, login_input))
                user = c.fetchone()
                
                if user and check_password_hash(user[3], password):
                    # Successful login
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    session['balance'] = user[4]
                    
                    # Set admin flag
                    session['is_admin'] = (user[1] == 'admin')
                    
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid username/M-Pesa number or password!', 'error')
                    
        except sqlite3.Error as e:
            flash('Database error occurred. Please try again.', 'error')
        except Exception as e:
            flash('Login error occurred. Please try again.', 'error')
    
    return render_template('login.html')