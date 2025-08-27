from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re

app = Flask(__name__)
app.secret_key = 'gamebet_secret_key_2024'

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/matches')
def matches():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('matches.html', available_matches=[], my_matches=[])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        
        conn = sqlite3.connect('gamebet.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['balance'] = user[4]
            conn.close()
            return redirect(url_for('dashboard'))
        
        conn.close()
        flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=None, matches=[])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)