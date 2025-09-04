from flask import jsonify, flash, redirect, url_for, request, session
import logging

def handle_user_friendly_errors(app):
    """Add user-friendly error handlers"""
    
    @app.errorhandler(429)
    def rate_limit_handler(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Too many requests. Please slow down.'}), 429
        flash('Too many requests. Please wait a moment and try again.', 'warning')
        return redirect(request.referrer or url_for('home'))
    
    @app.errorhandler(500)
    def server_error_handler(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Server error. Please try again.'}), 500
        flash('Something went wrong. Please try again.', 'error')
        return redirect(url_for('dashboard') if 'user_id' in session else url_for('home'))
    
    @app.errorhandler(404)
    def not_found_handler(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not found'}), 404
        flash('Page not found.', 'error')
        return redirect(url_for('dashboard') if 'user_id' in session else url_for('home'))

def log_user_actions(action, user_id=None, details=None):
    """Log important user actions"""
    logging.info(f"Action: {action}, User: {user_id}, Details: {details}")