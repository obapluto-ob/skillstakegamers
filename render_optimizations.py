import os
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

def optimize_for_render(app):
    """Optimize Flask app for Render free tier"""
    
    # Reduce memory usage
    app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max upload
    
    # Cache static files
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 year
    
    # Optimize session
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Rate limiting for free tier
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["200 per hour", "50 per minute"]
    )
    
    return app

# Keep-alive endpoint for free tier
def add_keepalive_route(app):
    @app.route('/keepalive')
    def keepalive():
        return {'status': 'alive', 'platform': 'render'}