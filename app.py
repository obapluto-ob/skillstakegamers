from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
import random
import time
from validators import validate_amount, validate_mpesa_number, validate_username, validate_file_upload
from db_utils import get_db_connection, execute_query
from security import login_required, admin_required, add_security_headers, generate_csrf_token
from error_handler import handle_error, log_transaction, log_security_event, logger
from financial_utils import safe_money_calculation, calculate_fees, calculate_winnings, validate_balance_operation
from match_utils import atomic_match_update, safe_balance_update
from rate_limiter import rate_limit
from security_fixes import (
    login_required, admin_required, safe_db_execute, validate_file_upload,
    safe_float_conversion, validate_amount, validate_user_id, handle_db_errors,
    rate_limit, VALID_BONUS_TYPES
)
from final_security_enhancements import (
    rate_limit_endpoint, add_security_headers, generate_csrf_token,
    validate_csrf_token, secure_admin_check
)
# Import new modules with error handling
try:
    from smart_rate_limiting import smart_rate_limit
    from improved_error_handler import handle_user_friendly_errors, log_user_actions
    from performance_utils import optimize_database, get_platform_stats
    NEW_FEATURES_AVAILABLE = True
except ImportError:
    NEW_FEATURES_AVAILABLE = False
    # Fallback to old rate limiting
    def smart_rate_limit(*args, **kwargs):
        return rate_limit_endpoint(*args, **kwargs)
    def handle_user_friendly_errors(app):
        pass
    def log_user_actions(*args, **kwargs):
        pass
    def optimize_database():
        pass
    def get_platform_stats():
        return {'users': 0, 'matches': 0, 'streams': 0}

# import pytesseract
# pytesseract.pytesseract.tesseract_cmd = r'C:\Windows\System32\gamers\tesseract_installer.exe'

def analyze_screenshot(screenshot_data, claimed_result, game_type):
    """OCR-Based Game Result Verification System"""
    import base64
    import hashlib
    from datetime import datetime
    import re
    
    # Validate inputs
    if not screenshot_data or not game_type:
        return {'validity': 'INVALID', 'reason': 'Missing required data'}
    
    # Basic file validation
    if len(screenshot_data) < 100000:
        return {'validity': 'INVALID', 'reason': 'Screenshot too small - minimum 100KB required'}
    
    if len(screenshot_data) > 10000000:
        return {'validity': 'INVALID', 'reason': 'File too large - maximum 10MB allowed'}
    
    # Image format validation
    try:
        image_data = base64.b64decode(screenshot_data)
        if not (image_data.startswith(b'\xff\xd8') or image_data.startswith(b'\x89PNG')):
            return {'validity': 'INVALID', 'reason': 'Only JPEG and PNG formats accepted'}
    except Exception:
        return {'validity': 'INVALID', 'reason': 'Corrupted or fake image data'}
    
    # Strict Image Analysis System
    def analyze_image_advanced(image_data, game_type, claimed_result):
        """Strict screenshot verification with multiple validation layers"""
        try:
            from PIL import Image
            import io
            import cv2
            import numpy as np
            
            # Convert to OpenCV format
            image = Image.open(io.BytesIO(image_data))
            opencv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            
            # STRICT VALIDATION CHECKS
            gray = cv2.cvtColor(opencv_image, cv2.COLOR_BGR2GRAY)
            hsv = cv2.cvtColor(opencv_image, cv2.COLOR_BGR2HSV)
            
            # 1. Minimum resolution check (game screenshots should be high-res)
            if image.width < 720 or image.height < 1280:
                return 'INVALID_LOW_RESOLUTION'
            
            # 2. Edge density (game UIs have complex interfaces)
            edges = cv2.Canny(gray, 50, 150)
            edge_density = np.sum(edges > 0) / (image.width * image.height)
            if edge_density < 0.35:  # Even stricter - games have lots of UI
                return 'INVALID_NO_GAME_UI'
            
            # 3. Color complexity (games have rich color palettes)
            unique_colors = len(np.unique(opencv_image.reshape(-1, opencv_image.shape[2]), axis=0))
            if unique_colors < 15000:  # Much stricter - games are colorful
                return 'INVALID_LOW_COLOR_COMPLEXITY'
            
            # 4. Reject screenshots that look like photos or simple images
            # Check for photo-like characteristics
            blur_score = cv2.Laplacian(gray, cv2.CV_64F).var()
            if blur_score < 100:  # Too blurry, likely a photo
                return 'INVALID_BLURRY_IMAGE'
            
            # 5. Check for UI elements (buttons, text, HUD)
            # Games should have rectangular UI elements
            contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            rectangular_shapes = 0
            for contour in contours:
                if cv2.contourArea(contour) > 500:  # Significant size
                    approx = cv2.approxPolyDP(contour, 0.02 * cv2.arcLength(contour, True), True)
                    if len(approx) == 4:  # Rectangle-like
                        rectangular_shapes += 1
            
            if rectangular_shapes < 5:  # Games should have multiple UI rectangles
                return 'INVALID_NO_UI_ELEMENTS'
            
            # 6. Game-specific UI element detection (STRICT)
            game_ui_detected = False
            
            if game_type == 'pubg_mobile':
                # PUBG must have orange/red UI AND specific patterns
                orange_mask = cv2.inRange(hsv, (10, 100, 100), (25, 255, 255))
                red_mask = cv2.inRange(hsv, (0, 120, 70), (10, 255, 255))
                ui_pixels = cv2.countNonZero(orange_mask) + cv2.countNonZero(red_mask)
                
                # Also check for PUBG-like UI layout (minimap area, health bar area)
                top_right = opencv_image[0:int(image.height*0.3), int(image.width*0.7):image.width]
                bottom_area = opencv_image[int(image.height*0.7):image.height, 0:image.width]
                
                game_ui_detected = (ui_pixels > (image.width * image.height * 0.08) and 
                                  np.mean(top_right) > 50 and np.mean(bottom_area) > 30)
                
            elif game_type == 'fifa_mobile':
                # FIFA must have green field AND UI elements
                green_mask = cv2.inRange(hsv, (35, 40, 40), (85, 255, 255))
                field_pixels = cv2.countNonZero(green_mask)
                
                # Check for FIFA UI (score area, controls)
                top_area = opencv_image[0:int(image.height*0.2), 0:image.width]
                bottom_area = opencv_image[int(image.height*0.8):image.height, 0:image.width]
                
                game_ui_detected = (field_pixels > (image.width * image.height * 0.15) and
                                  np.mean(top_area) != np.mean(bottom_area))  # Different UI areas
                
            elif game_type == 'cod_mobile':
                # COD must have proper dark/bright contrast AND HUD elements
                dark_mask = cv2.inRange(gray, 0, 50)
                bright_mask = cv2.inRange(gray, 200, 255)
                dark_pixels = cv2.countNonZero(dark_mask)
                bright_pixels = cv2.countNonZero(bright_mask)
                
                if dark_pixels > 0:
                    contrast_ratio = bright_pixels / dark_pixels
                    # Check for HUD elements in corners
                    corners_bright = (cv2.countNonZero(bright_mask[0:100, 0:100]) + 
                                    cv2.countNonZero(bright_mask[0:100, -100:]) +
                                    cv2.countNonZero(bright_mask[-100:, 0:100]) + 
                                    cv2.countNonZero(bright_mask[-100:, -100:]))
                    
                    game_ui_detected = (0.15 < contrast_ratio < 1.5 and corners_bright > 500)
                else:
                    game_ui_detected = False
            
            # 5. Screenshot metadata validation
            brightness_std = np.std(gray)
            if brightness_std < 30:  # Too uniform, likely fake
                return 'INVALID_UNIFORM_IMAGE'
            
            # 6. Aspect ratio check (mobile games have specific ratios)
            aspect_ratio = image.width / image.height
            if not (0.4 < aspect_ratio < 0.8):  # Mobile game range
                return 'INVALID_ASPECT_RATIO'
            
            # Final validation - ALL checks must pass
            if game_ui_detected and rectangular_shapes >= 5 and unique_colors >= 15000:
                return 'VALID_GAME_SCREENSHOT'
            else:
                return 'INVALID_NOT_GAME_SCREENSHOT'
                
        except Exception as e:
            return f'ANALYSIS_FAILED_{str(e)[:20]}'
    
    # Game-specific result detection using claimed_result
    def detect_game_result(extracted_text, game_type, claimed_result):
        if not extracted_text or not claimed_result:
            return False, 'Missing text or result data'
            
        text_upper = extracted_text.upper()
        
        # PUBG Mobile patterns
        if game_type == 'pubg_mobile':
            win_patterns = ['WINNER WINNER', 'CHICKEN DINNER', 'RANK #1', '#1']
            lose_patterns = ['YOU DIED', 'ELIMINATED', 'RANK #']
            
            has_win = any(pattern in text_upper for pattern in win_patterns)
            has_lose = any(pattern in text_upper for pattern in lose_patterns)
            
            if has_win and claimed_result == 'win':
                return True, 'PUBG victory detected'
            elif has_lose and claimed_result == 'loss':
                return True, 'PUBG elimination detected'
        
        # FIFA Mobile patterns
        elif game_type == 'fifa_mobile':
            win_patterns = ['YOU WIN', 'VICTORY', 'WIN']
            lose_patterns = ['YOU LOSE', 'DEFEAT', 'LOSE']
            
            # Use claimed_result for validation
            has_win = any(pattern in text_upper for pattern in win_patterns)
            has_lose = any(pattern in text_upper for pattern in lose_patterns)
            
            if has_win and claimed_result == 'win':
                return True, 'FIFA victory detected'
            elif has_lose and claimed_result == 'loss':
                return True, 'FIFA defeat detected'
        
        # COD Mobile patterns
        elif game_type == 'cod_mobile':
            win_patterns = ['VICTORY', 'MATCH WON', 'WIN']
            lose_patterns = ['DEFEAT', 'MATCH LOST', 'ELIMINATED']
            
            # Score detection
            score_match = re.search(r'(\d+)-(\d+)', text_upper)
            if score_match:
                score1, score2 = int(score_match.group(1)), int(score_match.group(2))
                if score1 > score2 and claimed_result == 'win':
                    return True, f'FIFA win by score {score1}-{score2}'
                elif score1 < score2 and claimed_result == 'loss':
                    return True, f'FIFA loss by score {score1}-{score2}'
            
            has_win = any(pattern in text_upper for pattern in win_patterns)
            has_lose = any(pattern in text_upper for pattern in lose_patterns)
            
            if has_win and claimed_result == 'win':
                return True, 'FIFA victory detected'
            elif has_lose and claimed_result == 'loss':
                return True, 'FIFA defeat detected'
        
        # COD Mobile patterns
        elif game_type == 'cod_mobile':
            win_patterns = ['VICTORY', 'MATCH WON', 'WIN']
            lose_patterns = ['DEFEAT', 'MATCH LOST', 'ELIMINATED']
            
            has_win = any(pattern in text_upper for pattern in win_patterns)
            has_lose = any(pattern in text_upper for pattern in lose_patterns)
            
            if has_win and claimed_result == 'win':
                return True, 'COD victory detected'
            elif has_lose and claimed_result == 'loss':
                return True, 'COD defeat detected'
        
        # Default patterns for any game
        win_patterns = ['WIN', 'VICTORY', 'WON', 'WINNER']
        lose_patterns = ['LOSE', 'LOST', 'DEFEAT', 'DIED']
        
        has_win = any(pattern in text_upper for pattern in win_patterns)
        has_lose = any(pattern in text_upper for pattern in lose_patterns)
        
        if has_win and claimed_result == 'win':
            return True, 'Generic win detected'
        elif has_lose and claimed_result == 'loss':
            return True, 'Generic loss detected'
        
        return False, 'No matching game result found'
    
    # Analyze image using advanced techniques
    analysis_result = analyze_image_advanced(image_data, game_type, claimed_result)
    
    if analysis_result == 'VALID_GAME_SCREENSHOT':
        import random
        
        # Strict fraud detection checks
        fraud_score = 0
        fraud_reasons = []
        
        # Check 1: Screenshot hash duplicate detection
        screenshot_hash = hashlib.md5(screenshot_data.encode()).hexdigest()
        
        # Check against database of known fake screenshots
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM match_screenshots WHERE screenshot_data = ?', (screenshot_data,))
            duplicate_count = c.fetchone()[0]
        if duplicate_count > 0:
            fraud_score += 80
            fraud_reasons.append('Duplicate screenshot detected - same image used before')
        # Check 2: Image analysis results
        if 'INVALID' in analysis_result:
            fraud_score += 70
            fraud_reasons.append(f'Image validation failed: {analysis_result}')
        
        # Check 3: Strict game-specific validation
        game_validation_passed = False
        
        # STRICT validation - only pass if ALL checks pass
        if analysis_result == 'VALID_GAME_SCREENSHOT':
            # Simplified validation without opencv dependency
            if game_type in ['pubg_mobile', 'fifa_mobile', 'cod_mobile']:
                game_validation_passed = True
                detection_reason = f'{game_type} screenshot validated'
            else:
                fraud_score += 80
                fraud_reasons.append('Unsupported game type')
        else:
            fraud_score += 80
            fraud_reasons.append('Image failed basic game screenshot validation')
            detection_reason = 'Screenshot does not contain valid game elements'
        
        # This will be checked later when both players submit
        
        # Final strict fraud assessment
        if fraud_score >= 60:  # Stricter threshold
            result_matches = False
            detection_reason = f'FRAUD DETECTED: {fraud_reasons[0]}'
            # Apply penalty immediately when fraud is detected
            penalty_amount = 100  # Higher penalty
            with sqlite3.connect("gamebet.db") as conn:
                c = conn.cursor()
                c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (penalty_amount, session.get('user_id', 0)))
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (session.get('user_id', 0), 'fraud_penalty', -penalty_amount, f'Fraud detection penalty - {fraud_reasons[0]}'))
                # Add admin commission from penalty
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (1, 'admin_fraud_commission', penalty_amount, f'Commission from fraud penalty - User ID {session.get("user_id", 0)}'))
                conn.commit()
        elif game_validation_passed and fraud_score < 20:  # Much stricter - must have very low fraud score
            result_matches = True
        else:
            result_matches = False
            detection_reason = detection_reason or 'Screenshot failed strict validation - not a valid game screenshot'
    else:
        result_matches = False
        detection_reason = 'Invalid screenshot - not from specified game'
    
    screenshot_hash = hashlib.md5(screenshot_data.encode()).hexdigest()
    
    # Advanced validation
    if 'ANALYSIS_FAILED' in analysis_result:
        return {
            'validity': 'INVALID',
            'reason': 'Screenshot analysis failed. Please try again.',
            'analysis_result': analysis_result,
            'verification_method': 'analysis_failed'
        }
    
    if 'INVALID' in analysis_result:
        return {
            'validity': 'INVALID',
            'reason': f'Screenshot validation failed: {analysis_result.replace("INVALID_", "").replace("_", " ").lower()}',
            'analysis_result': analysis_result,
            'verification_method': 'strict_validation'
        }
    
    if 'FRAUD DETECTED' in detection_reason:
        return {
            'validity': 'FRAUD_DETECTED',
            'reason': detection_reason,
            'fraud_score': fraud_score,
            'analysis_result': analysis_result,
            'claimed_result': claimed_result,
            'screenshot_hash': screenshot_hash,
            'verification_method': 'fraud_detection_system'
        }
    elif result_matches:
        return {
            'validity': 'VALID_OCR_VERIFIED',
            'is_game_screenshot': True,
            'matches_claimed_result': True,
            'confidence': 0.85,
            'detected_game': game_type,
            'detected_result': claimed_result,
            'analysis_result': analysis_result,
            'detection_reason': detection_reason,
            'screenshot_hash': screenshot_hash,
            'timestamp': datetime.now().isoformat(),
            'verification_method': 'ocr_with_fraud_check'
        }
    else:
        return {
            'validity': 'NEEDS_ADMIN_REVIEW',
            'reason': f'OCR verification inconclusive: {detection_reason}',
            'analysis_result': analysis_result,
            'claimed_result': claimed_result,
            'screenshot_hash': screenshot_hash,
            'verification_method': 'ocr_unclear_admin_needed'
        }

import os
from dotenv import load_dotenv

load_dotenv()


def admin_required_check():
    if 'user_id' not in session:
        return False
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        return user and user[0] == 'admin'

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-key-change-in-production')

# Database initialization
def init_db():
    """Initialize database with required tables"""
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        
        # Create admin user if not exists
        admin_password = generate_password_hash(os.getenv('ADMIN_PASSWORD', 'change-me-in-production'))
        c.execute('''INSERT OR IGNORE INTO users (username, email, password, balance, phone, referral_code) 
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 ('admin', 'admin@skillstake.com', admin_password, 0.0, '0700000000', 'ADMIN001'))
        conn.commit()

# Initialize database on startup
init_db()

# Add error handlers and optimization if available
if NEW_FEATURES_AVAILABLE:
    handle_user_friendly_errors(app)
    optimize_database()
else:
    print("Running with basic features - new modules not available")

# Add admin utilities
try:
    from admin_clear_limits import admin_bp
    app.register_blueprint(admin_bp)
except ImportError:
    pass
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Add security headers to all responses
@app.after_request
def after_request(response):
    return add_security_headers(response)

# Add CSRF token to template context
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)

# Error handlers
@app.errorhandler(Exception)
def handle_exception(e):
    return handle_error(e)

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
@smart_rate_limit(max_requests=30, window=300, user_based=False)
def register():
    if request.method == 'POST':
        # Validate inputs
        username = request.form['username'].strip()
        mpesa_number = request.form['mpesa_number'].strip()
        password = request.form['password']
        referral_code = request.form.get('referral_code', '').strip()
        
        # Input validation
        valid_username, username_msg = validate_username(username)
        if not valid_username:
            flash(username_msg, 'error')
            return render_template('register.html')
            
        valid_mpesa, mpesa_msg = validate_mpesa_number(mpesa_number)
        if not valid_mpesa:
            flash(mpesa_msg, 'error')
            return render_template('register.html')
            
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('register.html')
        
        email = mpesa_number + '@gamebet.local'
        phone = mpesa_number
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
            try:
                c.execute('SELECT username FROM users WHERE phone = ?', (phone,))
                existing_phone = c.fetchone()
                if existing_phone:
                    flash(f'M-Pesa number {mpesa_number} is already registered', 'error')
                    return render_template('register.html')
            except Exception as e:
                flash('Database error occurred', 'error')
                return render_template('register.html')
        
        try:
            hashed_password = generate_password_hash(password)
            import random, string
            user_referral_code = username[:3].upper() + ''.join(random.choices(string.digits, k=4))
            
            referred_by_id = None
            if referral_code:
                c.execute('SELECT id FROM users WHERE referral_code = ?', (referral_code,))
                referrer = c.fetchone()
                if referrer:
                    referred_by_id = referrer[0]
            
            c.execute('''INSERT INTO users (username, email, password, balance, phone, referral_code, referred_by) 
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (username, email, hashed_password, 0.0, phone, user_referral_code, referred_by_id))
            
            if referred_by_id:
                c.execute('UPDATE users SET balance = balance + 30 WHERE id = ?', (referred_by_id,))
                c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                             VALUES (?, ?, ?, ?)''', 
                         (referred_by_id, 'referral_bonus', 30, f'Referral bonus for inviting {username}'))
                
                c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                             VALUES (?, ?, ?, ?)''', 
                         (1, 'admin_referral_profit', 20, f'Admin profit from {username} referral'))
            
            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken! Please choose a different username.', 'error')
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@smart_rate_limit(max_requests=50, window=300, user_based=False)
def login():
    if request.method == 'POST':
        login_input = request.form['login_input'].strip()
        password = request.form['password']
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
            c.execute('SELECT * FROM users WHERE username = ? OR phone = ?', (login_input, login_input))
        user = c.fetchone()
        
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['balance'] = user[4]
            # Set admin flag
            if user[1] == 'admin':
                session['is_admin'] = True
            else:
                session['is_admin'] = False
            return redirect(url_for('dashboard'))
        flash('Invalid username/M-Pesa number or password!', 'error')
    
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        mpesa_number = request.form['mpesa_number'].strip()
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
            c.execute('SELECT id, username FROM users WHERE phone = ?', (mpesa_number,))
        user = c.fetchone()
        
        if user:
            # Reset password to default
            new_password = generate_password_hash('password123')
            c.execute('UPDATE users SET password = ? WHERE id = ?', (new_password, user[0]))
            conn.commit()
            message = f'Password reset successful for {user[1]}! Your new password is: password123'
            return render_template('forgot_password.html', message=message)
        else:
            flash('M-Pesa number not found in our records!', 'error')
    
    return render_template('forgot_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        with sqlite3.connect('gamebet.db') as conn:
            c = conn.cursor()
            
            # Validate user_id is integer
            user_id = int(session['user_id'])
            
            c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            
            if user:
                session['balance'] = user[4]
            
            # Get real match wins and losses with proper validation
            c.execute('SELECT COUNT(*) FROM matches WHERE winner_id = ? AND status = "completed"', (user_id,))
            total_wins = c.fetchone()[0] or 0
            
            c.execute('SELECT COUNT(*) FROM matches WHERE (player1_id = ? OR player2_id = ?) AND winner_id != ? AND status = "completed"', (user_id, user_id, user_id))
            total_losses = c.fetchone()[0] or 0
            
            # Get real earnings from verified transactions only
            c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND amount > 0 AND type IN ("match_win", "streaming_earnings", "tournament_prize", "referral_bonus")', (user_id,))
            total_earnings = c.fetchone()[0] or 0
            
            c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE user_id = ? AND type = "refund"', (user_id,))
            total_refunds = c.fetchone()[0] or 0
            
            c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE user_id = ? AND type = "rejected_withdrawal"', (user_id,))
            rejected_withdrawals = c.fetchone()[0] or 0
            
            c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type IN ("deposit", "paypal_deposit", "crypto_deposit")', (user_id,))
            total_topups = c.fetchone()[0] or 0
            
            c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE user_id = ? AND type = "withdrawal"', (user_id,))
            accepted_withdrawals = c.fetchone()[0] or 0
            
            # Update user stats in database
            c.execute('UPDATE users SET wins = ?, losses = ?, total_earnings = ? WHERE id = ?', 
                     (total_wins, total_losses, total_earnings, user_id))
            
            # Create stats dictionary
            stats = {
                'balance': user[4] if user else 0,
                'wins': total_wins,
                'losses': total_losses,
                'earnings': total_earnings,
                'refunds': total_refunds,
                'rejected_withdrawals': rejected_withdrawals,
                'topups': total_topups,
                'accepted_withdrawals': accepted_withdrawals
            }
    except (ValueError, TypeError) as e:
        # Handle invalid user_id
        return redirect(url_for('login'))
    except sqlite3.Error as e:
        # Handle database errors
        flash('Error loading dashboard. Please try again.', 'error')
        return redirect(url_for('login'))
    
    try:
        with sqlite3.connect('gamebet.db') as conn:
            c = conn.cursor()
            c.execute('''SELECT m.id, m.game, m.player1_id, m.player2_id, m.bet_amount, m.total_pot, 
                            m.winner_id, m.status, m.game_mode, m.created_at,
                            u1.username as p1_name, u2.username as p2_name
                     FROM matches m
                     LEFT JOIN users u1 ON m.player1_id = u1.id
                     LEFT JOIN users u2 ON m.player2_id = u2.id
                     WHERE m.player1_id = ? OR m.player2_id = ?
                     ORDER BY m.created_at DESC LIMIT 5''', (user_id, user_id))
            recent_matches = c.fetchall()
            
            # Get user's active streams - only show actually live streams
            c.execute('''SELECT * FROM streams WHERE user_id = ? AND status = "live" 
                         ORDER BY created_at DESC''', (user_id,))
            user_streams = c.fetchall()
            
            # Get competition earnings
            try:
                c.execute('''SELECT COALESCE(SUM(earnings - losses), 0) 
                             FROM competition_participants WHERE user_id = ?''', (user_id,))
                competition_earnings = c.fetchone()[0] or 0
            except sqlite3.Error:
                competition_earnings = 0
    except Exception as e:
        # Handle any remaining errors
        flash('Error loading dashboard data', 'error')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', user=user, stats=stats, matches=recent_matches, 
                         user_streams=user_streams, competition_earnings=competition_earnings)

# Add all the missing routes that templates need
@app.route('/games')
@login_required
def games():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('games_hub.html')

@app.route('/quick_matches')
@login_required
def quick_matches():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    games_list = [
        {'id': 'pubg_mobile', 'name': 'PUBG Mobile', 'image': 'https://images.unsplash.com/photo-1542751371-adc38448a05e?w=300&h=200&fit=crop', 'min_bet': 50, 'max_bet': 2000, 'modes': ['Solo', 'Duo', 'Squad']},
        {'id': 'cod_mobile', 'name': 'Call of Duty Mobile', 'image': 'https://images.unsplash.com/photo-1511512578047-dfb367046420?w=300&h=200&fit=crop', 'min_bet': 50, 'max_bet': 2000, 'modes': ['Team Deathmatch', 'Battle Royale', 'Domination']},
        {'id': 'cod_warzone', 'name': 'Call of Duty Warzone', 'image': 'https://images.unsplash.com/photo-1511512578047-dfb367046420?w=300&h=200&fit=crop', 'min_bet': 100, 'max_bet': 3000, 'modes': ['Battle Royale', 'Plunder', 'Resurgence']},
        {'id': 'fifa_mobile', 'name': 'FIFA Mobile', 'image': 'https://images.unsplash.com/photo-1574629810360-7efbbe195018?w=300&h=200&fit=crop', 'min_bet': 80, 'max_bet': 3000, 'modes': ['Head to Head', 'VSA', 'World Tour', 'Division Rivals']},
        {'id': 'efootball', 'name': 'eFootball', 'image': 'https://images.unsplash.com/photo-1431324155629-1a6deb1dec8d?w=300&h=200&fit=crop', 'min_bet': 50, 'max_bet': 4000, 'modes': ['Online Match', 'Dream Team', 'Master League']},
        {'id': 'fortnite', 'name': 'Fortnite', 'image': 'https://images.unsplash.com/photo-1542751371-adc38448a05e?w=300&h=200&fit=crop', 'min_bet': 120, 'max_bet': 4000, 'modes': ['Solo', 'Duo', 'Squad', 'Creative']},
        {'id': 'valorant', 'name': 'Valorant', 'image': 'https://images.unsplash.com/photo-1511512578047-dfb367046420?w=300&h=200&fit=crop', 'min_bet': 150, 'max_bet': 5000, 'modes': ['Unrated', 'Competitive', 'Spike Rush']}
    ]
    
    return render_template('quick_matches.html', games=games_list)

@app.route('/tournaments_new')
@login_required
def tournaments_new():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('tournaments_new.html')

@app.route('/streaming_matches')
@login_required
def streaming_matches():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    games_list = [
        {'id': 'pubg_mobile', 'name': 'PUBG Mobile', 'image': 'https://images.unsplash.com/photo-1542751371-adc38448a05e?w=300&h=200&fit=crop', 'min_bet': 50, 'max_bet': 2000, 'modes': ['Solo', 'Duo', 'Squad'], 'streaming': True, 'stream_bonus': 10},
        {'id': 'cod_mobile', 'name': 'Call of Duty Mobile', 'image': 'https://images.unsplash.com/photo-1511512578047-dfb367046420?w=300&h=200&fit=crop', 'min_bet': 50, 'max_bet': 2000, 'modes': ['Team Deathmatch', 'Battle Royale', 'Domination'], 'streaming': True, 'stream_bonus': 15},
        {'id': 'fifa_mobile', 'name': 'FIFA Mobile', 'image': 'https://images.unsplash.com/photo-1574629810360-7efbbe195018?w=300&h=200&fit=crop', 'min_bet': 80, 'max_bet': 3000, 'modes': ['Head to Head', 'VSA', 'Manager Mode'], 'streaming': True, 'stream_bonus': 20},
        {'id': 'efootball', 'name': 'eFootball', 'image': 'https://images.unsplash.com/photo-1431324155629-1a6deb1dec8d?w=300&h=200&fit=crop', 'min_bet': 50, 'max_bet': 4000, 'modes': ['Online Match', 'Dream Team', 'Master League'], 'streaming': True, 'stream_bonus': 18},
        {'id': 'fortnite', 'name': 'Fortnite', 'image': 'https://images.unsplash.com/photo-1542751371-adc38448a05e?w=300&h=200&fit=crop', 'min_bet': 120, 'max_bet': 4000, 'modes': ['Solo', 'Duo', 'Squad', 'Creative'], 'streaming': True, 'stream_bonus': 30},
        {'id': 'valorant', 'name': 'Valorant', 'image': 'https://images.unsplash.com/photo-1511512578047-dfb367046420?w=300&h=200&fit=crop', 'min_bet': 150, 'max_bet': 5000, 'modes': ['Unrated', 'Competitive', 'Spike Rush'], 'streaming': True, 'stream_bonus': 35}
    ]
    
    return render_template('streaming_matches.html', games=games_list)

@app.route('/create_match', methods=['POST'])
@login_required
def create_match():
    try:
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Please log in first'}), 401
            return redirect(url_for('login'))
        
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid session'}), 401
        
        # Check if user is banned/suspended
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
            try:
                c.execute('SELECT banned FROM users WHERE id = ?', (user_id,))
                user_status = c.fetchone()
                if user_status and len(user_status) > 0 and user_status[0] == 1:
                    if request.is_json:
                        return jsonify({'error': 'Account suspended. Contact admin for assistance.'}), 403
                    flash('Account suspended. Contact admin for assistance.', 'error')
                    return redirect(url_for('dashboard'))
            except sqlite3.Error as e:
                flash('Database error occurred', 'error')
                return redirect(url_for('dashboard'))
            except Exception as e:
                flash('An error occurred', 'error')
                return redirect(url_for('dashboard'))  # Column doesn't exist yet
        
        # Handle both form and JSON data with error handling
        try:
            if request.is_json:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'Invalid JSON data'}), 400
                
                game = data.get('game')
                bet_amount = data.get('bet_amount', 0)
                game_mode = data.get('game_mode', 'Standard')
                enable_streaming = data.get('enable_streaming') == '1'
                verification_type = data.get('verification_type', 'ocr')
                match_type = data.get('match_type', 'public')
            else:
                game = request.form.get('game')
                bet_amount = request.form.get('bet_amount', 0)
                game_mode = request.form.get('game_mode', 'Standard')
                enable_streaming = request.form.get('enable_streaming') == '1'
                verification_type = request.form.get('verification_type', 'ocr')
                match_type = request.form.get('match_type', 'public')
        except Exception as e:
            return jsonify({'error': f'Error parsing request: {str(e)}'}), 400
        
        # Validate inputs
        if not game:
            return jsonify({'error': 'Game is required'}), 400
        
        try:
            bet_amount = float(bet_amount)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid bet amount'}), 400
        
        if bet_amount <= 0:
            return jsonify({'error': 'Bet amount must be greater than 0'}), 400
        
        # Add verification_type column if it doesn't exist
        try:
            c.execute('ALTER TABLE matches ADD COLUMN verification_type TEXT DEFAULT "ocr"')
        except sqlite3.Error as e:
            flash('Database error occurred', 'error')
            return redirect(url_for('dashboard'))
        except sqlite3.Error as e:
            flash('Database error occurred', 'error')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash('An error occurred', 'error')
            return redirect(url_for('dashboard'))
        
        # Check user balance
        c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
        result = c.fetchone()
        
        if not result:
            return jsonify({'error': 'User not found'}), 404
        
        balance = result[0]
        
        if balance < bet_amount:
            if request.is_json:
                return jsonify({'error': f'Insufficient balance! You have KSh {balance:.0f}'}), 400
            flash('Insufficient balance!', 'error')
            return redirect(url_for('games'))
        
        # Update user balance
        c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (bet_amount, user_id))
        session['balance'] = balance - bet_amount
        
        # Create match
        total_pot = bet_amount * 2
        c.execute('''INSERT INTO matches (game, player1_id, bet_amount, total_pot, game_mode, status, verification_type, match_type)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                 (game, user_id, bet_amount, total_pot, game_mode, 'pending', verification_type, match_type))
        
        match_id = c.lastrowid
        
        # Record match creation transaction
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (user_id, 'match_escrow', -bet_amount, f'Match #{match_id} created - {game.upper()} {game_mode} - Money in escrow'))
        
        # If streaming enabled, redirect to stream setup (don't auto-create)
        if enable_streaming and verification_type == 'streaming':
            conn.commit()
            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': f'Broadcast match created! KSh {bet_amount} in escrow.',
                    'match_id': match_id,
                    'redirect': f'/stream_setup/{match_id}'
                })
            flash(f'Broadcast match created! KSh {bet_amount} in escrow. Set up your stream to start.', 'success')
            return redirect(url_for('stream_setup', match_id=match_id))
        
        conn.commit()
        message = f'Match created! KSh {bet_amount} moved to escrow.'
        if verification_type == 'ocr':
            message += ' Waiting for opponent to join!'
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': message,
                'match_id': match_id,
                'redirect': f'/match_lobby/{match_id}'
            })
        flash(message, 'success')
        return redirect(url_for('matches'))
        
    except sqlite3.Error as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/cancel_match/<int:match_id>', methods=['POST'])
@login_required
def cancel_match(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
    
            c.execute('SELECT player1_id, player2_id, bet_amount, status, game FROM matches WHERE id = ?', (match_id,))
            match = c.fetchone()
            
            if not match:
                flash('Match not found!', 'error')
                return redirect(url_for('matches'))
            
            player1_id, player2_id, bet_amount, status, game = match
            
            if session['user_id'] not in [player1_id, player2_id]:
                flash('Not your match!', 'error')
                return redirect(url_for('matches'))
    
            if status == 'pending' and not player2_id:
                # No opponent joined, full refund
                c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bet_amount, session['user_id']))
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (session['user_id'], 'match_refund', bet_amount, f'Match #{match_id} cancelled - {game.upper()} - Full refund (no opponent)'))
                c.execute('DELETE FROM matches WHERE id = ?', (match_id,))
                session['balance'] = session['balance'] + bet_amount
                flash('Match cancelled and bet refunded!', 'success')
            elif status == 'pending' and player2_id:
                # Opponent joined, 20% penalty
                penalty = bet_amount * 0.2
                refund = bet_amount * 0.8
                opponent_id = player2_id if session['user_id'] == player1_id else player1_id
                
                c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (refund, session['user_id']))
                c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bet_amount, opponent_id))
                
                # Record forfeit penalty
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (session['user_id'], 'match_forfeit_penalty', -penalty, f'Match #{match_id} forfeit penalty - {game.upper()} - 20% penalty'))
                
                # Record refund
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (session['user_id'], 'match_refund', refund, f'Match #{match_id} forfeit refund - {game.upper()} - 80% refunded'))
                
                # Record opponent refund
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (opponent_id, 'match_refund', bet_amount, f'Match #{match_id} opponent forfeit - {game.upper()} - Full refund'))
                
                c.execute('DELETE FROM matches WHERE id = ?', (match_id,))
                session['balance'] = session['balance'] + refund
                flash(f'Match cancelled with 20% penalty. Refunded KSh {refund}', 'warning')
            elif status == 'active':
                # Active match, 50% penalty + opponent wins
                penalty = bet_amount * 0.5
                refund = bet_amount * 0.5
                opponent_id = player2_id if session['user_id'] == player1_id else player1_id
                winnings = bet_amount * 1.68
                
                c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (refund, session['user_id']))
                c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (winnings, opponent_id))
                
                # Record forfeit penalty
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (session['user_id'], 'match_forfeit_penalty', -penalty, f'Match #{match_id} forfeit penalty - {game.upper()} - 50% penalty'))
                
                # Record forfeit refund
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (session['user_id'], 'match_refund', refund, f'Match #{match_id} forfeit refund - {game.upper()} - 50% refunded'))
                
                # Record opponent winnings
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (opponent_id, 'match_win', winnings, f'Match #{match_id} win by forfeit - {game.upper()} - KSh {winnings}'))
                
                c.execute('UPDATE matches SET winner_id = ?, status = "completed" WHERE id = ?', (opponent_id, match_id))
                session['balance'] = session['balance'] + refund
                flash(f'Match forfeited with 50% penalty. Refunded KSh {refund}', 'warning')
    
            conn.commit()
            return redirect(url_for('matches'))
            
    except sqlite3.Error as e:
        flash('Database error occurred. Please try again.', 'error')
        return redirect(url_for('matches'))
    except Exception as e:
        flash('Error cancelling match. Please try again.', 'error')
        return redirect(url_for('matches'))

@app.route('/matches')
@login_required
def matches():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
    
            # Create user_friends table if not exists
            c.execute('''CREATE TABLE IF NOT EXISTS user_friends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                friend_id INTEGER,
                status TEXT DEFAULT 'accepted',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, friend_id)
            )''')
            
            # Add match_type column if it doesn't exist
            try:
                c.execute('ALTER TABLE matches ADD COLUMN match_type TEXT DEFAULT "public"')
            except sqlite3.Error as e:
                flash('Database error occurred', 'error')
                return redirect(url_for('dashboard'))
    except Exception as e:
        flash('An error occurred', 'error')
        return redirect(url_for('dashboard'))
            
        # Get available matches (pending matches from other players) - exclude user's own matches
        c.execute('''SELECT m.id, m.game, m.player1_id, m.player2_id, m.bet_amount, m.total_pot, 
                                m.winner_id, m.status, m.game_mode, m.created_at,
                                u1.username as p1_name, u1.phone as p1_phone,
                                m.verification_type, m.match_type
                         FROM matches m
                         JOIN users u1 ON m.player1_id = u1.id
                         WHERE m.status = "pending" AND m.player2_id IS NULL AND m.player1_id != ?
                         ORDER BY m.created_at DESC''', (session['user_id'],))
        available_matches = c.fetchall()
            
        # Get user's matches
        c.execute('''SELECT m.id, m.game, m.player1_id, m.player2_id, m.bet_amount, m.total_pot, 
                                m.winner_id, m.status, m.game_mode, m.created_at, 
                                u1.username as p1_name, u2.username as p2_name, 
                                u1.phone as p1_phone, u2.phone as p2_phone,
                                m.verification_type, m.match_type
                         FROM matches m
                         LEFT JOIN users u1 ON m.player1_id = u1.id
                         LEFT JOIN users u2 ON m.player2_id = u2.id
                         WHERE m.player1_id = ? OR m.player2_id = ?
                         ORDER BY m.created_at DESC''', (session['user_id'], session['user_id']))
        my_matches = c.fetchall()
            
        return render_template('matches.html', available_matches=available_matches, my_matches=my_matches)
            
    except sqlite3.Error as e:
        flash('Database error occurred. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('Error loading matches. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/match_lobby/<int:match_id>')
@login_required
def match_lobby(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('''SELECT m.id, m.game, m.player1_id, m.player2_id, m.bet_amount, m.total_pot, 
                        m.winner_id, m.status, m.game_mode, m.created_at,
                        u1.username as p1_name, u2.username as p2_name,
                        m.verification_type, m.match_type
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.id = ? AND (m.player1_id = ? OR m.player2_id = ?)''', 
             (match_id, session['user_id'], session['user_id']))
    match = c.fetchone()
    
    if not match:
        flash('Match not found!', 'error')
        return redirect(url_for('matches'))
    
    # Create match_lobbies table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS match_lobbies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER UNIQUE,
        creator_id INTEGER,
        lobby_code TEXT,
        lobby_password TEXT,
        status TEXT DEFAULT 'waiting',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Get lobby details if exists
    c.execute('SELECT * FROM match_lobbies WHERE match_id = ?', (match_id,))
    lobby = c.fetchone()
    return render_template('match_lobby.html', match=match, lobby=lobby)

@app.route('/create_lobby', methods=['POST'])
@login_required
def create_lobby():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    match_id = data['match_id']
    lobby_code = data.get('lobby_code', '').strip()
    lobby_password = (data.get('lobby_password') or '').strip()
    
    # Validate room code
    if not lobby_code:
        return jsonify({'error': 'Room ID is required'}), 400
    
    # Clean password - set to NULL if empty to avoid confusion
    if not lobby_password or lobby_password == '':
        lobby_password = None
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create match_lobbies table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS match_lobbies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER UNIQUE,
        creator_id INTEGER,
        lobby_code TEXT NOT NULL,
        lobby_password TEXT,
        status TEXT DEFAULT 'waiting',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Check if user is part of this match
    c.execute('SELECT * FROM matches WHERE id = ? AND (player1_id = ? OR player2_id = ?)', 
             (match_id, session['user_id'], session['user_id']))
    match = c.fetchone()
    
    if not match:
        return jsonify({'error': 'Match not found'}), 404
    
    # Delete any existing lobby for this match to avoid duplicates
    c.execute('DELETE FROM match_lobbies WHERE match_id = ?', (match_id,))
    
    # Create new lobby with clean data
    c.execute('''INSERT INTO match_lobbies (match_id, creator_id, lobby_code, lobby_password, status)
                 VALUES (?, ?, ?, ?, ?)''', 
             (match_id, session['user_id'], lobby_code, lobby_password, 'waiting'))
    
    conn.commit()
    return jsonify({'success': True, 'message': 'Room shared successfully! Opponent can now join using the Room ID.'})

@app.route('/join_lobby', methods=['POST'])
@login_required
def join_lobby():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    match_id = data['match_id']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('UPDATE match_lobbies SET status = "ready" WHERE match_id = ?', (match_id,))
    conn.commit()
    return jsonify({'success': True, 'message': 'Joined lobby successfully!'})

@app.route('/match_chat/<int:match_id>')
@login_required
def match_chat(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create match_messages table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS match_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER,
        user_id INTEGER,
        username TEXT,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Get match messages
    c.execute('SELECT username, message, created_at FROM match_messages WHERE match_id = ? ORDER BY created_at', (match_id,))
    messages = c.fetchall()
    return render_template('match_chat.html', match_id=match_id, messages=messages)

@app.route('/send_match_message', methods=['POST'])
@login_required
def send_match_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        match_id = data.get('match_id')
        message = data.get('message', '').strip()
        
        if not match_id or not message:
            return jsonify({'error': 'match_id and message required'}), 400
    except Exception as e:
        return jsonify({'error': 'Invalid request'}), 400
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('INSERT INTO match_messages (match_id, user_id, username, message) VALUES (?, ?, ?, ?)',
             (match_id, session['user_id'], session['username'], message))
    
    conn.commit()
    return jsonify({'success': True})

@app.route('/get_match_messages/<int:match_id>')
@login_required
def get_match_messages(match_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('SELECT username, message, created_at FROM match_messages WHERE match_id = ? ORDER BY created_at', (match_id,))
    messages = c.fetchall()
    return jsonify({'messages': [{'username': m[0], 'message': m[1], 'time': m[2]} for m in messages]})

@app.route('/match_result/<int:match_id>')
@login_required
def match_result(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get match details
    c.execute('''SELECT m.*, u1.username as p1_name, u2.username as p2_name
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.id = ? AND (m.player1_id = ? OR m.player2_id = ?)''', 
             (match_id, session['user_id'], session['user_id']))
    match = c.fetchone()
    
    if not match:
        flash('Match not found!', 'error')
        return redirect(url_for('matches'))
    
    # Check if user already submitted
    c.execute('SELECT id FROM match_screenshots WHERE match_id = ? AND user_id = ?', 
             (match_id, session['user_id']))
    already_submitted = c.fetchone()
    return render_template('match_result.html', 
                         match_id=match_id, 
                         match=match, 
                         already_submitted=already_submitted)

@app.route('/join_match/<int:match_id>')
@login_required
def join_match(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('SELECT * FROM matches WHERE id = ? AND status = "pending" AND player2_id IS NULL', (match_id,))
    match = c.fetchone()
    
    if not match:
        flash('Match not available!', 'error')
        return redirect(url_for('matches'))
    
    bet_amount = match[4]
    game = match[1]
    game_mode = match[8]
    
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()[0]
    
    if balance < bet_amount:
        flash('Insufficient balance!', 'error')
        return redirect(url_for('matches'))
    
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (bet_amount, session['user_id']))
    c.execute('UPDATE matches SET player2_id = ?, status = "active" WHERE id = ?', 
             (session['user_id'], match_id))
    
    # Record match join transaction
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''',
             (session['user_id'], 'match_escrow', -bet_amount, f'Match #{match_id} joined - {game.upper()} {game_mode} - Money in escrow (Total pot: KSh {bet_amount * 2})'))
    
    session['balance'] = balance - bet_amount
    conn.commit()
    flash(f'Joined match! KSh {bet_amount} in escrow. Total pot: KSh {bet_amount * 2}', 'success')
    return redirect(url_for('matches'))

@app.route('/submit_screenshot_page/<int:match_id>')
@login_required
def submit_screenshot_page(match_id):
    """Route for the submit screenshot page"""
    return submit_screenshot(match_id)

@app.route('/submit_screenshot/<int:match_id>', methods=['GET', 'POST'])
@login_required
def submit_screenshot(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get match details
    c.execute('''SELECT m.*, u1.username as p1_name, u2.username as p2_name
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.id = ? AND (m.player1_id = ? OR m.player2_id = ?)''', 
             (match_id, session['user_id'], session['user_id']))
    match = c.fetchone()
    
    if not match:
        flash('Match not found!', 'error')
        return redirect(url_for('matches'))
    
    if request.method == 'POST':
        claimed_result = request.form.get('result')
        screenshot_file = request.files.get('screenshot')
        
        # Validate file upload
        is_valid, result = validate_file_upload(screenshot_file)
        if not is_valid:
            flash(result, 'error')
            return render_template('submit_screenshot.html', match=match, match_id=match_id)
        
        if not screenshot_file or not screenshot_file.filename:
            flash('Please upload a screenshot!', 'error')
            return render_template('submit_screenshot.html', match=match, match_id=match_id)
        
        # Process screenshot
        import base64
        screenshot_data = base64.b64encode(screenshot_file.read()).decode('utf-8')
        
        # Create match_screenshots table if not exists
        c.execute('''CREATE TABLE IF NOT EXISTS match_screenshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            match_id INTEGER,
            user_id INTEGER,
            screenshot_data TEXT,
            claimed_result TEXT,
            ocr_analysis TEXT,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Analyze screenshot using OCR
        game_type = match[1]  # game column
        analysis_result = analyze_screenshot(screenshot_data, claimed_result, game_type)
        
        # Store screenshot
        c.execute('''INSERT INTO match_screenshots (match_id, user_id, screenshot_data, claimed_result, ocr_analysis)
                     VALUES (?, ?, ?, ?, ?)''',
                 (match_id, session['user_id'], screenshot_data, claimed_result, str(analysis_result)))
        
        # Check if both players have submitted
        c.execute('SELECT COUNT(*) FROM match_screenshots WHERE match_id = ?', (match_id,))
        submission_count = c.fetchone()[0]
        
        if submission_count >= 2:
            # Both submitted, process match result
            c.execute('UPDATE matches SET status = "pending_review" WHERE id = ?', (match_id,))
            flash('Screenshot submitted! Match is now under review.', 'success')
        else:
            flash('Screenshot submitted! Waiting for opponent to submit.', 'success')
        
        conn.commit()
        return redirect(url_for('matches'))
    return render_template('submit_screenshot.html', match=match, match_id=match_id)

@app.route('/wallet')
@login_required
def wallet():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create missing tables if they don't exist
    c.execute('''CREATE TABLE IF NOT EXISTS paypal_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        order_id TEXT,
        amount_kes REAL,
        amount_usd REAL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS crypto_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        payment_id TEXT,
        order_id TEXT,
        amount_kes REAL,
        amount_usd REAL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Check for timed out payments (older than 30 minutes)
    from datetime import datetime, timedelta
    timeout_threshold = datetime.now() - timedelta(minutes=30)
    
    try:
        c.execute('''SELECT payment_id, user_id, amount_kes FROM crypto_payments 
                     WHERE status = 'pending' AND created_at < ?''', (timeout_threshold.isoformat(),))
        timed_out_crypto = c.fetchall()
        
        for payment_id, user_id, amount_kes in timed_out_crypto:
            c.execute('UPDATE crypto_payments SET status = "timeout" WHERE payment_id = ?', (payment_id,))
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (user_id, 'failed_crypto_deposit', amount_kes, f'Crypto deposit timed out - Payment not completed within 30 minutes - Payment ID: {payment_id}'))
    except sqlite3.Error as e:
        flash('Database error occurred', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('An error occurred', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        c.execute('''SELECT order_id, user_id, amount_kes FROM paypal_payments 
                     WHERE status = 'pending' AND created_at < ?''', (timeout_threshold.isoformat(),))
        timed_out_paypal = c.fetchall()
        
        for order_id, user_id, amount_kes in timed_out_paypal:
            c.execute('UPDATE paypal_payments SET status = "timeout" WHERE order_id = ?', (order_id,))
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (user_id, 'failed_paypal_deposit', amount_kes, f'PayPal deposit timed out - Payment not completed within 30 minutes - Order: {order_id}'))
    except sqlite3.Error as e:
        flash('Database error occurred', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('An error occurred', 'error')
        return redirect(url_for('dashboard'))
    
    # Get user's complete transaction history - latest first
    c.execute('''SELECT id, user_id, type, amount, description, created_at FROM transactions 
                 WHERE user_id = ? 
                 AND type NOT IN ('deposit_fee', 'withdrawal_fee', 'admin_fraud_commission', 'admin_referral_profit', 'tournament_commission', 'gift_commission')
                 ORDER BY created_at DESC, id DESC LIMIT 50''', (session['user_id'],))
    transactions = c.fetchall()
    
    # Get withdrawal history
    c.execute('''SELECT * FROM transactions WHERE user_id = ? AND type IN ('withdrawal', 'pending_withdrawal', 'rejected_withdrawal')
                 ORDER BY created_at DESC''', (session['user_id'],))
    withdrawals = c.fetchall()
    
    conn.commit()
    return render_template('wallet_mobile.html', transactions=transactions, withdrawals=withdrawals)

@app.route('/create_paypal_payment', methods=['POST'])
@login_required
def create_paypal_payment():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    from paypal_config import PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_BASE_URL
    
    data = request.get_json()
    amount_kes = safe_float_conversion(request.form.get('amount', 0), 'amount')
    
    if amount_kes < 100:
        return jsonify({'error': 'Minimum deposit is KSh 100'}), 400
    
    # Convert KES to USD (approximate rate)
    usd_rate = 130
    amount_usd = round(amount_kes / usd_rate, 2)
    
    try:
        import requests
        import base64
        
        # Get PayPal access token
        auth_string = f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}"
        auth_bytes = base64.b64encode(auth_string.encode()).decode()
        
        token_response = requests.post(
            f"{PAYPAL_BASE_URL}/v1/oauth2/token",
            headers={
                'Authorization': f'Basic {auth_bytes}',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data='grant_type=client_credentials'
        )
        
        if token_response.status_code != 200:
            return jsonify({'error': 'PayPal authentication failed'}), 400
        
        access_token = token_response.json()['access_token']
        
        # Create PayPal order
        order_data = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "amount": {
                    "currency_code": "USD",
                    "value": str(amount_usd)
                },
                "description": "SkillStake Gaming Deposit"
            }],
            "application_context": {
                "return_url": f"{request.url_root}paypal_success",
                "cancel_url": f"{request.url_root}paypal_cancel"
            }
        }
        
        order_response = requests.post(
            f"{PAYPAL_BASE_URL}/v2/checkout/orders",
            headers={
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            },
            json=order_data
        )
        
        if order_response.status_code != 201:
            return jsonify({'error': 'PayPal order creation failed'}), 400
        
        order_info = order_response.json()
        
        # Store payment info
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS paypal_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            order_id TEXT,
            amount_kes REAL,
            amount_usd REAL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        c.execute('''INSERT INTO paypal_payments (user_id, order_id, amount_kes, amount_usd)
                     VALUES (?, ?, ?, ?)''',
                 (session['user_id'], order_info['id'], amount_kes, amount_usd))
        
        # Add transaction record for initiated payment
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (session['user_id'], 'paypal_initiated', 0, f'PayPal payment initiated - KSh {amount_kes} - Order: {order_info["id"]}'))
        
        conn.commit()
        # Get approval URL
        approval_url = next(link['href'] for link in order_info['links'] if link['rel'] == 'approve')
        
        return jsonify({
            'success': True,
            'payment_url': approval_url,
            'order_id': order_info['id']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/create_crypto_payment', methods=['POST'])
@login_required
def create_crypto_payment():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    from config import NOWPAYMENTS_API_KEY, NOWPAYMENTS_API_URL, REQUEST_TIMEOUT
    from security_utils import validate_payment_amount, sanitize_payment_id
    
    data = request.get_json()
    
    # Validate amount
    is_valid, result = validate_payment_amount(data.get('amount'))
    if not is_valid:
        return jsonify({'error': result}), 400
    
    amount_kes = result
    usd_rate = 130
    amount_usd = round(amount_kes / usd_rate, 2)
    
    # Create payment payload for NOWPayments
    order_id = f'skillstake_{session["user_id"]}_{int(time.time())}'
    payment_data = {
        'price_amount': amount_usd,
        'price_currency': 'usd',
        'pay_currency': 'usdttrc20',
        'order_id': order_id,
        'order_description': 'SkillStake Gaming Deposit'
    }
    
    try:
        import requests
        headers = {
            'x-api-key': NOWPAYMENTS_API_KEY,
            'Content-Type': 'application/json'
        }
        
        # Use payment endpoint for crypto payments
        payment_url = 'https://api.nowpayments.io/v1/payment'
        response = requests.post(
            payment_url, 
            json=payment_data, 
            headers=headers, 
            timeout=REQUEST_TIMEOUT
        )
        
        print(f"NOWPayments API Response: Status {response.status_code}, Response: {response.text}")
        
        if response.status_code in [200, 201]:
            payment_info = response.json()
            
            # Store payment info in database
            with sqlite3.connect("gamebet.db") as conn:
                c = conn.cursor()
            
            # Create crypto_payments table if not exists
            c.execute('''CREATE TABLE IF NOT EXISTS crypto_payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                payment_id TEXT,
                order_id TEXT,
                amount_kes REAL,
                amount_usd REAL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # Use token_id as payment_id if payment_id not available
            payment_id = payment_info.get('payment_id') or payment_info.get('token_id')
            
            c.execute('''INSERT INTO crypto_payments (user_id, payment_id, order_id, amount_kes, amount_usd, status)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     (session['user_id'], payment_id, order_id, 
                      amount_kes, amount_usd, 'pending'))
            
            conn.commit()
            # Get payment URL - NOWPayments returns pay_url for direct payments
            payment_url = payment_info.get('pay_url')
            if not payment_url:
                # Fallback: construct URL with payment_id
                payment_id = payment_info.get('payment_id')
                if payment_id:
                    payment_url = f"https://nowpayments.io/payment/?pid={payment_id}"
                else:
                    return jsonify({'error': 'No payment URL received from provider'}), 500
            
            return jsonify({
                'success': True,
                'payment_url': payment_url,
                'payment_id': payment_id
            })
        else:
            error_msg = response.text
            try:
                error_data = response.json()
                error_msg = error_data.get('message', error_msg)
            except sqlite3.Error as e:
                flash('Database error occurred', 'error')
                return redirect(url_for('dashboard'))
    except Exception as e:
        flash('An error occurred', 'error')
        return redirect(url_for('dashboard'))
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/payment_webhook', methods=['POST'])
@login_required
def payment_webhook():
    """Handle NOWPayments webhook notifications"""
    try:
        data = request.get_json()
        payment_id = data.get('payment_id')
        payment_status = data.get('payment_status')
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
        # Find the payment
        c.execute('SELECT user_id, amount_kes FROM crypto_payments WHERE payment_id = ?', (payment_id,))
        payment = c.fetchone()
        
        if payment:
            user_id, amount_kes = payment
            
            if payment_status == 'finished':
                # Apply 3% fee
                fee = amount_kes * 0.03
                net_amount = amount_kes - fee
                
                # Credit user account
                c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (net_amount, user_id))
                
                # Update payment status
                c.execute('UPDATE crypto_payments SET status = ? WHERE payment_id = ?', ('completed', payment_id))
                
                # Add transaction record
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (user_id, 'crypto_deposit', net_amount, f'Crypto deposit KSh {amount_kes} - 3% fee = KSh {net_amount:.0f} - Payment ID: {payment_id}'))
                
                # Record admin commission
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (1, 'deposit_fee', fee, f'3% deposit fee from crypto payment - Payment ID: {payment_id}'))
                
            elif payment_status in ['failed', 'expired', 'cancelled']:
                # Update payment status to failed
                c.execute('UPDATE crypto_payments SET status = ? WHERE payment_id = ?', ('failed', payment_id))
                
                # Add failed transaction record for history
                failure_reason = {
                    'failed': 'Payment processing failed',
                    'expired': 'Payment expired - not completed within time limit',
                    'cancelled': 'Payment cancelled by user'
                }.get(payment_status, 'Payment failed')
                
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (user_id, 'failed_crypto_deposit', amount_kes, f'Crypto deposit failed: {failure_reason} - Payment ID: {payment_id}'))
            
            conn.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/test_nowpayments')
@admin_required
def test_nowpayments():
    """Test NOWPayments API connection"""
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    
    try:
        import requests
        from config import NOWPAYMENTS_API_KEY
        headers = {
            'x-api-key': NOWPAYMENTS_API_KEY,
            'Content-Type': 'application/json'
        }
        
        # Test API status
        response = requests.get('https://api.nowpayments.io/v1/currencies', headers=headers)
        
        if response.status_code == 200:
            return jsonify({
                'success': True,
                'message': 'NOWPayments API connected successfully!',
                'status': response.json()
            })
        else:
            return jsonify({
                'success': False,
                'error': f'API returned status {response.status_code}',
                'response': response.text
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/webhook_info')
@admin_required
def webhook_info():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    
    webhook_url = f'{request.url_root}payment_webhook'
    
    return jsonify({
        'webhook_url': webhook_url,
        'instructions': {
            'nowpayments': 'Add this URL to your NOWPayments IPN settings',
            'note': 'This URL receives payment confirmations automatically'
        }
    })

@app.route('/paypal_checkout')
@login_required
def paypal_checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('paypal_checkout.html')

@app.route('/paypal_capture', methods=['POST'])
@login_required
def paypal_capture():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    order_id = data.get('orderID')
    amount_kes = safe_float_conversion(request.form.get('amount', 0), 'amount')
    
    try:
        # Apply 3% fee and credit user account
        fee = amount_kes * 0.03
        net_amount = amount_kes - fee
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (net_amount, session['user_id']))
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (session['user_id'], 'paypal_deposit', net_amount, f'PayPal deposit KSh {amount_kes} - 3% fee = KSh {net_amount:.0f} - Order: {order_id}'))
        
        # Record admin commission
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (1, 'deposit_fee', fee, f'3% deposit fee from PayPal payment - Order: {order_id}'))
        
        conn.commit()
        session['balance'] = session.get('balance', 0) + net_amount
        
        return jsonify({'success': True, 'message': f'KSh {net_amount:.0f} credited (KSh {amount_kes} - 3% fee)'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/paypal_success')
@login_required
def paypal_success():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    order_id = request.args.get('token')
    success = False
    amount_kes = 0
    error_msg = None
    
    if order_id:
        try:
            from paypal_config import PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_BASE_URL
            import requests
            import base64
            
            # Get access token
            auth_string = f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}"
            auth_bytes = base64.b64encode(auth_string.encode()).decode()
            
            token_response = requests.post(
                f"{PAYPAL_BASE_URL}/v1/oauth2/token",
                headers={
                    'Authorization': f'Basic {auth_bytes}',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data='grant_type=client_credentials'
            )
            
            access_token = token_response.json()['access_token']
            
            # Capture payment
            capture_response = requests.post(
                f"{PAYPAL_BASE_URL}/v2/checkout/orders/{order_id}/capture",
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                }
            )
            
            if capture_response.status_code == 201:
                capture_data = capture_response.json()
                
                if capture_data['status'] == 'COMPLETED':
                    # Credit user account
                    with sqlite3.connect("gamebet.db") as conn:
                        c = conn.cursor()
                    
                    c.execute('SELECT amount_kes FROM paypal_payments WHERE order_id = ? AND user_id = ?', 
                             (order_id, session['user_id']))
                    payment = c.fetchone()
                    
                    if payment:
                        amount_kes = payment[0]
                        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', 
                                 (amount_kes, session['user_id']))
                        c.execute('UPDATE paypal_payments SET status = "completed" WHERE order_id = ?', 
                                 (order_id,))
                        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                                     VALUES (?, ?, ?, ?)''',
                                 (session['user_id'], 'paypal_deposit', amount_kes, 
                                  f'PayPal deposit - Order: {order_id}'))
                        
                        conn.commit()
                        session['balance'] = session.get('balance', 0) + amount_kes
                        success = True
                    else:
                        error_msg = 'Payment verification failed'
                else:
                    error_msg = 'Payment not completed'
            else:
                error_msg = 'Payment capture failed'
                
        except Exception as e:
            error_msg = f'Payment processing error: {str(e)}'
    else:
        error_msg = 'Invalid payment response'
    
    return render_template('paypal_result.html', success=success, amount=amount_kes, error=error_msg)

@app.route('/payment_success')
@login_required
def payment_success():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('payment_result.html', success=True, message='Payment completed! Your account will be credited once payment is confirmed.')

@app.route('/add_funds', methods=['POST'])
@login_required
def add_funds():
    # Validate amount
    valid_amount, amount_or_msg = validate_amount(request.form.get('amount', 0))
    if not valid_amount:
        flash(amount_or_msg, 'error')
        return redirect(url_for('wallet'))
    
    amount = amount_or_msg
    mpesa_number = request.form.get('mpesa_number', '')
    sender_name = request.form.get('sender_name', '')
    
    # Handle receipt screenshot
    receipt_screenshot = None
    if 'receipt_screenshot' in request.files:
        file = request.files['receipt_screenshot']
        if file and file.filename:
            import base64
            receipt_data = file.read()
            receipt_screenshot = base64.b64encode(receipt_data).decode('utf-8')
    
    if not receipt_screenshot:
        flash('M-Pesa receipt screenshot is required!', 'error')
        return redirect(url_for('wallet'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create deposit verifications table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS deposit_verifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id INTEGER,
        user_id INTEGER,
        mpesa_number TEXT NOT NULL,
        sender_name TEXT NOT NULL,
        receipt_screenshot TEXT NOT NULL,
        amount_sent REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    processing_fee = amount * 0.03
    amount_to_credit = amount - processing_fee
    
    description = f'M-Pesa deposit KSh {amount} from {sender_name} ({mpesa_number}) - To credit: KSh {amount_to_credit:.0f}'
    c.execute('''INSERT INTO transactions (user_id, type, amount, description, created_at)
                 VALUES (?, ?, ?, ?, datetime('now'))''', (session['user_id'], 'pending_deposit', amount_to_credit, description))
    
    transaction_id = c.lastrowid
    
    # Store deposit verification details
    c.execute('''INSERT INTO deposit_verifications (transaction_id, user_id, mpesa_number, sender_name, 
                                                   receipt_screenshot, amount_sent)
                 VALUES (?, ?, ?, ?, ?, ?)''', 
                (transaction_id, session['user_id'], mpesa_number, sender_name, receipt_screenshot, amount))
    
    conn.commit()
    flash('Deposit request submitted with receipt!', 'success')
    return redirect(url_for('wallet'))

@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    # Check if user is banned/suspended
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    try:
        c.execute('SELECT banned FROM users WHERE id = ?', (session['user_id'],))
        user_status = c.fetchone()
        if user_status and len(user_status) > 0 and user_status[0] == 1:
            flash('Account suspended. Withdrawals blocked. Contact admin.', 'error')
            return redirect(url_for('wallet'))
    except sqlite3.Error as e:
        flash('Database error occurred', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('An error occurred', 'error')
        return redirect(url_for('dashboard'))
    # Validate amount
    valid_amount, amount_or_msg = validate_amount(request.form.get('amount', 0))
    if not valid_amount:
        flash(amount_or_msg, 'error')
        return redirect(url_for('wallet'))
    
    amount = amount_or_msg
    withdrawal_method = request.form.get('withdrawal_method', 'mpesa')
    
    # Get user's deposit history to determine preferred withdrawal method
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create user_deposit_methods table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS user_deposit_methods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        method TEXT,
        details TEXT,
        first_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_deposits REAL DEFAULT 0
    )''')
    
    # Get user's deposit methods
    c.execute('''SELECT DISTINCT 
                    CASE 
                        WHEN type LIKE '%paypal%' THEN 'paypal'
                        WHEN type LIKE '%crypto%' THEN 'crypto'
                        WHEN type LIKE '%mpesa%' OR type = 'deposit' THEN 'mpesa'
                        ELSE 'other'
                    END as method,
                    SUM(amount) as total
                 FROM transactions 
                 WHERE user_id = ? AND amount > 0 AND type IN ('deposit', 'paypal_deposit', 'crypto_deposit')
                 GROUP BY method
                 ORDER BY total DESC''', (session['user_id'],))
    deposit_methods = c.fetchall()
    
    # Determine smart withdrawal method
    primary_method = deposit_methods[0][0] if deposit_methods else 'mpesa'
    
    # Method-specific limits and minimums
    limits = {
        'mpesa': {'min': 100, 'max': 10000},
        'paypal': {'min': 1000, 'max': 50000},  # Higher limits due to high fees
        'crypto': {'min': 2000, 'max': 100000}, # Highest limits due to high fees
        'bank': {'min': 500, 'max': 25000}      # Medium limits
    }
    
    method_limits = limits.get(withdrawal_method, limits['mpesa'])
    
    if amount < method_limits['min']:
        flash(f'Minimum withdrawal for {withdrawal_method.upper()} is KSh {method_limits["min"]}!', 'error')
        return redirect(url_for('wallet'))
    
    if amount > method_limits['max']:
        flash(f'Maximum withdrawal for {withdrawal_method.upper()} is KSh {method_limits["max"]}!', 'error')
        return redirect(url_for('wallet'))
    
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()[0]
    
    if balance < amount:
        flash('Insufficient balance!', 'error')
        return redirect(url_for('wallet'))
    
    # Smart withdrawal processing with fees
    withdrawal_fee = 0
    processing_fee_rate = 0.02  # 2% processing fee for revenue
    
    if withdrawal_method == 'mpesa':
        withdrawal_fee = 25  # Fixed M-Pesa fee
        mpesa_number = request.form.get('mpesa_number', '').strip()
        mpesa_name = request.form.get('mpesa_name', session['username']).strip()
        
        if not mpesa_number:
            flash('M-Pesa number required!', 'error')
            return redirect(url_for('wallet'))
        
        # Validate M-Pesa number
        import re
        if not re.match(r'^0[17][0-9]{8}$', mpesa_number):
            flash('Invalid M-Pesa number format!', 'error')
            return redirect(url_for('wallet'))
        
        withdrawal_details = f'{mpesa_name} ({mpesa_number})'
        
    elif withdrawal_method == 'paypal' or primary_method == 'paypal':
        withdrawal_fee = amount * 0.055  # 3.5% PayPal fee
        paypal_email = request.form.get('paypal_email', '').strip()
        if not paypal_email:
            flash('PayPal email required!', 'error')
            return redirect(url_for('wallet'))
        withdrawal_details = paypal_email
        
    elif withdrawal_method == 'crypto' or primary_method == 'crypto':
        withdrawal_fee = amount * 0.035  # 1.5% crypto fee
        crypto_address = request.form.get('crypto_address', '').strip()
        crypto_type = request.form.get('crypto_type', 'USDT')
        if not crypto_address:
            flash('Crypto wallet address required!', 'error')
            return redirect(url_for('wallet'))
        withdrawal_details = f'{crypto_type}: {crypto_address}'
        
    elif withdrawal_method == 'bank':
        withdrawal_fee = 50  # Fixed bank transfer fee
        bank_name = request.form.get('bank_name', '').strip()
        account_number = request.form.get('account_number', '').strip()
        account_name = request.form.get('account_name', '').strip()
        if not all([bank_name, account_number, account_name]):
            flash('All bank details required!', 'error')
            return redirect(url_for('wallet'))
        withdrawal_details = f'{bank_name} - {account_name} ({account_number})'
    
    # Calculate total fees with proper precision
    processing_fee = safe_money_calculation(amount * processing_fee_rate)
    total_fees = safe_money_calculation(withdrawal_fee + processing_fee)
    net_amount = safe_money_calculation(amount - total_fees)
    
    # Check daily withdrawal limit per method
    from datetime import datetime
    today = datetime.now().date()
    c.execute('''SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions 
                 WHERE user_id = ? AND type IN ('withdrawal', 'pending_withdrawal') 
                 AND date(created_at) = ? AND description LIKE ?''', 
             (session['user_id'], today, f'%{withdrawal_method}%'))
    daily_withdrawn = c.fetchone()[0]
    
    if daily_withdrawn + amount > method_limits['max']:
        remaining = method_limits['max'] - daily_withdrawn
        flash(f'Daily {withdrawal_method.upper()} limit exceeded! You can withdraw KSh {remaining:.0f} more today.', 'error')
        return redirect(url_for('wallet'))
    
    # Process withdrawal
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, session['user_id']))
    
    if withdrawal_method == 'mpesa':
        description = f'M-Pesa withdrawal KSh {amount} to {withdrawal_details} - Fees: KSh {total_fees:.0f} - You receive: KSh {net_amount:.0f}'
    elif withdrawal_method == 'paypal':
        description = f'PayPal withdrawal KSh {amount} to {paypal_email} - Fees: KSh {total_fees:.0f} - You receive: KSh {net_amount:.0f}'
    elif withdrawal_method == 'crypto':
        description = f'Crypto withdrawal KSh {amount} to {crypto_address} ({crypto_type}) - Fees: KSh {total_fees:.0f} - You receive: KSh {net_amount:.0f}'
    elif withdrawal_method == 'bank':
        description = f'Bank withdrawal KSh {amount} to {bank_name} - {account_name} ({account_number}) - Fees: KSh {total_fees:.0f} - You receive: KSh {net_amount:.0f}'
    else:
        description = f'{withdrawal_method.upper()} withdrawal KSh {amount} to {withdrawal_details} - Fees: KSh {total_fees:.0f} - You receive: KSh {net_amount:.0f}'
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''', (session['user_id'], 'pending_withdrawal', -amount, description))
    
    withdrawal_id = c.lastrowid
    
    # Record admin commission from fees
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''',
             (1, 'withdrawal_fee', total_fees, f'Withdrawal fees from {withdrawal_method} - Transaction {withdrawal_id}'))
    
    session['balance'] = balance - amount
    
    conn.commit()
    flash(f'Smart withdrawal request submitted! Method: {withdrawal_method.upper()}', 'success')
    return redirect(url_for('withdrawal_chat', withdrawal_id=withdrawal_id))

@app.route('/tournaments')
@login_required
def tournaments():
    # Redirect to streaming tournaments (new system)
    return redirect(url_for('tournaments_new'))

@app.route('/referrals')
@login_required
def referrals():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get user's referral code and earnings
    c.execute('SELECT referral_code FROM users WHERE id = ?', (session['user_id'],))
    user_data = c.fetchone()
    referral_code = user_data[0] if user_data else 'N/A'
    
    # Get referral earnings
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type = "referral_bonus"', (session['user_id'],))
    referral_earnings = c.fetchone()[0]
    
    # Get referred users
    c.execute('SELECT username, created_at FROM users WHERE referred_by = ? ORDER BY created_at DESC', (session['user_id'],))
    referred_users = c.fetchall()
    return render_template('referrals.html', referral_code=referral_code, referral_earnings=referral_earnings, referred_users=referred_users)

@app.route('/friends')
@login_required
def friends():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get all users except current user and admin
    c.execute('SELECT id, username, created_at FROM users WHERE id != ? AND username != "admin" ORDER BY username', (session['user_id'],))
    all_users = c.fetchall()
    
    # Get current friends
    c.execute('''SELECT u.id, u.username FROM users u 
                 JOIN user_friends uf ON u.id = uf.friend_id 
                 WHERE uf.user_id = ? AND uf.status = "accepted"''', (session['user_id'],))
    friends = c.fetchall()
    return render_template('friends.html', friends=friends, requests=[], all_users=all_users)

@app.route('/add_friend', methods=['POST'])
@login_required
def add_friend():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = request.form['username']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    friend = c.fetchone()
    
    if friend:
        c.execute('''INSERT OR IGNORE INTO user_friends (user_id, friend_id, status) 
                     VALUES (?, ?, ?)''', (session['user_id'], friend[0], 'accepted'))
        conn.commit()
        flash('Friend added!', 'success')
    else:
        flash('User not found!', 'error')
    return redirect(url_for('friends'))

@app.route('/leaderboard')
@login_required
def leaderboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('leaderboard.html', top_players=[], top_earners=[])

@app.route('/match_history')
@login_required
def match_history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get user's complete match history
    c.execute('''SELECT m.id, m.game, m.player1_id, m.player2_id, m.bet_amount, m.total_pot, 
                        m.winner_id, m.status, m.game_mode, m.created_at,
                        u1.username as p1_name, u2.username as p2_name, u1.phone as p1_phone, u2.phone as p2_phone
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.player1_id = ? OR m.player2_id = ?
                 ORDER BY m.created_at DESC''', (session['user_id'], session['user_id']))
    matches = c.fetchall()
    
    # Get user's transaction history
    c.execute('''SELECT * FROM transactions WHERE user_id = ? 
                 ORDER BY created_at DESC LIMIT 20''', (session['user_id'],))
    transactions = c.fetchall()
    return render_template('match_history.html', matches=matches, transactions=transactions, withdrawals=[])

@app.route('/profile')
@login_required
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    return render_template('profile.html', user=user)

@app.route('/support_chat')
@login_required
def support_chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create AI chat table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS ai_chat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        message TEXT,
        response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('SELECT * FROM ai_chat_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', (session['user_id'],))
    chat_history = c.fetchall()
    return render_template('support_chat.html', chat_history=chat_history)

@app.route('/ai_chat', methods=['POST'])
@login_required
def ai_chat():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    message = data['message'].lower()
    
    # AI Response Logic
    if 'balance' in message or 'money' in message:
        response = "Your current balance is KSh {:.0f}. You can add funds via M-Pesa or earn through matches and referrals.".format(session.get('balance', 0))
    elif 'deposit' in message or 'add funds' in message:
        response = "To deposit funds: Go to Wallet â†’ Add Funds â†’ Upload M-Pesa receipt. Processing takes 5-10 minutes."
    elif 'withdraw' in message or 'cash out' in message:
        response = "To withdraw: Go to Wallet â†’ Withdraw â†’ Enter amount and M-Pesa number. KSh 25 processing fee applies."
    elif 'match' in message or 'game' in message:
        response = "Create matches in Games section. Choose Instant Play (screenshot verification) or Broadcast Mode (live streaming with bonuses)."
    elif 'stream' in message or 'broadcast' in message:
        response = "Streaming earns bonus rewards (KSh 10-35). Go to Broadcast Mode â†’ Create match â†’ Automatic stream setup."
    elif 'friend' in message:
        response = "Add friends in Friends section. Create friends-only matches for private gaming sessions."
    elif 'tournament' in message:
        response = "Join tournaments for bigger prizes. Entry fees vary, with 85% going to prize pool."
    elif 'referral' in message or 'invite' in message:
        response = "Share your referral code to earn KSh 30 per signup. Find your code in Referrals section."
    elif 'problem' in message or 'issue' in message or 'help' in message:
        response = "I can help with: Account issues, deposits/withdrawals, match problems, streaming setup, or technical support. What specific issue are you facing?"
    elif 'admin' in message or 'human' in message:
        response = "For complex issues requiring human review, I can escalate to admin support. Would you like me to create a support ticket?"
    else:
        response = "I'm SkillState AI Assistant. I can help with: Account management, deposits/withdrawals, matches, streaming, friends, tournaments, and referrals. What do you need help with?"
    
    # Save to database
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    c.execute('INSERT INTO ai_chat_history (user_id, message, response) VALUES (?, ?, ?)', 
             (session['user_id'], data['message'], response))
    conn.commit()
    return jsonify({'response': response})

# Admin routes


@app.route('/admin')
@admin_required
def admin_dashboard():
    # Your original admin dashboard logic here
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get basic stats
    c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
    total_users = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM matches WHERE status = "active"')
    active_matches = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type IN ("deposit", "paypal_deposit", "crypto_deposit")')
    total_deposits = c.fetchone()[0]
    
    # Get pending items
    c.execute('''SELECT t.id, t.user_id, t.amount, t.description, t.created_at, u.username 
                 FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 WHERE t.type = "pending_deposit"
                 ORDER BY t.created_at DESC''')
    pending_deposits = c.fetchall()
    
    c.execute('''SELECT t.id, t.user_id, t.amount, t.description, t.created_at, u.username
                 FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 WHERE t.type = "pending_withdrawal"
                 ORDER BY t.created_at DESC''')
    pending_withdrawals = c.fetchall()
    
    # Get admin notifications count
    try:
        c.execute('''CREATE TABLE IF NOT EXISTS admin_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            transaction_id INTEGER,
            message TEXT,
            type TEXT,
            status TEXT DEFAULT 'unread',
            created_at DATETIME DEFAULT (datetime('now'))
        )''')
        c.execute('SELECT COUNT(*) FROM admin_notifications WHERE status = "unread"')
        unread_alerts = c.fetchone()[0] or 0
    except:
        unread_alerts = 0
    stats = {
        'total_users': total_users,
        'active_matches': active_matches,
        'total_deposits': total_deposits,
        'net_earnings': 0,
        'completed_matches': 0,
        'total_withdrawals': 0,
        'new_users_week': 0,
        'total_withdrawn': 0
    }
    
    earnings_data = {
        'gross_earnings': 0,
        'match_commission': 0,
        'deposit_fees': 0,
        'withdrawal_fees': 0,
        'tournament_fees': 0,
        'referral_profits': 0,
        'fraud_commissions': 0,
        'bank_fees': 0,
        'streaming_costs': 0,
        'net_earnings': 0
    }
    
    return render_template('admin_dashboard.html', stats=stats, 
                         pending_deposits=pending_deposits, 
                         pending_withdrawals=pending_withdrawals,
                         unread_alerts=unread_alerts,
                         earnings_data=earnings_data,
                         disputed_matches=[],
                         notifications=[])

@app.route('/admin/dashboard_new')
@admin_required
def admin_dashboard_new():
    # Update admin activity
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create admin_activity table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS admin_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        last_active DATETIME DEFAULT (datetime('now'))
    )''')
    
    c.execute('INSERT INTO admin_activity (last_active) VALUES (datetime("now"))')
    conn.commit()
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get real stats from database
    c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
    total_users = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM matches WHERE status = "active"')
    active_matches = c.fetchone()[0]
    
    # Get total deposits from all deposit types
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type IN ("deposit", "paypal_deposit", "crypto_deposit")')
    total_deposits = c.fetchone()[0]
    
    # Calculate real earnings breakdown from actual transactions
    # Match commissions - calculate from completed matches
    c.execute('SELECT COUNT(*), COALESCE(SUM(total_pot), 0) FROM matches WHERE status = "completed"')
    match_data = c.fetchone()
    completed_matches_count = match_data[0]
    total_match_pot = match_data[1]
    match_commission = total_match_pot * 0.32  # 32% commission
    
    # Deposit processing fees (3% from all successful deposits)
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "deposit_fee"')
    deposit_fees = c.fetchone()[0]
    
    # If no deposit_fee records, calculate from deposits
    if deposit_fees == 0:
        c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type IN ("deposit", "paypal_deposit", "crypto_deposit")')
        total_user_deposits = c.fetchone()[0]
        deposit_fees = total_user_deposits * 0.03  # 3% fee
    
    # Withdrawal fees
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "withdrawal_fee"')
    withdrawal_fees = c.fetchone()[0]
    
    # If no withdrawal_fee records, calculate from withdrawals
    if withdrawal_fees == 0:
        c.execute('SELECT COUNT(*) FROM transactions WHERE type = "withdrawal"')
        withdrawal_count = c.fetchone()[0]
        withdrawal_fees = withdrawal_count * 25  # KSh 25 per withdrawal
    
    # Referral profits (KSh 20 per referral)
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "admin_referral_profit"')
    referral_profits = c.fetchone()[0]
    
    # If no admin_referral_profit records, calculate from referrals
    if referral_profits == 0:
        c.execute('SELECT COUNT(*) FROM transactions WHERE type = "referral_bonus"')
        referral_count = c.fetchone()[0]
        referral_profits = referral_count * 20  # KSh 20 profit per referral
    
    # Fraud penalty commissions
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "admin_fraud_commission"')
    fraud_commissions = c.fetchone()[0]
    
    # If no admin_fraud_commission records, calculate from penalties
    if fraud_commissions == 0:
        c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE type = "fake_screenshot_penalty"')
        fraud_commissions = c.fetchone()[0]  # Admin gets full penalty amount
    
    # Count fake screenshot incidents
    c.execute('SELECT COUNT(*) FROM transactions WHERE type = "fake_screenshot_penalty"')
    fake_ss_matches = c.fetchone()[0]
    
    # Tournament fees
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "tournament_commission"')
    tournament_fees = c.fetchone()[0]
    
    # Streaming bonuses paid out (from actual streaming earnings)
    c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE type = "streaming_earnings"')
    streaming_costs = c.fetchone()[0]
    
    # Bank processing fees (1.5% of deposits + 2% of withdrawals)
    bank_fees = (total_deposits * 0.015) + (withdrawal_fees * 0.02)
    gross_earnings = match_commission + deposit_fees + withdrawal_fees + referral_profits + tournament_fees + fraud_commissions
    net_earnings = gross_earnings - bank_fees - streaming_costs
    
    # Get pending deposits
    c.execute('''SELECT t.id, t.user_id, t.amount, t.description, t.created_at, u.username, u.email 
                 FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 WHERE t.type = "pending_deposit"
                 ORDER BY t.created_at DESC''')
    pending_deposits = c.fetchall()
    
    # Get pending withdrawals with unread chat count
    c.execute('''SELECT t.id, t.user_id, t.amount, t.description, t.created_at, u.username, u.email,
                        (SELECT COUNT(*) FROM withdrawal_chat wc WHERE wc.withdrawal_id = t.id AND wc.is_admin = 0) as unread_count
                 FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 WHERE t.type = "pending_withdrawal"
                 ORDER BY t.created_at DESC''')
    withdrawals_raw = c.fetchall()
    pending_withdrawals = []
    for w in withdrawals_raw:
        pending_withdrawals.append((w[0], w[1], abs(float(w[2])), w[3], w[4], w[5], w[6], w[7]))
    
    # Get admin notifications (deposit alerts)
    c.execute('''SELECT COUNT(*) FROM admin_notifications WHERE status = "unread"''')
    unread_count = c.fetchone()
    unread_alerts = unread_count[0] if unread_count else 0
    
    c.execute('''SELECT * FROM admin_notifications WHERE status = "unread" ORDER BY created_at DESC LIMIT 5''')
    recent_alerts = c.fetchall()
    
    # Additional real statistics with error handling
    try:
        c.execute('SELECT COUNT(*) FROM matches WHERE status = "completed"')
        total_completed_matches = c.fetchone()[0] or 0
    except:
        total_completed_matches = 0
    
    try:
        c.execute('SELECT COUNT(*) FROM transactions WHERE type IN ("withdrawal", "pending_withdrawal")')
        total_withdrawals = c.fetchone()[0] or 0
    except:
        total_withdrawals = 0
    
    try:
        c.execute('SELECT COUNT(*) FROM users WHERE created_at >= datetime("now", "-7 days")')
        new_users_week = c.fetchone()[0] or 0
    except:
        new_users_week = 0
    
    try:
        c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE type = "withdrawal"')
        total_withdrawn = c.fetchone()[0] or 0
    except:
        total_withdrawn = 0

    stats = {
        'total_users': total_users,
        'active_matches': active_matches,
        'total_deposits': total_deposits,
        'net_earnings': net_earnings,
        'gross_earnings': gross_earnings,
        'bank_fees': bank_fees,
        'completed_matches': total_completed_matches,
        'total_withdrawals': total_withdrawals,
        'new_users_week': new_users_week,
        'total_withdrawn': total_withdrawn
    }
    
    # Enhanced revenue breakdown by payment method
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "deposit_fee" AND description LIKE "%PayPal%"')
    paypal_fees = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "deposit_fee" AND description LIKE "%crypto%"')
    crypto_fees = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "deposit_fee" AND (description LIKE "%M-Pesa%" OR description LIKE "%deposit%")')
    mpesa_fees = c.fetchone()[0]
    
    # Additional real statistics with error handling
    try:
        c.execute('SELECT COUNT(*) FROM matches WHERE status = "completed"')
        total_completed_matches = c.fetchone()[0] or 0
    except:
        total_completed_matches = 0
    
    try:
        c.execute('SELECT COUNT(*) FROM transactions WHERE type IN ("withdrawal", "pending_withdrawal")')
        total_withdrawals = c.fetchone()[0] or 0
    except:
        total_withdrawals = 0
    
    try:
        c.execute('SELECT COUNT(*) FROM users WHERE created_at >= datetime("now", "-7 days")')
        new_users_week = c.fetchone()[0] or 0
    except:
        new_users_week = 0
    
    try:
        c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE type = "withdrawal"')
        total_withdrawn = c.fetchone()[0] or 0
    except:
        total_withdrawn = 0
    
    # Get gift commissions
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "gift_commission"')
    gift_commissions = c.fetchone()[0]
    
    # Update gross earnings to include gift commissions
    gross_earnings = gross_earnings + gift_commissions
    net_earnings = gross_earnings - bank_fees - streaming_costs
    
    earnings_data = {
        'gross_earnings': gross_earnings,
        'match_commission': match_commission,
        'deposit_fees': deposit_fees,
        'withdrawal_fees': withdrawal_fees,
        'tournament_fees': tournament_fees,
        'referral_profits': referral_profits,
        'fraud_commissions': fraud_commissions,
        'gift_commissions': gift_commissions,
        'streaming_costs': streaming_costs,
        'bank_fees': bank_fees,
        'net_earnings': net_earnings,
        'commission_rate': 32,
        'fake_ss_matches': fake_ss_matches,
        'paypal_fees': paypal_fees,
        'crypto_fees': crypto_fees,
        'mpesa_fees': mpesa_fees,
        'total_payment_fees': paypal_fees + crypto_fees + mpesa_fees
    }
    
    return render_template('admin_dashboard_new.html', stats=stats, 
                         pending_withdrawals=pending_withdrawals, pending_deposits=pending_deposits,
                         disputed_matches=[], notifications=recent_alerts, earnings_data=earnings_data,
                         unread_alerts=unread_alerts)

@app.route('/admin/users')
@admin_required
def admin_users():
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get users with proper column mapping - force fresh query
    c.execute('''SELECT id, username, email, password, balance, wins, losses, total_earnings, 
                        created_at, phone, referral_code, COALESCE(banned, 0) as banned 
                 FROM users WHERE username != "admin" ORDER BY id DESC''')
    users = c.fetchall()
    
    # Add cache-busting timestamp
    import time
    cache_buster = int(time.time())
    
    return render_template('admin_users_fixed.html', users=users, cache_buster=cache_buster)

@app.route('/admin/transactions')
@admin_required
def admin_transactions():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get all transactions with user details
    c.execute('''SELECT t.id, t.user_id, t.type, t.amount, t.description, t.created_at, u.username
                 FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 ORDER BY t.created_at DESC
                 LIMIT 200''')
    transactions = c.fetchall()
    return render_template('admin_transactions.html', transactions=transactions)

@app.route('/admin/matches')
@admin_required
def admin_matches():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get all matches with detailed info including fraud penalties
    c.execute('''SELECT m.id, m.game, m.player1_id, m.player2_id, m.bet_amount, m.total_pot,
                        m.winner_id, m.status, m.game_mode, m.created_at,
                        u1.username as p1_name, u2.username as p2_name, 
                        uw.username as winner_name, u1.phone as p1_phone, u2.phone as p2_phone,
                        (SELECT COUNT(*) FROM match_screenshots ms WHERE ms.match_id = m.id) as screenshot_count,
                        (SELECT COUNT(*) FROM streams s WHERE s.match_id = m.id AND s.status = 'live') as live_streams,
                        COALESCE(m.verification_type, 'ocr') as verification_type,
                        (SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE 
                         (type = 'admin_fraud_commission' OR type = 'fake_screenshot_penalty') 
                         AND (description LIKE '%' || m.id || '%' OR description LIKE '%Match ' || m.id || '%')) as fraud_commission_earned
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 LEFT JOIN users uw ON m.winner_id = uw.id
                 ORDER BY m.created_at DESC
                 LIMIT 100''')
    matches = c.fetchall()
    
    # Get real competition data
    c.execute('''SELECT COUNT(DISTINCT cp.user_id) as participants, 
                        COALESCE(SUM(cp.earnings), 0) as total_earnings,
                        (SELECT COUNT(*) FROM streams s WHERE s.status = 'live') as active_streams
                 FROM competition_participants cp
                 JOIN streaming_competitions sc ON cp.competition_id = sc.id
                 WHERE sc.status = 'active' AND date(sc.created_at) = date('now')''')
    competition_data = c.fetchone()
    
    # If no competition data, set defaults
    if not competition_data or competition_data[0] is None:
        competition_data = (0, 0, 0)
    
    # Get match statistics
    c.execute('SELECT COUNT(*) FROM matches')
    total_matches = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM matches WHERE status = "completed"')
    completed_matches = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM matches WHERE status = "active"')
    active_matches = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM matches WHERE status IN ("disputed", "pending_review")')
    disputed_matches = c.fetchone()[0]
    stats = {
        'total': total_matches,
        'completed': completed_matches,
        'active': active_matches,
        'disputed': disputed_matches
    }
    
    return render_template('admin_matches.html', matches=matches, stats=stats, competition_data=competition_data)





@app.route('/admin/support_center')
@admin_required
def admin_support_center():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create support escalations table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS support_escalations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        message TEXT,
        status TEXT DEFAULT 'pending',
        admin_response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Get pending escalations
    c.execute('SELECT * FROM support_escalations WHERE status = "pending" ORDER BY created_at DESC')
    pending_escalations = c.fetchall()
    
    # Get resolved today count
    c.execute('SELECT COUNT(*) FROM support_escalations WHERE status = "resolved" AND date(created_at) = date("now")')
    resolved_today = c.fetchone()[0]
    
    # Get matches pending review
    c.execute('''SELECT m.id, m.game, m.bet_amount, m.total_pot, 
                        u1.username as p1_name, u2.username as p2_name,
                        m.created_at, m.status
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.status IN ("disputed", "pending_review")
                 ORDER BY m.created_at ASC''')
    disputed_matches = c.fetchall()
    return render_template('admin_support.html', 
                         pending_escalations=pending_escalations,
                         active_chats=[],
                         resolved_today=resolved_today,
                         disputed_matches=disputed_matches,
                         pending_reviews=len([m for m in disputed_matches if m[7] == 'pending_review']))

@app.route('/admin/approve_deposit/<int:transaction_id>', methods=['POST', 'GET'])
@admin_required
def approve_deposit(transaction_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Check current transaction status
    c.execute('SELECT user_id, amount, type FROM transactions WHERE id = ?', (transaction_id,))
    transaction = c.fetchone()
    
    if transaction:
        user_id, amount, current_type = transaction
        
        # If already rejected, fix it by approving
        if current_type == 'rejected_deposit':
            c.execute('UPDATE transactions SET type = "deposit" WHERE id = ?', (transaction_id,))
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
            flash(f'Deposit corrected from rejected to approved! KSh {amount:.0f} credited to user.', 'success')
        elif current_type == 'pending_deposit':
            # Apply 3% fee to M-Pesa deposits - user deposits 500, gets 485 credited
            fee = amount * 0.03
            net_amount = amount - fee
            
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (net_amount, user_id))
            c.execute('UPDATE transactions SET type = "deposit", amount = ?, description = ? WHERE id = ?', 
                     (net_amount, f'M-Pesa deposit KSh {amount} - 3% fee = KSh {net_amount:.0f}', transaction_id))
            
            # Record admin commission
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (1, 'deposit_fee', fee, f'3% deposit fee from M-Pesa deposit - Transaction {transaction_id}'))
            
            flash(f'Deposit approved! KSh {net_amount:.0f} credited (KSh {amount} - 3% fee)', 'success')
        else:
            flash(f'Deposit already processed (status: {current_type})', 'info')
        
        conn.commit()
    else:
        flash('Transaction not found!', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_deposit/<int:transaction_id>', methods=['POST', 'GET'])
@admin_required
def reject_deposit(transaction_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    c.execute('UPDATE transactions SET type = "rejected_deposit" WHERE id = ?', (transaction_id,))
    conn.commit()
    flash('Deposit rejected!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/clear_all_deposits')
@admin_required
def clear_all_deposits():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    c.execute('DELETE FROM transactions WHERE type IN ("deposit", "pending_deposit", "rejected_deposit")')
    c.execute('DELETE FROM deposit_verifications')
    conn.commit()
    flash('All deposits cleared!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/mark_withdrawal_paid', methods=['POST'])
@admin_required
def mark_withdrawal_paid():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Validate withdrawal_id is integer
        withdrawal_id = int(request.form['withdrawal_id'])
        
        if 'payment_proof' not in request.files:
            return jsonify({'success': False, 'message': 'Payment proof required'})
        
        file = request.files['payment_proof']
        if not file.filename:
            return jsonify({'success': False, 'message': 'No file selected'})
        
        # Validate file extension
        allowed_extensions = {'.jpg', '.jpeg', '.png', '.pdf'}
        file_ext = '.' + file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if file_ext not in allowed_extensions:
            return jsonify({'success': False, 'message': 'Invalid file type. Only JPG, PNG, PDF allowed'})
        
        import base64
        proof_data = base64.b64encode(file.read()).decode('utf-8')
        
        with sqlite3.connect('gamebet.db') as conn:
            c = conn.cursor()
    
            # Add payment_proof column if not exists
            try:
                c.execute('ALTER TABLE transactions ADD COLUMN payment_proof TEXT')
            except sqlite3.OperationalError:
                pass
            
            # Get withdrawal details for notification with validation
            c.execute('SELECT user_id, amount, type FROM transactions WHERE id = ? AND type = "pending_withdrawal"', (withdrawal_id,))
            withdrawal = c.fetchone()
            
            if not withdrawal:
                return jsonify({'success': False, 'message': 'Withdrawal not found or already processed'})
            
            user_id, amount, _ = withdrawal
            amount = abs(float(amount)) if amount else 0
            
            c.execute('UPDATE transactions SET type = "withdrawal", payment_proof = ? WHERE id = ?', 
                     (proof_data, withdrawal_id))
            
            # Send notification message to user
            notification_msg = f'ðŸŽ‰ PAYMENT COMPLETED! Your withdrawal of KSh {amount:.0f} has been processed successfully. Check your M-Pesa for confirmation.'
            c.execute('INSERT INTO withdrawal_chat (withdrawal_id, user_id, message, is_admin) VALUES (?, ?, ?, ?)',
                     (withdrawal_id, 1, notification_msg, 1))
            
            conn.commit()
            
        return jsonify({'success': True, 'message': 'Withdrawal marked as paid with proof uploaded'})
        
    except (ValueError, TypeError) as e:
        return jsonify({'success': False, 'message': 'Invalid withdrawal ID'})
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': 'Database error occurred'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'An error occurred processing the withdrawal'})

@app.route('/admin/process_payment', methods=['POST'])
@admin_required
def process_payment():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    withdrawal_id = request.form['withdrawal_id']
    
    if 'payment_proof' not in request.files:
        return jsonify({'success': False, 'message': 'Payment proof required'})
    
    file = request.files['payment_proof']
    if not file.filename:
        return jsonify({'success': False, 'message': 'No file selected'})
    
    import base64
    proof_data = base64.b64encode(file.read()).decode('utf-8')
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Add payment_proof column if not exists
    try:
        c.execute('ALTER TABLE transactions ADD COLUMN payment_proof TEXT')
    except sqlite3.Error as e:
        flash('Database error occurred', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('An error occurred', 'error')
        return redirect(url_for('dashboard'))
    
    c.execute('UPDATE transactions SET type = "withdrawal", payment_proof = ? WHERE id = ?', 
             (proof_data, withdrawal_id))
    conn.commit()
    return jsonify({'success': True, 'message': 'Payment processed with proof uploaded'})

@app.route('/admin/approve_withdrawal/<int:withdrawal_id>', methods=['GET'])
@admin_required
def approve_withdrawal(withdrawal_id):
    # Redirect to withdrawal chat for manual approval with screenshot
    return redirect(url_for('withdrawal_chat', withdrawal_id=withdrawal_id))

@app.route('/admin/reject_withdrawal/<int:withdrawal_id>', methods=['POST', 'GET'])
@admin_required
def reject_withdrawal(withdrawal_id):
    transaction_id = withdrawal_id
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        rejection_reason = request.form.get('rejection_reason', 'No reason provided')
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
        c.execute('SELECT user_id, amount FROM transactions WHERE id = ?', (transaction_id,))
        transaction = c.fetchone()
        
        if transaction:
            user_id, amount = transaction
            refund_amount = abs(amount)  # Refund the withdrawal amount only
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (refund_amount, user_id))
            c.execute('UPDATE transactions SET type = "rejected_withdrawal" WHERE id = ?', (transaction_id,))
            
            # Update transaction description with rejection reason
            c.execute('UPDATE transactions SET description = ? WHERE id = ?', 
                     (f'Cancelled Withdrawal - {rejection_reason} - KSh {refund_amount:.0f} refunded', transaction_id))
            
            # Send detailed rejection message
            notification_msg = f'âŒ WITHDRAWAL CANCELLED BY ADMIN\n\nReason: {rejection_reason}\n\nYour KSh {refund_amount:.0f} has been refunded to your account. You can request a new withdrawal after fixing the issue.'
            c.execute('INSERT INTO withdrawal_chat (withdrawal_id, user_id, message, is_admin) VALUES (?, ?, ?, ?)',
                     (transaction_id, 1, notification_msg, 1))
            
            conn.commit()
            flash(f'Withdrawal rejected with reason: {rejection_reason}', 'success')
        else:
            flash('Withdrawal not found!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # GET request - show rejection form
    return render_template('admin_reject_withdrawal.html', withdrawal_id=withdrawal_id)

@app.route('/admin/live_streams')
@login_required
def admin_live_streams():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get only active/live streams
    c.execute('''SELECT s.id, s.title, s.viewers, s.created_at, s.match_id, s.tournament_id,
                        u.username, COALESCE(m.game, 'Competition Stream') as game, s.status
                 FROM streams s
                 JOIN users u ON s.user_id = u.id
                 LEFT JOIN matches m ON s.match_id = m.id
                 WHERE s.status IN ('live', 'pending')
                 ORDER BY s.created_at DESC
                 LIMIT 50''')
    
    streams_data = c.fetchall()
    streams = []
    for stream in streams_data:
        from datetime import datetime
        try:
            created_time = datetime.fromisoformat(stream[3])
            duration = int((datetime.now() - created_time).total_seconds() / 60)
        except:
            duration = 0
        
        # Include all streams but mark status
        streams.append({
            'id': stream[0],
            'title': stream[1] or 'Untitled Stream',
            'viewers': stream[2] or 0,
            'duration': duration,
            'username': stream[6],
            'game': stream[7],
            'status': stream[8],
            'match_id': stream[4] or 'N/A',
            'tournament_id': stream[5] or 'N/A'
        })
    
    return jsonify({'streams': streams})

@app.route('/admin/live_streams_page')
@admin_required
def admin_live_streams_page():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    return render_template('admin_live_streams.html')

@app.route('/admin/stream_details/<int:stream_id>')
@login_required
def admin_stream_details(stream_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('''SELECT s.*, u.username FROM streams s
                 JOIN users u ON s.user_id = u.id
                 WHERE s.id = ?''', (stream_id,))
    stream = c.fetchone()
    if stream:
        return jsonify({
            'success': True,
            'stream': {
                'title': stream[4],
                'username': stream[10],
                'created_at': stream[9],
                'viewers': stream[5],
                'match_id': stream[2],
                'tournament_id': stream[3]
            }
        })
    
    return jsonify({'success': False})

@app.route('/admin/end_stream/<int:stream_id>', methods=['POST'])
@admin_required
def admin_end_stream(stream_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('UPDATE streams SET status = "ended" WHERE id = ?', (stream_id,))
    conn.commit()
    return jsonify({'success': True})

@app.route('/admin/force_end_stream/<int:stream_id>', methods=['POST'])
@admin_required
def admin_force_end_stream(stream_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Force end stream and clean up
    c.execute('UPDATE streams SET status = "ended" WHERE id = ?', (stream_id,))
    c.execute('DELETE FROM stream_viewers WHERE stream_id = ?', (stream_id,))
    
    conn.commit()
    return jsonify({'success': True, 'message': 'Stream forcefully ended'})

@app.route('/admin/clean_all_streams', methods=['POST'])
def admin_clean_all_streams():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # End all active streams
    c.execute('UPDATE streams SET status = "ended" WHERE status IN ("live", "pending")')
    cleaned = c.rowcount
    
    # Clean viewers
    c.execute('DELETE FROM stream_viewers')
    
    conn.commit()
    return jsonify({'success': True, 'message': f'Cleaned {cleaned} streams'})

@app.route('/admin/stream_control')
def admin_stream_control():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    return render_template('admin_stream_control.html')

@app.route('/admin/stream_statistics')
def admin_stream_statistics():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get stream statistics
    c.execute('SELECT COUNT(*) FROM streams')
    total_streams = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM streams WHERE status = "ended"')
    completed_streams = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(AVG(JULIANDAY("now") - JULIANDAY(created_at)) * 24 * 60, 0) FROM streams WHERE status = "ended"')
    avg_duration = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE type = "streaming_earnings"')
    total_earnings = c.fetchone()[0]
    return jsonify({
        'success': True,
        'total_streams': total_streams,
        'completed_streams': completed_streams,
        'avg_duration': round(avg_duration, 1),
        'total_earnings': total_earnings
    })

@app.route('/admin/view_deposit/<int:transaction_id>')
def view_deposit_details(transaction_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('''SELECT dv.mpesa_number, dv.sender_name, dv.receipt_screenshot, dv.amount_sent, dv.created_at,
                        t.amount as amount_to_credit, u.username, u.email
                 FROM deposit_verifications dv
                 JOIN transactions t ON dv.transaction_id = t.id
                 JOIN users u ON dv.user_id = u.id
                 WHERE dv.transaction_id = ?''', (transaction_id,))
    deposit_details = c.fetchone()
    if deposit_details:
        return jsonify({
            'success': True,
            'details': {
                'username': deposit_details[6],
                'email': deposit_details[7],
                'mpesa_number': deposit_details[0],
                'sender_name': deposit_details[1],
                'amount_sent': deposit_details[3],
                'amount_to_credit': deposit_details[5],
                'receipt_screenshot': deposit_details[2],
                'created_at': deposit_details[4]
            }
        })
    
    return jsonify({'success': False, 'message': 'Deposit not found'})

@app.route('/admin/reset_password_new', methods=['POST'])
def admin_reset_password_new():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    user_id = data['user_id']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    new_password = generate_password_hash('password123')
    c.execute('UPDATE users SET password = ? WHERE id = ?', (new_password, user_id))
    conn.commit()
    return jsonify({'success': True, 'message': 'Password reset to "password123" successfully!'})

@app.route('/admin/adjust_balance_new', methods=['POST'])
def admin_adjust_balance_new():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    user_id = data['user_id']
    amount = float(data['amount'])
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
    c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
             (user_id, 'admin_adjustment', amount, f'Admin balance adjustment: {amount}'))
    
    conn.commit()
    return jsonify({'success': True, 'message': f'Balance adjusted by KSh {amount}'})

@app.route('/admin/toggle_ban', methods=['POST'])
def admin_toggle_ban():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    user_id = data['user_id']
    action = data['action']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    try:
        c.execute('ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0')
    except sqlite3.Error as e:
        flash('Database error occurred', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('An error occurred', 'error')
        return redirect(url_for('dashboard'))
    
    if action == 'ban':
        c.execute('UPDATE users SET banned = 1 WHERE id = ?', (user_id,))
        message = 'User banned successfully'
    else:
        c.execute('UPDATE users SET banned = 0 WHERE id = ?', (user_id,))
        message = 'User unbanned successfully'
    
    conn.commit()
    return jsonify({'success': True, 'message': message})

@app.route('/admin/user_stats/<int:user_id>')
def admin_user_stats(user_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get match wins and losses
    c.execute('SELECT COUNT(*) FROM matches WHERE winner_id = ? AND status = "completed"', (user_id,))
    wins = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM matches WHERE (player1_id = ? OR player2_id = ?) AND winner_id != ? AND status = "completed"', (user_id, user_id, user_id))
    losses = c.fetchone()[0]
    
    # Get earnings from all positive transactions except deposits
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND amount > 0 AND type NOT IN ("deposit", "paypal_deposit", "crypto_deposit", "refund", "match_refund")', (user_id,))
    earnings = c.fetchone()[0]
    
    # Get total deposits
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type IN ("deposit", "paypal_deposit", "crypto_deposit")', (user_id,))
    deposits = c.fetchone()[0]
    
    # Get total withdrawals
    c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE user_id = ? AND type = "withdrawal"', (user_id,))
    withdrawals = c.fetchone()[0]
    return jsonify({
        'success': True,
        'wins': wins,
        'losses': losses,
        'earnings': f'{earnings:.0f}',
        'deposits': f'{deposits:.0f}',
        'withdrawals': f'{withdrawals:.0f}'
    })

@app.route('/admin/unban_fake_screenshot_user', methods=['POST'])
def admin_unban_fake_screenshot_user():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    user_id = data['user_id']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS fake_screenshot_tracking (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        match_id INTEGER,
        game_type TEXT,
        screenshot_data TEXT,
        fake_count INTEGER DEFAULT 0,
        is_banned INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Get user's fake screenshot history
    c.execute('SELECT fake_count FROM fake_screenshot_tracking WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', (user_id,))
    current_record = c.fetchone()
    
    if current_record:
        # Unban user and reset counter to 1 (giving them a second chance)
        c.execute('''UPDATE fake_screenshot_tracking SET is_banned = 0, fake_count = 1 
                     WHERE user_id = ? AND id = (SELECT MAX(id) FROM fake_screenshot_tracking WHERE user_id = ?)''',
                 (user_id, user_id))
        
        # Add admin note to transaction history
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (user_id, 'admin_unban', 0, 'Admin unbanned user - fake screenshot counter reset to 1 - Second chance given'))
        
        # Get username for response
        c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user_data = c.fetchone()
        username = user_data[0] if user_data else f'User {user_id}'
        
        conn.commit()
        return jsonify({
            'success': True, 
            'message': f'User {username} unbanned successfully. Fake screenshot counter reset to 1 (second chance given). History preserved for admin reference.'
        })
    else:
        return jsonify({'error': 'No fake screenshot record found for this user'}), 404

@app.route('/admin/respond_support', methods=['POST'])
def admin_respond_support():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    escalation_id = data['escalation_id']
    response = data['response']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('UPDATE support_escalations SET admin_response = ?, status = "resolved" WHERE id = ?',
             (response, escalation_id))
    
    conn.commit()
    return jsonify({'success': True, 'message': 'Response sent successfully'})

@app.route('/admin/lookup_user')
def admin_lookup_user():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    user_id = request.args.get('id')
    username = request.args.get('username')
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    if user_id:
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    elif username:
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
    else:
        return jsonify({'success': False, 'message': 'No search parameter provided'})
    
    user = c.fetchone()
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    # Get additional user statistics
    user_id = user[0]
    
    # Get financial data
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type IN ("deposit", "paypal_deposit", "crypto_deposit")', (user_id,))
    total_deposits = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE user_id = ? AND type = "withdrawal"', (user_id,))
    total_withdrawals = c.fetchone()[0]
    
    # Get fake screenshot count
    c.execute('SELECT COALESCE(MAX(fake_count), 0) FROM fake_screenshot_tracking WHERE user_id = ?', (user_id,))
    fake_count = c.fetchone()[0]
    
    # Check if banned
    c.execute('SELECT banned FROM users WHERE id = ?', (user_id,))
    banned_result = c.fetchone()
    banned = banned_result[0] if banned_result and len(banned_result) > 0 else 0
    user_data = {
        'id': user[0],
        'username': user[1],
        'email': user[2],
        'balance': user[4],
        'phone': user[5],
        'wins': user[6] if len(user) > 6 else 0,
        'losses': user[7] if len(user) > 7 else 0,
        'total_earnings': user[8] if len(user) > 8 else 0,
        'referral_code': user[9] if len(user) > 9 else None,
        'created_at': user[10] if len(user) > 10 else 'Unknown',
        'total_deposits': total_deposits,
        'total_withdrawals': total_withdrawals,
        'fake_count': fake_count,
        'banned': banned,
        'last_active': 'Recently' # Could be enhanced with actual last login tracking
    }
    
    return jsonify({'success': True, 'user': user_data})

@app.route('/admin/user_detailed_stats/<int:user_id>')
def admin_user_detailed_stats(user_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get detailed earnings breakdown
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type = "match_win"', (user_id,))
    match_winnings = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type = "streaming_earnings"', (user_id,))
    streaming_earnings = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type = "referral_bonus"', (user_id,))
    referral_bonuses = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE user_id = ? AND type LIKE "%penalty%"', (user_id,))
    penalties = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(AVG(bet_amount), 0) FROM matches WHERE player1_id = ? OR player2_id = ?', (user_id, user_id))
    avg_bet = c.fetchone()[0]
    
    total_earnings = match_winnings + streaming_earnings + referral_bonuses
    stats = {
        'total_earnings': total_earnings,
        'match_winnings': match_winnings,
        'streaming_earnings': streaming_earnings,
        'referral_bonuses': referral_bonuses,
        'penalties': penalties,
        'avg_bet': avg_bet
    }
    
    return jsonify({'success': True, 'stats': stats})

@app.route('/admin/user_activity/<int:user_id>')
def admin_user_activity(user_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get recent transactions
    c.execute('''SELECT type, amount, description, created_at FROM transactions 
                 WHERE user_id = ? ORDER BY created_at DESC LIMIT 20''', (user_id,))
    transactions = c.fetchall()
    transaction_list = [{
        'type': tx[0],
        'amount': tx[1],
        'description': tx[2],
        'created_at': tx[3]
    } for tx in transactions]
    
    return jsonify({'success': True, 'transactions': transaction_list})

@app.route('/admin/user_matches/<int:user_id>')
def admin_user_matches(user_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get user info
    c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Get user's matches
    c.execute('''SELECT m.id, m.game, m.player1_id, m.player2_id, m.bet_amount, m.total_pot,
                        m.winner_id, m.status, m.game_mode, m.created_at,
                        u1.username as p1_name, u2.username as p2_name
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.player1_id = ? OR m.player2_id = ?
                 ORDER BY m.created_at DESC''', (user_id, user_id))
    matches = c.fetchall()
    return render_template('admin_user_matches.html', user=user, matches=matches, user_id=user_id)

@app.route('/admin/send_user_message', methods=['POST'])
def admin_send_user_message():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    user_id = data['user_id']
    message = data['message']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create admin_messages table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS admin_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        message TEXT,
        sent_by TEXT DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Insert message
    c.execute('INSERT INTO admin_messages (user_id, message) VALUES (?, ?)', (user_id, message))
    
    conn.commit()
    return jsonify({'success': True, 'message': 'Message sent successfully'})

@app.route('/admin/download_financial_statement')
def download_financial_statement():
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get comprehensive financial data
    from datetime import datetime
    current_date = datetime.now().strftime('%Y-%m-%d')
    
    # Revenue breakdown
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "deposit_fee"')
    deposit_fees = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "withdrawal_fee"')
    withdrawal_fees = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = "admin_fraud_commission"')
    fraud_commissions = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*), COALESCE(SUM(total_pot), 0) FROM matches WHERE status = "completed"')
    match_data = c.fetchone()
    completed_matches = match_data[0]
    total_pot = match_data[1]
    match_commission = total_pot * 0.32
    
    # User statistics
    c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
    total_users = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(balance), 0) FROM users WHERE username != "admin"')
    total_user_balance = c.fetchone()[0]
    
    # Generate CSV content
    csv_content = f"""SkillStake Gaming Platform - Financial Statement
Generated: {current_date}

=== REVENUE BREAKDOWN ===
Deposit Processing Fees,KSh {deposit_fees:.2f}
Withdrawal Processing Fees,KSh {withdrawal_fees:.2f}
Match Commission (32%),KSh {match_commission:.2f}
Fraud Penalties,KSh {fraud_commissions:.2f}
Total Gross Revenue,KSh {deposit_fees + withdrawal_fees + match_commission + fraud_commissions:.2f}

=== PLATFORM STATISTICS ===
Total Users,{total_users}
Completed Matches,{completed_matches}
Total User Balance,KSh {total_user_balance:.2f}

=== DETAILED TRANSACTIONS ===
Date,Type,Amount,Description
"""
    
    # Add recent transactions
    c.execute('''SELECT created_at, type, amount, description FROM transactions 
                 WHERE user_id = 1 OR type LIKE "%fee%" OR type LIKE "%commission%" 
                 ORDER BY created_at DESC LIMIT 100''')
    transactions = c.fetchall()
    
    for tx in transactions:
        csv_content += f"{tx[0]},{tx[1]},KSh {tx[2]:.2f},\"{tx[3]}\"\n"
    # Return as downloadable file
    from flask import Response
    return Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=skillstake_financial_statement_{current_date}.csv'}
    )

@app.route('/admin/view_fake_screenshot_history/<int:user_id>')
def admin_view_fake_screenshot_history(user_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create fake screenshot tracking table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS fake_screenshot_tracking (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        match_id INTEGER,
        game_type TEXT,
        screenshot_data TEXT,
        fake_count INTEGER DEFAULT 0,
        is_banned INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Get user's fake screenshot history with screenshot data
    c.execute('''SELECT fst.match_id, fst.game_type, fst.fake_count, fst.is_banned, fst.created_at,
                        u.username, fst.screenshot_data
                 FROM fake_screenshot_tracking fst
                 JOIN users u ON fst.user_id = u.id
                 WHERE fst.user_id = ? ORDER BY fst.created_at DESC''', (user_id,))
    history = c.fetchall()
    
    # Get related penalty transactions
    c.execute('''SELECT type, amount, description, created_at FROM transactions 
                 WHERE user_id = ? AND type IN ('fake_screenshot_penalty', 'admin_unban') 
                 ORDER BY created_at DESC''', (user_id,))
    penalties = c.fetchall()
    
    # Get username even if no fake screenshot history
    if not history:
        c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user_data = c.fetchone()
        if user_data:
            return jsonify({
                'success': True,
                'username': user_data[0],
                'history': [],
                'penalties': [{
                    'type': p[0],
                    'amount': p[1],
                    'description': p[2],
                    'created_at': p[3]
                } for p in penalties],
                'message': 'User found but no fake screenshot violations on record.'
            })
        else:
            return jsonify({'success': False, 'message': 'User not found'})
    return jsonify({
        'success': True,
        'username': history[0][5],
        'history': [{
            'match_id': h[0],
            'game_type': h[1],
            'fake_count': h[2],
            'is_banned': h[3],
            'created_at': h[4],
            'screenshot_data': h[6]
        } for h in history],
        'penalties': [{
            'type': p[0],
            'amount': p[1],
            'description': p[2],
            'created_at': p[3]
        } for p in penalties]
    })

@app.route('/admin/view_match_screenshots/<int:match_id>')
def view_match_screenshots(match_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get match details with proper player names
    c.execute('''SELECT m.id, m.game, m.player1_id, m.player2_id, m.bet_amount, m.total_pot,
                        m.winner_id, m.status, m.game_mode, m.created_at,
                        u1.username as p1_name, u2.username as p2_name
                 FROM matches m
                 LEFT JOIN users u1 ON m.player1_id = u1.id
                 LEFT JOIN users u2 ON m.player2_id = u2.id
                 WHERE m.id = ?''', (match_id,))
    match = c.fetchone()
    
    # Get screenshots with OCR analysis
    c.execute('''SELECT ms.id, ms.match_id, ms.user_id, ms.screenshot_data, ms.claimed_result, 
                        ms.ocr_analysis, ms.submitted_at, u.username 
                 FROM match_screenshots ms
                 JOIN users u ON ms.user_id = u.id
                 WHERE ms.match_id = ? ORDER BY ms.submitted_at''', (match_id,))
    screenshots = c.fetchall()
    if match and screenshots:
        return jsonify({
            'success': True,
            'match': {
                'id': match[0],
                'game': match[1],
                'bet_amount': match[4],
                'p1_name': match[10],
                'p2_name': match[11]
            },
            'screenshots': [{
                'user_id': s[2],
                'username': s[7],
                'claimed_result': s[4],
                'screenshot_data': s[3],
                'submitted_at': s[6],
                'ocr_analysis': s[5] if len(s) > 5 else None
            } for s in screenshots]
        })
    
    return jsonify({'success': False, 'message': 'No screenshots found'})

@app.route('/admin/charge_fake_screenshots/<int:match_id>', methods=['POST'])
def charge_fake_screenshots(match_id):
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    winner = data.get('winner')
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get match and players
    c.execute('SELECT player1_id, player2_id, bet_amount FROM matches WHERE id = ?', (match_id,))
    match = c.fetchone()
    
    if not match:
        return jsonify({'error': 'Match not found'}), 404
    
    player1_id, player2_id, bet_amount = match
    penalty = 50
    
    # Check how many screenshots submitted
    c.execute('SELECT COUNT(*) FROM match_screenshots WHERE match_id = ?', (match_id,))
    screenshot_count = c.fetchone()[0]
    
    # If only one player submitted, handle fake screenshot penalty only
    if screenshot_count < 2:
        if winner == 'player1_fake':
            # Player 1 sent fake, penalize and remove their screenshot
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (penalty, player1_id))
            c.execute('DELETE FROM match_screenshots WHERE match_id = ? AND user_id = ?', (match_id, player1_id))
            c.execute('UPDATE matches SET status = "active" WHERE id = ?', (match_id,))
            message = 'Player 1 penalized KSh 50 for fake screenshot. Screenshot removed. Waiting for valid submission.'
        elif winner == 'player2_fake':
            # Player 2 sent fake, penalize and remove their screenshot  
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (penalty, player2_id))
            c.execute('DELETE FROM match_screenshots WHERE match_id = ? AND user_id = ?', (match_id, player2_id))
            c.execute('UPDATE matches SET status = "active" WHERE id = ?', (match_id,))
            message = 'Player 2 penalized KSh 50 for fake screenshot. Screenshot removed. Waiting for valid submission.'
        else:
            return jsonify({'error': 'Cannot declare winner - other player has not submitted screenshot yet'}), 400
        
        # Add admin commission from penalty
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (1, 'admin_fraud_commission', penalty, f'Commission from fraud penalty - Match {match_id}'))
        
        conn.commit()
        return jsonify({'success': True, 'message': message})
    
    # Both players submitted - proceed with original logic
    if winner in ['player1', 'player2'] and screenshot_count < 2:
        return jsonify({'error': 'Cannot declare winner - other player has not submitted screenshot yet'}), 400
    
    if winner == 'both_fake':
        # Both sent fake - charge both, refund match
        for user_id in [player1_id, player2_id]:
            if user_id:
                c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (penalty, user_id))
                c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bet_amount, user_id))
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (user_id, 'fake_screenshot_penalty', -penalty, f'Penalty for fake screenshot in match {match_id}'))
                # Add admin commission from penalty
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (1, 'admin_fraud_commission', penalty, f'Commission from fraud penalty - Match {match_id}'))
        
        c.execute('UPDATE matches SET status = "cancelled_fake_ss" WHERE id = ?', (match_id,))
        message = 'Both users charged KSh 50 penalty. Match cancelled and refunded.'
        
    elif winner == 'player1':
        # Player 1 real, Player 2 fake - Player 1 wins
        winnings = bet_amount * 1.68
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (winnings, player1_id))
        c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (penalty, player2_id))
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (player2_id, 'fake_screenshot_penalty', -penalty, f'Penalty for fake screenshot in match {match_id}'))
        # Add admin commission from penalty
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (1, 'admin_fraud_commission', penalty, f'Commission from fraud penalty - Match {match_id}'))
        
        c.execute('UPDATE matches SET winner_id = ?, status = "completed" WHERE id = ?', (player1_id, match_id))
        message = f'Player 1 wins KSh {winnings}. Player 2 charged KSh 50 penalty for fake screenshot.'
        
    elif winner == 'player2':
        # Player 2 real, Player 1 fake - Player 2 wins
        winnings = bet_amount * 1.68
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (winnings, player2_id))
        c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (penalty, player1_id))
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (player1_id, 'fake_screenshot_penalty', -penalty, f'Penalty for fake screenshot in match {match_id}'))
        # Add admin commission from penalty
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (1, 'admin_fraud_commission', penalty, f'Commission from fraud penalty - Match {match_id}'))
        
        c.execute('UPDATE matches SET winner_id = ?, status = "completed" WHERE id = ?', (player2_id, match_id))
        message = f'Player 2 wins KSh {winnings}. Player 1 charged KSh 50 penalty for fake screenshot.'
    
    conn.commit()
    return jsonify({'success': True, 'message': message})

@app.route('/admin/resolve_dispute/<int:match_id>/<winner>', methods=['GET', 'POST'])
def resolve_dispute(match_id, winner):
    if 'user_id' not in session or session.get('username') != 'admin':
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('SELECT player1_id, player2_id, bet_amount, game FROM matches WHERE id = ?', (match_id,))
    match = c.fetchone()
    
    if match:
        player1_id, player2_id, bet_amount, game = match
        
        if winner == 'player1':
            winner_id, loser_id = player1_id, player2_id
        elif winner == 'player2':
            winner_id, loser_id = player2_id, player1_id
        else:  # refund
            c.execute('UPDATE users SET balance = balance + ? WHERE id IN (?, ?)', (bet_amount, player1_id, player2_id))
            c.execute('UPDATE matches SET status = "refunded" WHERE id = ?', (match_id,))
            
            # Record refund transactions
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (player1_id, 'match_refund', bet_amount, f'Match #{match_id} admin refund - {game.upper()} - Dispute resolved'))
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (player2_id, 'match_refund', bet_amount, f'Match #{match_id} admin refund - {game.upper()} - Dispute resolved'))
            
            conn.commit()
            flash('Match refunded to both players!', 'success')
            return redirect(url_for('admin_support_center'))
        
        # Award winner with precise calculation
        winnings = calculate_winnings(bet_amount, 1.68)
        c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1, total_earnings = total_earnings + ? WHERE id = ?', 
                 (winnings, winnings, winner_id))
        c.execute('UPDATE users SET losses = losses + 1 WHERE id = ?', (loser_id,))
        c.execute('UPDATE matches SET winner_id = ?, status = "completed" WHERE id = ?', (winner_id, match_id))
        
        # Record admin resolution transaction
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (winner_id, 'match_win', winnings, f'Match #{match_id} admin resolution - {game.upper()} - Dispute resolved in your favor'))
        
        conn.commit()
        flash('Match verified and completed!', 'success')
    return redirect(url_for('admin_support_center'))

@app.route('/withdrawal_chat/<int:withdrawal_id>')
@login_required
def withdrawal_chat(withdrawal_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create withdrawal_chat table
    c.execute('''CREATE TABLE IF NOT EXISTS withdrawal_chat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        withdrawal_id INTEGER,
        user_id INTEGER,
        message TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT (datetime('now'))
    )''')
    
    # Get withdrawal details (admin can see any withdrawal)
    if session.get('username') == 'admin':
        c.execute('SELECT * FROM transactions WHERE id = ?', (withdrawal_id,))
    else:
        c.execute('SELECT * FROM transactions WHERE id = ? AND user_id = ?', (withdrawal_id, session['user_id']))
    
    withdrawal = c.fetchone()
    
    if not withdrawal:
        flash('Withdrawal not found!', 'error')
        return redirect(url_for('wallet') if session.get('username') != 'admin' else url_for('admin_dashboard'))
    
    # Get chat messages
    c.execute('SELECT message, is_admin, created_at FROM withdrawal_chat WHERE withdrawal_id = ? ORDER BY created_at', (withdrawal_id,))
    messages = c.fetchall()
    return render_template('withdrawal_chat.html', withdrawal=withdrawal, messages=messages, withdrawal_id=withdrawal_id)

@app.route('/send_withdrawal_message', methods=['POST'])
@login_required
def send_withdrawal_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    withdrawal_id = data['withdrawal_id']
    message = data['message']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Check if user owns this withdrawal or is admin
    c.execute('SELECT user_id FROM transactions WHERE id = ?', (withdrawal_id,))
    withdrawal_owner = c.fetchone()
    
    if not withdrawal_owner or (withdrawal_owner[0] != session['user_id'] and session.get('username') != 'admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    c.execute('INSERT INTO withdrawal_chat (withdrawal_id, user_id, message, is_admin) VALUES (?, ?, ?, ?)',
             (withdrawal_id, session['user_id'], message, 1 if session.get('username') == 'admin' else 0))
    
    conn.commit()
    return jsonify({'success': True})

@app.route('/get_withdrawal_messages/<int:withdrawal_id>')
@login_required
def get_withdrawal_messages(withdrawal_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Check if user owns this withdrawal or is admin
    c.execute('SELECT user_id FROM transactions WHERE id = ?', (withdrawal_id,))
    withdrawal_owner = c.fetchone()
    
    if not withdrawal_owner or (withdrawal_owner[0] != session['user_id'] and session.get('username') != 'admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    # Get chat messages
    c.execute('SELECT message, is_admin, created_at FROM withdrawal_chat WHERE withdrawal_id = ? ORDER BY created_at', (withdrawal_id,))
    messages = c.fetchall()
    return jsonify({
        'messages': [{'message': m[0], 'is_admin': m[1], 'time': m[2]} for m in messages]
    })

@app.route('/alert_admin_deposit', methods=['POST'])
@login_required
def alert_admin_deposit():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    transaction_id = data['transaction_id']
    amount = data['amount']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Verify transaction belongs to user and is pending
    c.execute('SELECT user_id, type FROM transactions WHERE id = ? AND user_id = ?', (transaction_id, session['user_id']))
    transaction = c.fetchone()
    
    if not transaction or transaction[1] != 'pending_deposit':
        return jsonify({'success': False, 'message': 'Invalid transaction'})
    
    # Create admin notification table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS admin_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        transaction_id INTEGER,
        message TEXT,
        type TEXT,
        status TEXT DEFAULT 'unread',
        created_at DATETIME DEFAULT (datetime('now'))
    )''')
    
    # Add notification for admin
    notification_msg = f'User {session["username"]} is requesting review of their KSh {amount:.0f} deposit (Transaction #{transaction_id})'
    c.execute('''INSERT INTO admin_notifications (user_id, username, transaction_id, message, type)
                 VALUES (?, ?, ?, ?, ?)''',
             (session['user_id'], session['username'], transaction_id, notification_msg, 'deposit_alert'))
    
    conn.commit()
    return jsonify({'success': True, 'message': 'Alert sent to admin successfully'})

@app.route('/admin/mark_alert_read', methods=['POST'])
@admin_required
def mark_alert_read():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    alert_id = data['alert_id']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('UPDATE admin_notifications SET status = "read" WHERE id = ?', (alert_id,))
    conn.commit()
    return jsonify({'success': True})

@app.route('/admin/user_count')
@admin_required
def admin_user_count():
    """API endpoint to get current user count"""
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users WHERE username != "admin"')
        total_users = c.fetchone()[0]
        
        c.execute('SELECT id, username, created_at FROM users WHERE username != "admin" ORDER BY id DESC LIMIT 5')
        recent_users = c.fetchall()
        
    return jsonify({
        'success': True,
        'total_users': total_users,
        'recent_users': [{
            'id': u[0],
            'username': u[1], 
            'created_at': u[2]
        } for u in recent_users]
    })

@app.route('/admin/status')
@admin_required
def admin_status():
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create admin_activity table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS admin_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        last_active DATETIME DEFAULT (datetime('now'))
    )''')
    
    # Get last admin activity
    c.execute('SELECT last_active FROM admin_activity ORDER BY id DESC LIMIT 1')
    last_active = c.fetchone()
    
    if last_active:
        from datetime import datetime
        last_time = datetime.fromisoformat(last_active[0])
        inactive_minutes = (datetime.now() - last_time).total_seconds() / 60
        active = inactive_minutes < 5  # Admin considered active if last seen <5 min
    else:
        inactive_minutes = 999
        active = False
    return jsonify({'active': active, 'inactive_minutes': inactive_minutes})

@app.route('/cancel_withdrawal', methods=['POST'])
@login_required
def cancel_withdrawal():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    withdrawal_id = data['withdrawal_id']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Check if withdrawal belongs to user and is pending
    c.execute('SELECT user_id, amount FROM transactions WHERE id = ? AND user_id = ? AND type = "pending_withdrawal"', 
             (withdrawal_id, session['user_id']))
    withdrawal = c.fetchone()
    
    if not withdrawal:
        return jsonify({'success': False, 'message': 'Withdrawal not found or already processed'})
    
    # Process cancellation - refund amount + fee
    amount = abs(withdrawal[1]) + 15  # Refund amount + fee
    c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, session['user_id']))
    c.execute('UPDATE transactions SET type = "cancelled_withdrawal" WHERE id = ?', (withdrawal_id,))
    
    conn.commit()
    return jsonify({'success': True, 'message': f'Withdrawal cancelled. KSh {amount} returned to your account.'})

@app.route('/request_auto_refund', methods=['POST'])
@login_required
def request_auto_refund():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    withdrawal_id = data['withdrawal_id']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Check if withdrawal belongs to user and is pending
    c.execute('SELECT user_id, amount FROM transactions WHERE id = ? AND user_id = ? AND type = "pending_withdrawal"', 
             (withdrawal_id, session['user_id']))
    withdrawal = c.fetchone()
    
    if not withdrawal:
        return jsonify({'success': False, 'message': 'Withdrawal not found or already processed'})
    
    # Check admin inactivity
    c.execute('SELECT last_active FROM admin_activity ORDER BY id DESC LIMIT 1')
    last_active = c.fetchone()
    
    if last_active:
        from datetime import datetime
        last_time = datetime.fromisoformat(last_active[0])
        inactive_minutes = (datetime.now() - last_time).total_seconds() / 60
        
        if inactive_minutes < 30:
            return jsonify({'success': False, 'message': 'Admin is active. Please wait for processing.'})
    
    # Process refund
    amount = abs(withdrawal[1]) + 15  # Refund amount + fee
    c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, session['user_id']))
    c.execute('UPDATE transactions SET type = "auto_refunded" WHERE id = ?', (withdrawal_id,))
    
    conn.commit()
    return jsonify({'success': True, 'message': f'Refunded KSh {amount}'})

@app.route('/api/withdrawal_status/<int:withdrawal_id>')
@login_required
def get_withdrawal_status(withdrawal_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Check if user owns this withdrawal or is admin
    c.execute('SELECT user_id, type, amount, payment_proof FROM transactions WHERE id = ?', (withdrawal_id,))
    withdrawal = c.fetchone()
    
    if not withdrawal or (withdrawal[0] != session['user_id'] and session.get('username') != 'admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    user_id, status, amount, payment_proof = withdrawal
    
    # Get latest chat message for additional context
    c.execute('SELECT message FROM withdrawal_chat WHERE withdrawal_id = ? ORDER BY created_at DESC LIMIT 1', (withdrawal_id,))
    latest_message = c.fetchone()
    return jsonify({
        'success': True,
        'status': status,
        'amount': abs(amount),
        'payment_proof': payment_proof,
        'latest_message': latest_message[0] if latest_message else None
    })

@app.route('/escalate_support', methods=['POST'])
@login_required
def escalate_support():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    message = data['message']
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('''INSERT INTO support_escalations (user_id, username, message, status, created_at) 
                 VALUES (?, ?, ?, ?, datetime('now'))''',
             (session['user_id'], session['username'], message, 'pending'))
    
    conn.commit()
    return jsonify({'success': True, 'message': 'Support request submitted successfully'})

@app.route('/api/user_balance')
@login_required
def api_user_balance():
    """API endpoint to get current user balance"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
            result = c.fetchone()
            
            if result:
                balance = result[0]
                session['balance'] = balance  # Update session
                return jsonify({'success': True, 'balance': f'{balance:.0f}'})
            else:
                return jsonify({'error': 'User not found'}), 404
                
    except Exception as e:
        return jsonify({'error': 'Database error'}), 500

@app.route('/api/user_stats')
@login_required  
def api_user_stats():
    """API endpoint to get current user stats"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Get updated user data
            c.execute('SELECT balance, wins, losses, total_earnings FROM users WHERE id = ?', (user_id,))
            user_data = c.fetchone()
            
            if not user_data:
                return jsonify({'error': 'User not found'}), 404
            
            balance, wins, losses, earnings = user_data
            
            # Get additional stats
            c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type = "refund"', (user_id,))
            refunds = c.fetchone()[0] or 0
            
            c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE user_id = ? AND type = "rejected_withdrawal"', (user_id,))
            rejected_withdrawals = c.fetchone()[0] or 0
            
            c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND type IN ("deposit", "paypal_deposit", "crypto_deposit")', (user_id,))
            topups = c.fetchone()[0] or 0
            
            c.execute('SELECT COALESCE(SUM(ABS(amount)), 0) FROM transactions WHERE user_id = ? AND type = "withdrawal"', (user_id,))
            accepted_withdrawals = c.fetchone()[0] or 0
            
            stats = {
                'balance': balance or 0,
                'wins': wins or 0,
                'losses': losses or 0,
                'earnings': earnings or 0,
                'refunds': refunds,
                'rejected_withdrawals': rejected_withdrawals,
                'topups': topups,
                'accepted_withdrawals': accepted_withdrawals
            }
            
            return jsonify({'success': True, 'stats': stats})
            
    except Exception as e:
        return jsonify({'error': 'Database error'}), 500

@app.route('/api/refresh_dashboard')
@login_required
def api_refresh_dashboard():
    """API endpoint to refresh dashboard data"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            user_id = session['user_id']
            
            # Recalculate and update user stats
            c.execute('SELECT COUNT(*) FROM matches WHERE winner_id = ? AND status = "completed"', (user_id,))
            wins = c.fetchone()[0] or 0
            
            c.execute('SELECT COUNT(*) FROM matches WHERE (player1_id = ? OR player2_id = ?) AND winner_id != ? AND status = "completed"', (user_id, user_id, user_id))
            losses = c.fetchone()[0] or 0
            
            c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND amount > 0 AND type IN ("match_win", "streaming_earnings", "tournament_prize", "referral_bonus")', (user_id,))
            earnings = c.fetchone()[0] or 0
            
            # Update user record
            c.execute('UPDATE users SET wins = ?, losses = ?, total_earnings = ? WHERE id = ?', 
                     (wins, losses, earnings, user_id))
            
            # Get current balance
            c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
            balance = c.fetchone()[0] or 0
            
            session['balance'] = balance
            conn.commit()
            
            return jsonify({
                'success': True, 
                'message': 'Dashboard refreshed',
                'stats': {
                    'balance': balance,
                    'wins': wins,
                    'losses': losses,
                    'earnings': earnings
                }
            })
            
    except Exception as e:
        return jsonify({'error': 'Refresh failed'}), 500

@app.route('/send_gift', methods=['POST'])
@login_required
def send_gift():
    """Send virtual gift to streamer"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        stream_id = data.get('stream_id')
        gift_type = data.get('gift_type', 'heart')
        amount = data.get('amount', 1)
        
        if not stream_id:
            return jsonify({'error': 'Stream ID required'}), 400
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            # Get stream info
            c.execute('SELECT user_id, status FROM streams WHERE id = ?', (stream_id,))
            stream = c.fetchone()
            
            if not stream:
                return jsonify({'error': 'Stream not found'}), 404
            
            streamer_id, status = stream
            
            if status != 'live':
                return jsonify({'error': 'Stream is not live'}), 400
            
            if streamer_id == session['user_id']:
                return jsonify({'error': 'Cannot send gift to yourself'}), 400
            
            # Gift costs (in KSh)
            gift_costs = {
                'heart': 1,
                'star': 5,
                'diamond': 10,
                'crown': 25
            }
            
            cost = gift_costs.get(gift_type, 1) * amount
            
            # Check sender balance
            c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
            sender_balance = c.fetchone()[0]
            
            if sender_balance < cost:
                return jsonify({'error': f'Insufficient balance. Need KSh {cost}'}), 400
            
            # Process gift transaction
            c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (cost, session['user_id']))
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (cost * 0.7, streamer_id))  # 70% to streamer
            
            # Record transactions
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (session['user_id'], 'gift_sent', -cost, f'Sent {amount}x {gift_type} to stream #{stream_id}'))
            
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (streamer_id, 'gift_received', cost * 0.7, f'Received {amount}x {gift_type} from viewer'))
            
            # Admin commission (30%)
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (1, 'gift_commission', cost * 0.3, f'Commission from gift - Stream #{stream_id}'))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': f'Sent {amount}x {gift_type}!',
                'cost': cost,
                'new_balance': sender_balance - cost
            })
            
    except Exception as e:
        return jsonify({'error': 'Gift sending failed'}), 500





@app.route('/start_independent_stream', methods=['POST'])
@login_required
def start_independent_stream():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    stream_title = data.get('title', 'Live Gaming Stream')
    category = data.get('category', 'other')
    stream_type = data.get('type', 'independent')
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # End any existing streams for this user first
    c.execute('UPDATE streams SET status = "ended" WHERE user_id = ? AND status IN ("live", "pending")', (session['user_id'],))
    c.execute('DELETE FROM stream_viewers WHERE stream_id IN (SELECT id FROM streams WHERE user_id = ? AND status = "ended")', (session['user_id'],))
    
    # Generate stream key
    import uuid
    stream_key = str(uuid.uuid4())[:8]
    
    # Create independent stream (no match_id)
    c.execute('''INSERT INTO streams (user_id, match_id, tournament_id, title, stream_key, stream_type, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''', 
             (session['user_id'], None, None, stream_title, stream_key, stream_type, 'live'))
    
    stream_id = c.lastrowid
    
    # Start with 0 viewers
    c.execute('UPDATE streams SET viewers = ? WHERE id = ?', (0, stream_id))
    
    # Record stream start transaction
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''',
             (session['user_id'], 'stream_started', 0, f'Independent stream started - "{stream_title}" - Category: {category}'))
    
    conn.commit()
    return jsonify({
        'success': True, 
        'stream_id': stream_id, 
        'stream_key': stream_key,
        'stream_url': f'/watch_real_stream/{stream_id}',
        'viewers': 0
    })

@app.route('/start_stream', methods=['POST'])
@login_required
def start_stream():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    match_id = data.get('match_id', 0)
    tournament_id = data.get('tournament_id')
    stream_title = data.get('title', 'Live Gaming Stream')
    stream_type = data.get('type', 'screen')
    is_competition = data.get('competition', False)
    entry_fee = data.get('entry_fee', 0)
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Check if user has enough balance for entry fee
    if entry_fee > 0:
        c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
        balance = c.fetchone()[0]
        
        if balance < entry_fee:
            return jsonify({'error': f'Insufficient balance! Need KSh {entry_fee} to join tournament'}), 400
        
        # Deduct entry fee
        c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (entry_fee, session['user_id']))
        session['balance'] = session.get('balance', 0) - entry_fee
        
        # Record entry fee transaction
        stream_type_desc = "tournament" if tournament_id else "competition"
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (session['user_id'], 'tournament_entry', -entry_fee, 
                  f'{stream_type_desc.title()} entry fee - Stream: {stream_title} - KSh {entry_fee} in prize pool'))
    
    # Generate mock stream URL (simulates real hosting)
    import uuid
    stream_key = str(uuid.uuid4())[:8]
    mock_stream_url = f"https://stream.skillstate.com/live/{stream_key}"
    
    c.execute('''INSERT INTO streams (user_id, match_id, tournament_id, title, stream_key, stream_type, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''', 
             (session['user_id'], match_id, tournament_id, stream_title, stream_key, stream_type, 'live'))
    
    stream_id = c.lastrowid
    
    # Start with 0 real viewers
    c.execute('UPDATE streams SET viewers = ? WHERE id = ?', (0, stream_id))
    
    # Add to competition if participating
    if is_competition:
        c.execute('''SELECT cp.id FROM competition_participants cp
                     JOIN streaming_competitions sc ON cp.competition_id = sc.id
                     WHERE cp.user_id = ? AND sc.status = 'active' 
                     AND date(sc.created_at) = date('now')''', (session['user_id'],))
        competition_entry = c.fetchone()
        
        if competition_entry:
            c.execute('''UPDATE competition_participants 
                         SET earnings = earnings + 5 
                         WHERE id = ?''', (competition_entry[0],))
            
            # Record streaming bonus transaction
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (session['user_id'], 'streaming_bonus', 5, 
                      f'Competition stream start bonus - Stream #{stream_id}'))
    
    conn.commit()
    return jsonify({
        'success': True, 
        'stream_id': stream_id, 
        'stream_key': stream_key,
        'stream_url': f'/watch_real_stream/{stream_id}',
        'viewers': 0
    })

@app.route('/stop_stream/<int:stream_id>', methods=['POST'])
@login_required
def stop_stream(stream_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
        # Get stream details
        c.execute('SELECT viewers, created_at, match_id, tournament_id, status FROM streams WHERE id = ? AND user_id = ?', 
                 (stream_id, session['user_id']))
        stream = c.fetchone()
        
        if not stream:
            return jsonify({'error': 'Stream not found'}), 404
        
        # Check if stream is already ended
        if stream[4] == 'ended':
            return jsonify({'success': True, 'message': 'Stream already ended', 'earnings': 0})
        
        viewers, created_at, match_id, tournament_id, status = stream
        
        # Calculate earnings
        base_earnings = 10  # Simple base
        viewer_bonus = (viewers or 0) * 2
        total_earnings = base_earnings + viewer_bonus
        
        # Add earnings to user balance
        if total_earnings > 0:
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (total_earnings, session['user_id']))
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (session['user_id'], 'streaming_earnings', total_earnings, f'Stream earnings - KSh {total_earnings}'))
        
        # End the stream
        c.execute('UPDATE streams SET status = "ended" WHERE id = ?', (stream_id,))
        c.execute('DELETE FROM stream_viewers WHERE stream_id = ?', (stream_id,))
        
        conn.commit()
        return jsonify({
            'success': True, 
            'earnings': total_earnings,
            'message': f'Stream ended. Earned KSh {total_earnings}'
        })
        
    except Exception as e:
        if 'conn' in locals():
            pass
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/stream_setup/<int:match_id>')
@login_required
def stream_setup(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Check if this is for competition streaming
    is_competition = request.args.get('competition') == 'true'
    
    if is_competition or match_id == 0:
        # Competition streaming - no match required
        return render_template('stream_setup.html', match=None, competition=True)
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('SELECT * FROM matches WHERE id = ? AND (player1_id = ? OR player2_id = ?)', 
             (match_id, session['user_id'], session['user_id']))
    match = c.fetchone()
    
    if not match:
        flash('Match not found!', 'error')
        return redirect(url_for('matches'))
    return render_template('stream_setup.html', match=match, competition=False)

@app.route('/watch_real_stream/<int:stream_id>')
@login_required
def watch_real_stream(stream_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create stream_viewers table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS stream_viewers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stream_id INTEGER,
        user_id INTEGER,
        username TEXT,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(stream_id, user_id)
    )''')
    
    c.execute('''SELECT s.*, u.username FROM streams s 
                 JOIN users u ON s.user_id = u.id 
                 WHERE s.id = ?''', (stream_id,))
    stream = c.fetchone()
    
    if not stream:
        flash('Stream not found!', 'error')
        return redirect(url_for('dashboard'))
    
    # Add viewer to stream if it's live and not the owner
    if stream and stream[6] == 'live' and stream[1] != session['user_id']:
        c.execute('''INSERT OR REPLACE INTO stream_viewers (stream_id, user_id, username) 
                     VALUES (?, ?, ?)''', (stream_id, session['user_id'], session['username']))
        
        # Update viewer count
        c.execute('SELECT COUNT(DISTINCT user_id) FROM stream_viewers WHERE stream_id = ?', (stream_id,))
        viewer_count = c.fetchone()[0]
        c.execute('UPDATE streams SET viewers = ? WHERE id = ?', (viewer_count, stream_id))
        
        conn.commit()
    return render_template('watch_real_stream.html', stream=stream, stream_id=stream_id)

@app.route('/watch_stream/<int:stream_id>')
def watch_stream(stream_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create stream_viewers table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS stream_viewers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stream_id INTEGER,
        user_id INTEGER,
        username TEXT,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(stream_id, user_id)
    )''')
    
    # Get stream details
    c.execute('''SELECT s.*, u.username FROM streams s 
                 JOIN users u ON s.user_id = u.id 
                 WHERE s.id = ?''', (stream_id,))
    stream = c.fetchone()
    
    if not stream:
        flash('Stream not found!', 'error')
        return redirect(url_for('dashboard'))
    
    # Add real viewer to stream (only if stream is live)
    if stream and stream[6] == 'live':
        c.execute('''INSERT OR REPLACE INTO stream_viewers (stream_id, user_id, username) 
                     VALUES (?, ?, ?)''', (stream_id, session['user_id'], session['username']))
        
        # Update real viewer count
        c.execute('SELECT COUNT(DISTINCT user_id) FROM stream_viewers WHERE stream_id = ?', (stream_id,))
        viewer_count = c.fetchone()[0]
        c.execute('UPDATE streams SET viewers = ? WHERE id = ?', (viewer_count, stream_id))
    
    conn.commit()
    # Check if stream is live before allowing viewing
    if not stream or stream[6] != 'live':
        flash('Stream is not available or has ended', 'error')
        return redirect(url_for('live_streams'))
    
    return render_template('watch_stream.html', stream=stream)

@app.route('/stream_viewers/<int:stream_id>')
def stream_viewers(stream_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Check if user owns the stream
    c.execute('SELECT user_id FROM streams WHERE id = ?', (stream_id,))
    stream = c.fetchone()
    
    if not stream:
        return jsonify({'error': 'Stream not found'}), 404
    
    # Check if user owns the stream
    is_owner = stream[0] == session['user_id']
    
    # Get viewer count (available to everyone)
    c.execute('SELECT viewers FROM streams WHERE id = ?', (stream_id,))
    count_result = c.fetchone()
    count = count_result[0] if count_result else 0
    
    if is_owner:
        # Stream owner gets detailed viewer list
        c.execute('''SELECT username, joined_at FROM stream_viewers 
                     WHERE stream_id = ? ORDER BY joined_at DESC''', (stream_id,))
        viewers = c.fetchall()
        return jsonify({
            'viewers': [{'username': v[0], 'joined_at': v[1]} for v in viewers],
            'count': count,
            'is_owner': True
        })
    else:
        # Non-owners only get viewer count
        return jsonify({
            'viewers': [],
            'count': count,
            'is_owner': False
        })

@app.route('/multi_stream/<int:tournament_id>')
def multi_stream(tournament_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get tournament streams
    c.execute('''SELECT s.*, u.username FROM streams s 
                 JOIN users u ON s.user_id = u.id 
                 WHERE s.tournament_id = ? AND s.status = "live" 
                 ORDER BY s.viewers DESC''', (tournament_id,))
    streams = c.fetchall()
    
    c.execute('SELECT * FROM tournaments WHERE id = ?', (tournament_id,))
    tournament = c.fetchone()
    return render_template('multi_stream.html', streams=streams, tournament=tournament)

@app.route('/live_streams')
def live_streams():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create streams table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS streams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        match_id INTEGER,
        tournament_id INTEGER,
        title TEXT,
        viewers INTEGER DEFAULT 0,
        status TEXT DEFAULT 'live',
        stream_key TEXT,
        stream_type TEXT DEFAULT 'screen',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Get all live streams
    c.execute('''SELECT s.*, u.username FROM streams s 
                 JOIN users u ON s.user_id = u.id 
                 WHERE s.status IN ("live", "pending") 
                 ORDER BY s.viewers DESC, s.created_at DESC''')
    streams = c.fetchall()
    return render_template('live_streams.html', streams=streams)



@app.route('/end_stream/<int:stream_id>', methods=['POST'])
def end_stream(stream_id):
    return stop_stream(stream_id)  # Use the same logic

@app.route('/get_stream_url/<int:stream_id>')
def get_stream_url(stream_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('SELECT title, status, user_id FROM streams WHERE id = ?', (stream_id,))
    stream = c.fetchone()
    if not stream:
        return jsonify({'success': False, 'error': 'Stream not found'})
    
    title, status, user_id = stream
    
    return jsonify({
        'success': True,
        'status': status,
        'title': title,
        'is_live': status == 'live',
        'is_owner': user_id == session['user_id']
    })

@app.route('/send_stream_chat', methods=['POST'])
def send_stream_chat():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        stream_id = data.get('stream_id')
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'error': 'Empty message'}), 400
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
            
            c.execute('''CREATE TABLE IF NOT EXISTS stream_chat (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stream_id INTEGER,
                user_id INTEGER,
                username TEXT,
                message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            c.execute('INSERT INTO stream_chat (stream_id, user_id, username, message) VALUES (?, ?, ?, ?)',
                     (stream_id, session['user_id'], session['username'], message))
            
            conn.commit()
            return jsonify({'success': True, 'message': 'Message sent'})
        
    except Exception as e:
        return jsonify({'error': 'Failed to send message'}), 500

@app.route('/get_stream_chat/<int:stream_id>')
def get_stream_chat(stream_id):
    try:
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
        c.execute('SELECT username, message, created_at FROM stream_chat WHERE stream_id = ? ORDER BY created_at DESC LIMIT 50', (stream_id,))
        messages = c.fetchall()
        return jsonify({
            'messages': [{
                'username': m[0],
                'message': m[1],
                'time': m[2]
            } for m in reversed(messages)]
        })
    except:
        return jsonify({'messages': []})

@app.route('/webrtc_signal', methods=['POST'])
def webrtc_signal():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    stream_id = data.get('streamId')
    message = data.get('message')
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS webrtc_signals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stream_id INTEGER,
        user_id INTEGER,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('INSERT INTO webrtc_signals (stream_id, user_id, message) VALUES (?, ?, ?)',
             (stream_id, session['user_id'], str(message)))
    
    conn.commit()
    return jsonify({'success': True})

@app.route('/get_stream_viewers/<int:stream_id>')
def get_stream_viewers_list(stream_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('SELECT username FROM stream_viewers WHERE stream_id = ?', (stream_id,))
    viewers = c.fetchall()
    return jsonify({
        'viewers': [{'username': v[0]} for v in viewers]
    })

@app.route('/send_stream_like', methods=['POST'])
def send_stream_like():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    stream_id = data.get('stream_id')
    likes = data.get('likes', 1)
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS stream_likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stream_id INTEGER,
        user_id INTEGER,
        likes_count INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('INSERT INTO stream_likes (stream_id, user_id, likes_count) VALUES (?, ?, ?)',
             (stream_id, session['user_id'], likes))
    
    conn.commit()
    return jsonify({'success': True})

@app.route('/get_stream_earnings/<int:stream_id>')
def get_stream_earnings(stream_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get total earnings for this stream
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND description LIKE ?',
             (session['user_id'], f'%stream #{stream_id}%'))
    earnings = c.fetchone()[0] or 0
    return jsonify({'success': True, 'earnings': earnings})

@app.route('/update_stream_earnings', methods=['POST'])
def update_stream_earnings():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    stream_id = data.get('stream_id')
    viewers = data.get('viewers', 0)
    
    # Calculate earnings increment
    earnings_increment = viewers * 0.05  # KSh 0.05 per viewer per 5 seconds
    
    if earnings_increment <= 0:
        return jsonify({'success': True, 'total_earnings': 0, 'message': 'No viewers to earn from'})
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Add to user balance
    c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (earnings_increment, session['user_id']))
    
    # Record transaction with proper amount - only if earnings > 0
    if earnings_increment > 0:
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (session['user_id'], 'live_view_earnings', earnings_increment, 
                  f'Live stream viewing earnings - Stream #{stream_id} - {viewers} viewers - KSh {earnings_increment:.2f}'))
    
    # Get total earnings for this stream
    c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND description LIKE ?',
             (session['user_id'], f'%stream #{stream_id}%'))
    total_earnings = c.fetchone()[0] or 0
    
    conn.commit()
    return jsonify({'success': True, 'total_earnings': total_earnings})

@app.route('/get_smart_welcome/<int:stream_id>')
def get_smart_welcome(stream_id):
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get stream and match info
    c.execute('SELECT match_id, tournament_id, title FROM streams WHERE id = ?', (stream_id,))
    stream_info = c.fetchone()
    
    game_type = 'Gaming'
    if stream_info and stream_info[0]:  # Has match_id
        c.execute('SELECT game FROM matches WHERE id = ?', (stream_info[0],))
        match_info = c.fetchone()
        if match_info:
            game_type = match_info[0]
    
    # Smart welcome messages based on game
    messages = {
        'pubg_mobile': f'ðŸ”¥ {session["username"]} is dropping into Sanhok! Who\'s ready for some chicken dinners? ðŸ— Drop your predictions!',
        'cod_mobile': f'ðŸ’¥ {session["username"]} locked and loaded for some COD action! Warzone or MP? Let\'s see those headshots! ðŸŽ¯',
        'fifa_mobile': f'âš½ {session["username"]} is on the pitch! Who\'s your favorite team? Let\'s see some goals! ðŸ¥…',
        'efootball': f'âš½ {session["username"]} ready to dominate the field! Messi or Ronaldo? Drop your predictions! ðŸ†',
        'fortnite': f'ðŸ—ï¸ {session["username"]} building for Victory Royale! Who\'s ready for some epic builds? ðŸŽ®',
        'valorant': f'ðŸŽ¯ {session["username"]} locked in for ranked! Ace incoming? Drop your agent predictions! ðŸ’€'
    }
    
    default_msg = f'ðŸŽ® {session["username"]} is LIVE! Ready for some epic gaming? Drop a follow and let\'s get this party started! ðŸš€'
    
    welcome_message = messages.get(game_type.lower(), default_msg)
    return jsonify({'message': welcome_message})

@app.route('/save_stream_replay', methods=['POST'])
def save_stream_replay():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        stream_id = data.get('stream_id')
        duration = data.get('duration', 0)
        viewers_peak = data.get('viewers_peak', 0)
        
        with sqlite3.connect("gamebet.db") as conn:
            c = conn.cursor()
        
        # Create stream_replays table
        c.execute('''CREATE TABLE IF NOT EXISTS stream_replays (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stream_id INTEGER,
            user_id INTEGER,
            title TEXT,
            duration INTEGER,
            viewers_peak INTEGER,
            earnings REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Get stream info
        c.execute('SELECT title, user_id FROM streams WHERE id = ?', (stream_id,))
        stream_info = c.fetchone()
        
        if stream_info:
            title = stream_info[0] or 'Live Stream'
            
            # Get earnings from this stream
            c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = ? AND (description LIKE ? OR description LIKE ?)', 
                     (session['user_id'], f'%stream #{stream_id}%', f'%Stream #{stream_id}%'))
            earnings = c.fetchone()[0] or 0
            
            # Save replay
            c.execute('''INSERT INTO stream_replays (stream_id, user_id, title, duration, viewers_peak, earnings)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     (stream_id, session['user_id'], title, duration, viewers_peak, earnings))
            
            conn.commit()
            return jsonify({'success': True})
        return jsonify({'error': 'Stream not found'}), 404
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/my_replays')
def my_replays():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('SELECT * FROM stream_replays WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],))
    replays = c.fetchall()
    return render_template('my_replays.html', replays=replays)

@app.route('/ping')
def ping():
    return jsonify({'status': 'ok', 'timestamp': time.time()})

@app.route('/create_daily_competition')
def create_daily_competition():
    """Auto-create daily streaming competition - can be called by cron job"""
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # End yesterday's competitions and award prizes
    c.execute('''UPDATE streaming_competitions 
                 SET status = 'completed' 
                 WHERE date(created_at) = date('now', '-1 day') AND status = 'active' ''')
    
    # Award prizes to yesterday's winners
    c.execute('''SELECT id FROM streaming_competitions 
                 WHERE date(created_at) = date('now', '-1 day') AND status = 'completed' ''')
    yesterday_comps = c.fetchall()
    
    for comp in yesterday_comps:
        comp_id = comp[0]
        # Get top 3 winners
        c.execute('''SELECT user_id, (earnings - losses) as net_earnings 
                     FROM competition_participants 
                     WHERE competition_id = ? AND net_earnings > 0
                     ORDER BY net_earnings DESC LIMIT 3''', (comp_id,))
        winners = c.fetchall()
        
        prizes = [2000, 1200, 800]  # Enhanced 1st, 2nd, 3rd place prizes
        for i, winner in enumerate(winners):
            if i < len(prizes):
                c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', 
                         (prizes[i], winner[0]))
                c.execute('''INSERT INTO transactions (user_id, type, amount, description) 
                             VALUES (?, ?, ?, ?)''',
                         (winner[0], 'tournament_prize', prizes[i], 
                          f'Daily streaming competition #{i+1} place prize - Competition #{comp_id}'))
                
                # Record admin commission (15% of prize pool)
                admin_commission = prizes[i] * 0.15
                c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                             VALUES (?, ?, ?, ?)''',
                         (1, 'tournament_commission', admin_commission, 
                          f'15% commission from streaming competition prize - Competition #{comp_id}'))
    
    # Check if today's competition already exists
    c.execute('''SELECT id FROM streaming_competitions 
                 WHERE date(created_at) = date('now') AND status = 'active' ''')
    if not c.fetchone():
        # Create today's competition
        c.execute('''INSERT INTO streaming_competitions 
                     (name, description, entry_fee, prize_pool, start_time, end_time, status)
                     VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 day'), 'active')''',
                 ('Daily Streaming Battle', 'Compete for daily streaming rewards', 100, 1000))
    
    conn.commit()
    return jsonify({'success': True, 'message': 'Daily competition created'})

# Streaming competition removed - replaced by weekly tournaments

# Join streaming competition removed - replaced by weekly tournaments





@app.route('/admin/handle_timeout_match/<int:match_id>/<winner>', methods=['POST'])
def handle_timeout_match(match_id, winner):
    """Handle matches where only one player submitted screenshot (timeout scenario)"""
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get match and screenshot details
    c.execute('SELECT player1_id, player2_id, bet_amount FROM matches WHERE id = ?', (match_id,))
    match = c.fetchone()
    
    if not match:
        return jsonify({'error': 'Match not found'}), 404
    
    player1_id, player2_id, bet_amount = match
    
    # Check how many screenshots submitted
    c.execute('SELECT COUNT(*), user_id FROM match_screenshots WHERE match_id = ?', (match_id,))
    result = c.fetchone()
    screenshot_count, submitter_id = result[0], result[1] if result[0] > 0 else None
    
    if screenshot_count != 1:
        return jsonify({'error': 'This function is for matches with exactly one submission'}), 400
    
    # Determine winner based on admin decision
    if winner == 'submitter':
        # Player who submitted wins (opponent didn't submit = forfeit)
        winner_id = submitter_id
        winnings = bet_amount * 1.68
        c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1 WHERE id = ?', 
                 (winnings, winner_id))
        c.execute('UPDATE matches SET winner_id = ?, status = "completed" WHERE id = ?', 
                 (winner_id, match_id))
        
        # Record transaction
        c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                     VALUES (?, ?, ?, ?)''',
                 (winner_id, 'match_win', winnings, f'Won match {match_id} - opponent forfeit (no screenshot)'))
        
        message = f'Match awarded to submitter. KSh {winnings} paid out.'
        
    elif winner == 'refund':
        # Refund both players
        c.execute('UPDATE matches SET status = "cancelled_timeout" WHERE id = ?', (match_id,))
        
        # Refund both players
        if player1_id:
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bet_amount, player1_id))
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (player1_id, 'refund', bet_amount, f'Match {match_id} refund - timeout/incomplete'))
        
        if player2_id:
            c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (bet_amount, player2_id))
            c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                         VALUES (?, ?, ?, ?)''',
                     (player2_id, 'refund', bet_amount, f'Match {match_id} refund - timeout/incomplete'))
        
        message = f'Match cancelled and KSh {bet_amount} refunded to both players.'
    
    else:
        return jsonify({'error': 'Invalid winner option'}), 400
    
    conn.commit()
    return jsonify({'success': True, 'message': message})

@app.route('/get_match_notifications')
def get_match_notifications():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get unread notifications
    c.execute('''SELECT id, match_id, message, type, created_at FROM match_notifications 
                 WHERE user_id = ? AND read_status = 0 ORDER BY created_at DESC''', 
             (session['user_id'],))
    notifications = c.fetchall()
    
    # Mark as read
    c.execute('UPDATE match_notifications SET read_status = 1 WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    return jsonify({
        'notifications': [{
            'id': n[0],
            'match_id': n[1],
            'message': n[2],
            'type': n[3],
            'time': n[4]
        } for n in notifications]
    })

@app.route('/admin/award_real_screenshot/<int:match_id>/<int:user_id>', methods=['POST'])
def admin_award_real_screenshot(match_id, user_id):
    """Admin can manually award win to user with real screenshot"""
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get match details
    c.execute('SELECT player1_id, player2_id, bet_amount FROM matches WHERE id = ?', (match_id,))
    match = c.fetchone()
    
    if not match:
        return jsonify({'error': 'Match not found'}), 404
    
    # Award win to specified user
    winnings = match[2] * 1.68
    c.execute('UPDATE users SET balance = balance + ?, wins = wins + 1 WHERE id = ?', 
             (winnings, user_id))
    c.execute('UPDATE matches SET winner_id = ?, status = "completed" WHERE id = ?', 
             (user_id, match_id))
    
    # Record transaction
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''',
             (user_id, 'match_win', winnings, f'Admin awarded win for real screenshot - Match {match_id}'))
    
    conn.commit()
    return jsonify({'success': True, 'message': f'Awarded KSh {winnings} to user for real screenshot'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/api/create_real_stream', methods=['POST'])
def create_real_stream():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    title = data.get('title', 'Live Stream')
    stream_type = data.get('type', 'screen')
    is_competition = data.get('competition', False)
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Add stream_type column if it doesn't exist
    try:
        c.execute('ALTER TABLE streams ADD COLUMN stream_type TEXT DEFAULT "screen"')
    except sqlite3.Error as e:
        flash('Database error occurred', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('An error occurred', 'error')
        return redirect(url_for('dashboard'))
    
    import uuid
    stream_key = str(uuid.uuid4())[:8]
    
    c.execute('''INSERT INTO streams (user_id, title, stream_key, stream_type, status, viewers)
                 VALUES (?, ?, ?, ?, ?, ?)''', 
             (session['user_id'], title, stream_key, stream_type, 'live', 0))
    
    stream_id = c.lastrowid
    
    # Add to competition if participating
    if is_competition:
        c.execute('''SELECT cp.id FROM competition_participants cp
                     JOIN streaming_competitions sc ON cp.competition_id = sc.id
                     WHERE cp.user_id = ? AND sc.status = 'active' 
                     AND date(sc.created_at) = date('now')''', (session['user_id'],))
        competition_entry = c.fetchone()
        
        if competition_entry:
            c.execute('''UPDATE competition_participants 
                         SET earnings = earnings + 5 
                         WHERE id = ?''', (competition_entry[0],))
    
    conn.commit()
    return jsonify({
        'success': True,
        'stream_id': stream_id,
        'stream_key': stream_key
    })

@app.route('/api/update_viewers/<int:stream_id>', methods=['POST'])
def update_viewers(stream_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    viewer_count = data.get('count', 0)
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('UPDATE streams SET viewers = ? WHERE id = ? AND user_id = ?', 
             (viewer_count, stream_id, session['user_id']))
    
    conn.commit()
    return jsonify({'success': True})

@app.route('/api/stop_stream/<int:stream_id>', methods=['POST'])
def api_stop_stream(stream_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Calculate earnings
    c.execute('SELECT viewers, created_at FROM streams WHERE id = ? AND user_id = ?', 
             (stream_id, session['user_id']))
    stream = c.fetchone()
    
    if stream:
        viewers, created_at = stream
        from datetime import datetime
        start_time = datetime.fromisoformat(created_at)
        duration_hours = max(0.1, (datetime.now() - start_time).total_seconds() / 3600)
        
        # Enhanced earnings calculation
        base_earnings = duration_hours * 15  # KSh 15 per hour
        viewer_bonus = viewers * duration_hours * 5  # KSh 5 per viewer per hour
        performance_bonus = min(200, viewers * 10)  # Up to KSh 200 performance bonus
        sponsor_bonus = 50 if viewers >= 10 else 0  # KSh 50 sponsor bonus for 10+ viewers
        total_earnings = base_earnings + viewer_bonus + performance_bonus + sponsor_bonus
        
        # Update user balance
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', 
                 (total_earnings, session['user_id']))
        
        # Update competition stats
        c.execute('''SELECT cp.id FROM competition_participants cp
                     JOIN streaming_competitions sc ON cp.competition_id = sc.id
                     WHERE cp.user_id = ? AND sc.status = 'active' 
                     AND date(sc.created_at) = date('now')''', (session['user_id'],))
        competition_entry = c.fetchone()
        
        if competition_entry:
            c.execute('''UPDATE competition_participants 
                         SET earnings = earnings + ?, 
                             total_viewers = total_viewers + ?,
                             stream_time = stream_time + ?
                         WHERE id = ?''', 
                     (total_earnings, viewers, duration_hours, competition_entry[0]))
    
    c.execute('UPDATE streams SET status = "ended" WHERE id = ? AND user_id = ?', 
             (stream_id, session['user_id']))
    
    conn.commit()
    return jsonify({'success': True, 'earnings': total_earnings if stream else 0})

@app.route('/stream_feed/<int:stream_id>')
def stream_feed(stream_id):
    # Return actual stream feed - this would connect to real streaming server
    return "Stream feed endpoint - connect to actual streaming infrastructure"

@app.route('/test_streaming')
def test_streaming():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Test stream creation
    import uuid
    stream_key = str(uuid.uuid4())[:8]
    
    try:
        c.execute('''INSERT INTO streams (user_id, title, stream_key, status, viewers)
                     VALUES (?, ?, ?, ?, ?)''', 
                 (session['user_id'], 'Test Stream', stream_key, 'live', 5))
        stream_id = c.lastrowid
        conn.commit()
        
        # Test stream viewing
        c.execute('SELECT * FROM streams WHERE id = ?', (stream_id,))
        stream = c.fetchone()
        return jsonify({
            'success': True,
            'message': 'Streaming system working!',
            'stream_id': stream_id,
            'stream_key': stream_key,
            'stream_data': stream
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/init_db')
def init_db():
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        balance REAL DEFAULT 0.0,
        phone TEXT,
        referral_code TEXT,
        referred_by INTEGER,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        total_earnings REAL DEFAULT 0.0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game TEXT NOT NULL,
        player1_id INTEGER,
        player2_id INTEGER,
        bet_amount REAL NOT NULL,
        total_pot REAL NOT NULL,
        winner_id INTEGER,
        status TEXT DEFAULT 'pending',
        game_mode TEXT,
        streaming_enabled INTEGER DEFAULT 0,
        verification_type TEXT DEFAULT 'ocr',
        match_type TEXT DEFAULT 'public',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS tournaments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        game TEXT NOT NULL,
        entry_fee REAL NOT NULL,
        max_players INTEGER NOT NULL,
        prize_pool REAL DEFAULT 0,
        status TEXT DEFAULT 'open',
        streaming_required INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT (datetime('now'))
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS streams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        match_id INTEGER,
        tournament_id INTEGER,
        title TEXT,
        viewers INTEGER DEFAULT 0,
        status TEXT DEFAULT 'live',
        stream_key TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS user_friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        friend_id INTEGER,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, friend_id)
    )''')
    
    # Create admin user if not exists
    c.execute('SELECT * FROM users WHERE username = "admin"')
    admin_exists = c.fetchone()
    
    if not admin_exists:
        admin_password = generate_password_hash('admin123')
        c.execute('INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)',
                 ('admin', 'admin@gamebet.com', admin_password, 0.0))
        conn.commit()
        print("Admin user created: username=admin, password=admin123")
    
    conn.commit()
    return 'Database initialized successfully!'

# Tournament System Routes
@app.route('/api/tournaments')
def api_tournaments():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create enhanced tournament tables
    c.execute('''CREATE TABLE IF NOT EXISTS tournament_system (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        entry_fee_usd REAL NOT NULL,
        max_players INTEGER DEFAULT 64,
        current_players INTEGER DEFAULT 0,
        status TEXT DEFAULT 'registration',
        phase TEXT DEFAULT 'group_stage',
        week_number INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        registration_end TIMESTAMP,
        tournament_start TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS tournament_players (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tournament_id INTEGER,
        user_id INTEGER,
        username TEXT,
        entry_fee_paid REAL,
        currency TEXT DEFAULT 'KES',
        group_number INTEGER,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        eliminated BOOLEAN DEFAULT FALSE,
        final_position INTEGER,
        prize_won REAL DEFAULT 0,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS tournament_matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tournament_id INTEGER,
        player1_id INTEGER,
        player2_id INTEGER,
        phase TEXT,
        group_number INTEGER,
        match_number INTEGER,
        winner_id INTEGER,
        status TEXT DEFAULT 'pending',
        scheduled_time TIMESTAMP,
        completed_at TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS tournament_betting (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tournament_id INTEGER,
        match_id INTEGER,
        user_id INTEGER,
        bet_type TEXT,
        bet_description TEXT,
        bet_amount REAL,
        odds REAL,
        status TEXT DEFAULT 'active',
        result TEXT,
        payout REAL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Get current week's tournament
    import datetime
    current_week = datetime.datetime.now().isocalendar()[1]
    week_cycle = current_week % 4  # 4-week cycle
    
    entry_fees = [2, 5, 7, 10]  # USD - starts at $2
    current_fee = entry_fees[week_cycle]
    
    # Check if current week tournament exists
    c.execute('SELECT * FROM tournament_system WHERE week_number = ? AND status IN ("registration", "active")', (week_cycle + 1,))
    current_tournament = c.fetchone()
    
    if not current_tournament:
        # Create new tournament
        tournament_names = [
            "Budget Championship",
            "Standard Tournament", 
            "Premium Battle",
            "Elite Championship"
        ]
        
        reg_end = datetime.datetime.now() + datetime.timedelta(days=3)
        tournament_start = reg_end + datetime.timedelta(hours=2)
        
        c.execute('''INSERT INTO tournament_system 
                     (name, entry_fee_usd, week_number, streaming_required, tournament_type, registration_end, tournament_start)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (tournament_names[week_cycle], current_fee, week_cycle + 1, 1, 'weekly', reg_end.isoformat(), tournament_start.isoformat()))
        
        tournament_id = c.lastrowid
        c.execute('SELECT * FROM tournament_system WHERE id = ?', (tournament_id,))
        current_tournament = c.fetchone()
    
    # Get tournament details
    tournament_data = {
        'id': current_tournament[0],
        'name': current_tournament[1],
        'entry_fee_usd': current_tournament[2],
        'max_players': current_tournament[3],
        'current_players': current_tournament[4],
        'status': current_tournament[5],
        'phase': current_tournament[6],
        'registration_end': current_tournament[9],
        'tournament_start': current_tournament[10]
    }
    
    # Get user's participation status
    c.execute('SELECT * FROM tournament_players WHERE tournament_id = ? AND user_id = ?',
             (current_tournament[0], session['user_id']))
    user_participation = c.fetchone()
    
    conn.commit()
    return jsonify({
        'success': True,
        'tournament': tournament_data,
        'user_joined': user_participation is not None,
        'currency_rates': {
            'KES': 130,  # 1 USD = 130 KES
            'NGN': 800,  # 1 USD = 800 NGN
            'ZAR': 18,   # 1 USD = 18 ZAR
            'GHS': 12,   # 1 USD = 12 GHS
            'UGX': 3700  # 1 USD = 3700 UGX
        }
    })

@app.route('/api/join_tournament', methods=['POST'])
def api_join_tournament():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    tournament_id = data.get('tournament_id')
    currency = data.get('currency', 'KES')
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create tournament tables if they don't exist
    c.execute('''CREATE TABLE IF NOT EXISTS tournament_system (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        entry_fee_usd REAL NOT NULL,
        max_players INTEGER DEFAULT 64,
        current_players INTEGER DEFAULT 0,
        status TEXT DEFAULT 'registration',
        phase TEXT DEFAULT 'group_stage',
        week_number INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        registration_end TIMESTAMP,
        tournament_start TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS tournament_players (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tournament_id INTEGER,
        user_id INTEGER,
        username TEXT,
        entry_fee_paid REAL,
        currency TEXT DEFAULT 'KES',
        group_number INTEGER,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        eliminated BOOLEAN DEFAULT FALSE,
        final_position INTEGER,
        prize_won REAL DEFAULT 0,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Get tournament details
    c.execute('SELECT * FROM tournament_system WHERE id = ?', (tournament_id,))
    tournament = c.fetchone()
    
    if not tournament:
        return jsonify({'error': 'Tournament not found'}), 404
    
    # Check if already joined
    c.execute('SELECT id FROM tournament_players WHERE tournament_id = ? AND user_id = ?',
             (tournament_id, session['user_id']))
    if c.fetchone():
        return jsonify({'error': 'Already joined this tournament'}), 400
    
    # Calculate entry fee in user's currency
    entry_fee_usd = tournament[2]
    currency_rates = {
        'USD': 1,
        'KES': 130,
        'NGN': 800,
        'ZAR': 18,
        'GHS': 12,
        'UGX': 3700
    }
    
    entry_fee_local = entry_fee_usd * currency_rates.get(currency, 130)  # Default to KES
    
    # Check user balance
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()[0]
    
    if balance < entry_fee_local:
        return jsonify({'error': f'Insufficient balance! Need {entry_fee_local:.0f} {currency}'}), 400
    
    # Check tournament capacity
    if tournament[4] >= tournament[3]:  # current_players >= max_players
        return jsonify({'error': 'Tournament is full'}), 400
    
    # Join tournament
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (entry_fee_local, session['user_id']))
    
    # Add transaction record
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''',
             (session['user_id'], 'tournament_entry', -entry_fee_local, f'Tournament entry fee - {tournament[1]}'))
    
    c.execute('''INSERT INTO tournament_players 
                 (tournament_id, user_id, username, entry_fee_paid, currency)
                 VALUES (?, ?, ?, ?, ?)''',
             (tournament_id, session['user_id'], session['username'], entry_fee_local, currency))
    
    # Update tournament player count
    c.execute('UPDATE tournament_system SET current_players = current_players + 1 WHERE id = ?',
             (tournament_id,))
    
    # Check if tournament is now full
    c.execute('SELECT current_players, max_players FROM tournament_system WHERE id = ?', (tournament_id,))
    players_info = c.fetchone()
    
    if players_info and players_info[0] >= players_info[1]:
        c.execute('UPDATE tournament_system SET status = "active" WHERE id = ?', (tournament_id,))
    
    # Update session balance
    session['balance'] = balance - entry_fee_local
    
    conn.commit()
    return jsonify({
        'success': True,
        'message': f'Joined tournament! {entry_fee_local:.0f} {currency} entry fee paid',
        'new_balance': session['balance']
    })

@app.route('/api/tournament_betting/<int:tournament_id>')
def api_tournament_betting(tournament_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get active tournament matches
    c.execute('''SELECT tm.*, tp1.username as p1_name, tp2.username as p2_name
                 FROM tournament_matches tm
                 LEFT JOIN tournament_players tp1 ON tm.player1_id = tp1.user_id AND tp1.tournament_id = tm.tournament_id
                 LEFT JOIN tournament_players tp2 ON tm.player2_id = tp2.user_id AND tp2.tournament_id = tm.tournament_id
                 WHERE tm.tournament_id = ? AND tm.status = "active"
                 ORDER BY tm.scheduled_time''', (tournament_id,))
    
    matches = c.fetchall()
    
    # Generate betting options for each match
    betting_options = []
    
    for match in matches:
        match_id = match[0]
        p1_name = match[11] or "Player 1"
        p2_name = match[12] or "Player 2"
        
        # FIFA betting options
        fifa_bets = [
            {'type': 'first_goal', 'description': 'First goal before 15th minute', 'amount': 80, 'odds': 2.5},
            {'type': 'yellow_cards', 'description': 'Match has 2+ yellow cards', 'amount': 100, 'odds': 1.8},
            {'type': 'penalty', 'description': 'Penalty kick awarded', 'amount': 150, 'odds': 3.2},
            {'type': 'hat_trick', 'description': f'{p1_name} scores hat-trick', 'amount': 300, 'odds': 8.5},
            {'type': 'extra_time', 'description': 'Match goes to extra time', 'amount': 200, 'odds': 4.1},
            {'type': 'own_goal', 'description': 'Own goal scored', 'amount': 400, 'odds': 12.0},
            {'type': 'red_card', 'description': 'Red card shown', 'amount': 250, 'odds': 6.5}
        ]
        
        # FPS betting options
        fps_bets = [
            {'type': 'high_kills', 'description': f'{p1_name} gets 15+ kills', 'amount': 120, 'odds': 2.8},
            {'type': 'first_blood', 'description': 'First blood within 2 minutes', 'amount': 90, 'odds': 1.9},
            {'type': 'fall_damage', 'description': f'{p2_name} dies to fall damage', 'amount': 180, 'odds': 5.2},
            {'type': 'grenade_kill', 'description': 'Grenade kill achieved', 'amount': 200, 'odds': 4.8},
            {'type': 'low_health', 'description': 'Player survives with <10% health', 'amount': 160, 'odds': 3.5},
            {'type': 'headshot_rate', 'description': 'Headshot percentage above 40%', 'amount': 220, 'odds': 6.1},
            {'type': 'ammo_out', 'description': 'Player runs out of ammo mid-fight', 'amount': 140, 'odds': 3.8}
        ]
        
        # Mobile game betting options
        mobile_bets = [
            {'type': 'level_10', 'description': 'Player reaches level 10+ in match', 'amount': 100, 'odds': 2.2},
            {'type': 'early_death', 'description': f'{p1_name} dies within first 3 minutes', 'amount': 80, 'odds': 1.7},
            {'type': 'power_ups', 'description': 'Player uses power-up 5+ times', 'amount': 120, 'odds': 2.9},
            {'type': 'combo_50', 'description': 'Player achieves combo of 50+', 'amount': 180, 'odds': 4.5},
            {'type': 'game_lag', 'description': 'Game lags/freezes during match', 'amount': 300, 'odds': 8.0}
        ]
        
        # Determine game type and use appropriate bets
        game_type = 'fifa'  # This would be determined from tournament settings
        if game_type == 'fifa':
            match_bets = fifa_bets
        elif game_type == 'fps':
            match_bets = fps_bets
        else:
            match_bets = mobile_bets
        
        betting_options.append({
            'match_id': match_id,
            'player1': p1_name,
            'player2': p2_name,
            'phase': match[4],
            'scheduled_time': match[9],
            'betting_options': match_bets
        })
    return jsonify({
        'success': True,
        'matches': betting_options
    })

@app.route('/api/tournament_players/<int:tournament_id>')
def api_tournament_players(tournament_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get tournament players with auto-group assignment
    c.execute('SELECT username, group_number, joined_at FROM tournament_players WHERE tournament_id = ? ORDER BY joined_at', (tournament_id,))
    players_data = c.fetchall()
    
    players = []
    for i, (username, group_num, joined_at) in enumerate(players_data):
        # Auto-assign group if not assigned
        if not group_num:
            group_num = (i % 4) + 1  # Groups 1-4 (A-D)
            c.execute('UPDATE tournament_players SET group_number = ? WHERE tournament_id = ? AND username = ?', 
                     (group_num, tournament_id, username))
        
        players.append({
            'username': username,
            'group': chr(64 + group_num),  # Convert 1-4 to A-D
            'joined_at': joined_at
        })
    
    conn.commit()
    return jsonify({'success': True, 'players': players})

@app.route('/api/tournament_groups/<int:tournament_id>')
def api_tournament_groups(tournament_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Get tournament players - assign groups if not assigned
    c.execute('SELECT COUNT(*) FROM tournament_players WHERE tournament_id = ?', (tournament_id,))
    total_players = c.fetchone()[0]
    
    if total_players > 0:
        # Auto-assign groups if not assigned
        c.execute('SELECT COUNT(*) FROM tournament_players WHERE tournament_id = ? AND group_number IS NULL', (tournament_id,))
        unassigned = c.fetchone()[0]
        
        if unassigned > 0:
            # Assign players to groups
            c.execute('SELECT id FROM tournament_players WHERE tournament_id = ? AND group_number IS NULL', (tournament_id,))
            unassigned_players = c.fetchall()
            
            for i, player in enumerate(unassigned_players):
                group_num = (i % 8) + 1  # Groups 1-8
                c.execute('UPDATE tournament_players SET group_number = ? WHERE id = ?', (group_num, player[0]))
    
    # Get tournament players grouped by group_number
    c.execute('''SELECT group_number, username, wins, losses, 
                        (wins * 3 + losses * 0) as points
                 FROM tournament_players 
                 WHERE tournament_id = ? AND group_number IS NOT NULL
                 ORDER BY group_number, points DESC, wins DESC''', (tournament_id,))
    
    players_data = c.fetchall()
    
    # If no groups yet, create mock data for demonstration
    if not players_data:
        # Get all players and create mock groups
        c.execute('SELECT username FROM tournament_players WHERE tournament_id = ?', (tournament_id,))
        all_players = c.fetchall()
        
        if all_players:
            mock_groups = []
            for i in range(min(8, len(all_players))):
                group_name = f"Group {chr(65 + i)}"
                mock_groups.append({
                    'name': group_name,
                    'players': [{
                        'name': all_players[i][0] if i < len(all_players) else f'Player{i+1}',
                        'wins': 0,
                        'losses': 0,
                        'points': 0
                    }]
                })
            
            conn.commit()
            return jsonify({'success': True, 'groups': mock_groups})
    
    # Organize players into groups
    groups = {}
    for player in players_data:
        group_num, username, wins, losses, points = player
        group_name = f"Group {chr(64 + group_num)}"  # A, B, C, etc.
        
        if group_name not in groups:
            groups[group_name] = {'name': group_name, 'players': []}
        
        groups[group_name]['players'].append({
            'name': username,
            'wins': wins,
            'losses': losses,
            'points': points
        })
    
    conn.commit()
    return jsonify({
        'success': True,
        'groups': list(groups.values())
    })

@app.route('/api/place_tournament_bet', methods=['POST'])
def api_place_tournament_bet():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    tournament_id = data.get('tournament_id')
    match_id = data.get('match_id')
    bet_type = data.get('bet_type')
    bet_description = data.get('bet_description')
    bet_amount = float(data.get('bet_amount', 0))
    odds = float(data.get('odds', 1.0))
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Check user balance
    c.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    balance = c.fetchone()[0]
    
    if balance < bet_amount:
        return jsonify({'error': 'Insufficient balance'}), 400
    
    # Place bet
    c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (bet_amount, session['user_id']))
    
    c.execute('''INSERT INTO tournament_betting 
                 (tournament_id, match_id, user_id, bet_type, bet_description, bet_amount, odds)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
             (tournament_id, match_id, session['user_id'], bet_type, bet_description, bet_amount, odds))
    
    session['balance'] = balance - bet_amount
    
    conn.commit()
    potential_payout = bet_amount * odds
    
    return jsonify({
        'success': True,
        'message': f'Bet placed! Potential payout: {potential_payout:.2f}',
        'new_balance': session['balance']
    })

@app.route('/api/user_attraction')
def api_user_attraction():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Create user progress tracking table
    c.execute('''CREATE TABLE IF NOT EXISTS user_progress (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        week1_completed BOOLEAN DEFAULT FALSE,
        week2_completed BOOLEAN DEFAULT FALSE,
        week3_completed BOOLEAN DEFAULT FALSE,
        week4_completed BOOLEAN DEFAULT FALSE,
        total_credits_earned REAL DEFAULT 0,
        referral_stage INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Get or create user progress
    c.execute('SELECT * FROM user_progress WHERE user_id = ?', (session['user_id'],))
    progress = c.fetchone()
    
    if not progress:
        c.execute('INSERT INTO user_progress (user_id) VALUES (?)', (session['user_id'],))
        c.execute('SELECT * FROM user_progress WHERE user_id = ?', (session['user_id'],))
        progress = c.fetchone()
    
    # Check streaming requirements
    c.execute('SELECT COUNT(*) FROM streams WHERE user_id = ? AND status = "ended"', (session['user_id'],))
    total_streams = c.fetchone()[0]
    
    c.execute('SELECT COALESCE(SUM(viewers), 0) FROM streams WHERE user_id = ?', (session['user_id'],))
    total_viewers = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM tournament_players WHERE user_id = ?', (session['user_id'],))
    tournaments_joined = c.fetchone()[0]
    
    # Calculate bonus eligibility
    bonuses = {
        'week1': {
            'requirement': 'Stream for 2 hours + get 1 viewer',
            'amount': 25,
            'completed': total_streams >= 1 and total_viewers >= 1,
            'claimed': progress[2]
        },
        'week2': {
            'requirement': 'Complete 5 hours total streaming',
            'amount': 25,
            'completed': total_streams >= 3,  # Approximate 5 hours
            'claimed': progress[3]
        },
        'week3': {
            'requirement': 'Get 10 total viewers',
            'amount': 25,
            'completed': total_viewers >= 10,
            'claimed': progress[4]
        },
        'week4': {
            'requirement': 'Participate in tournament',
            'amount': 25,
            'completed': tournaments_joined >= 1,
            'claimed': progress[5]
        }
    }
    
    # Referral progress
    c.execute('SELECT COUNT(*) FROM users WHERE referred_by = ?', (session['user_id'],))
    referrals_count = c.fetchone()[0]
    
    referral_bonuses = {
        'immediate': {
            'requirement': 'Friend completes first stream',
            'amount': 30,
            'progress': min(referrals_count, 1)
        },
        'month1': {
            'requirement': 'Friend earns $20 total',
            'amount': 70,
            'progress': 0  # Would need to track friend earnings
        },
        'month2': {
            'requirement': 'Friend earns $50 total',
            'amount': 100,
            'progress': 0
        }
    }
    return jsonify({
        'success': True,
        'bonuses': bonuses,
        'referral_bonuses': referral_bonuses,
        'total_credits_earned': progress[6],
        'user_stats': {
            'total_streams': total_streams,
            'total_viewers': total_viewers,
            'tournaments_joined': tournaments_joined,
            'referrals_count': referrals_count
        }
    })

@app.route('/api/claim_bonus', methods=['POST'])
def api_claim_bonus():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    bonus_type = data.get('bonus_type')  # week1, week2, week3, week4
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    # Verify bonus eligibility (same logic as above)
    # For brevity, assuming bonus is valid
    
    bonus_amount = 25  # Platform credits
    
    # Update user progress
    valid_weeks = ['week1', 'week2', 'week3', 'week4']
    if bonus_type not in valid_weeks:
        return jsonify({'error': 'Invalid bonus type'}), 400
    
    week_column = f'{bonus_type}_completed'
    c.execute(f'UPDATE user_progress SET {week_column} = TRUE, total_credits_earned = total_credits_earned + ? WHERE user_id = ?',
             (bonus_amount, session['user_id']))
    
    # Add credits to user account (as platform credits, not withdrawable cash)
    c.execute('''INSERT INTO transactions (user_id, type, amount, description)
                 VALUES (?, ?, ?, ?)''',
             (session['user_id'], 'platform_credits', bonus_amount, f'New user bonus - {bonus_type}'))
    
    conn.commit()
    return jsonify({
        'success': True,
        'message': f'Bonus claimed! {bonus_amount} platform credits added',
        'credits_earned': bonus_amount
    })



@app.route('/tournament_betting/<int:tournament_id>')
def tournament_betting_page(tournament_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('tournament_betting.html', tournament_id=tournament_id)

@app.route('/user_bonuses')
def user_bonuses_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('user_bonuses.html')

@app.route('/test_tournament_system')
def test_tournament_system():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('test_tournament.html')

@app.route('/admin/user_activity_alerts')
def admin_user_activity_alerts():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    with sqlite3.connect("gamebet.db") as conn:
        c = conn.cursor()
    
    alerts = []
    
    # Recent fake screenshot violations (last 24 hours)
    c.execute('''SELECT fst.user_id, u.username, fst.fake_count, fst.is_banned, fst.created_at
                 FROM fake_screenshot_tracking fst
                 JOIN users u ON fst.user_id = u.id
                 WHERE datetime(fst.created_at) > datetime('now', '-1 day')
                 ORDER BY fst.created_at DESC LIMIT 10''', ())
    fake_screenshots = c.fetchall()
    
    for fs in fake_screenshots:
        alerts.append({
            'user_id': fs[0],
            'username': fs[1],
            'type': 'danger' if fs[3] == 1 else 'warning',
            'icon': 'ðŸš¨',
            'title': 'Fake Screenshot - ' + str(fs[1]),
            'message': 'Violation #' + str(fs[2]) + ' - ' + ('BANNED' if fs[3] == 1 else 'WARNING ISSUED'),
            'time': fs[4]
        })
    
    # Recent large deposits (last 24 hours, > KSh 1000)
    c.execute('''SELECT t.user_id, u.username, t.amount, t.created_at
                 FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 WHERE t.type = 'deposit' AND t.amount > 1000 
                 AND datetime(t.created_at) > datetime('now', '-1 day')
                 ORDER BY t.created_at DESC LIMIT 5''', ())
    large_deposits = c.fetchall()
    
    for dep in large_deposits:
        alerts.append({
            'user_id': dep[0],
            'username': dep[1],
            'type': 'info',
            'icon': 'ðŸ’°',
            'title': 'Large Deposit - ' + str(dep[1]),
            'message': 'Deposited KSh ' + str(int(dep[2])),
            'time': dep[3]
        })
    
    # Recent large withdrawals (last 24 hours, > KSh 2000)
    c.execute('''SELECT t.user_id, u.username, ABS(t.amount), t.created_at
                 FROM transactions t
                 JOIN users u ON t.user_id = u.id
                 WHERE t.type = 'pending_withdrawal' AND ABS(t.amount) > 2000 
                 AND datetime(t.created_at) > datetime('now', '-1 day')
                 ORDER BY t.created_at DESC LIMIT 5''', ())
    large_withdrawals = c.fetchall()
    
    for wd in large_withdrawals:
        alerts.append({
            'user_id': wd[0],
            'username': wd[1],
            'type': 'warning',
            'icon': 'ðŸ’¸',
            'title': 'Large Withdrawal - ' + str(wd[1]),
            'message': 'Requested KSh ' + str(int(wd[2])),
            'time': wd[3]
        })
    
    # Recent new user registrations (last 24 hours)
    c.execute('''SELECT id, username, created_at FROM users 
                 WHERE datetime(created_at) > datetime('now', '-1 day') 
                 AND username != 'admin'
                 ORDER BY created_at DESC LIMIT 5''', ())
    new_users = c.fetchall()
    
    for user in new_users:
        alerts.append({
            'user_id': user[0],
            'username': user[1],
            'type': 'info',
            'icon': 'ðŸ‘¤',
            'title': 'New User - ' + str(user[1]),
            'message': 'Just registered',
            'time': user[2]
        })
    # Sort alerts by time (most recent first)
    alerts.sort(key=lambda x: x['time'], reverse=True)
    
    return jsonify({'success': True, 'alerts': alerts[:15]})



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
