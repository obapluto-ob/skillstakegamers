# Screen Capture Result Detection System

import cv2
import numpy as np
import pytesseract
import base64
from PIL import Image
import io

class GameResultDetector:
    """Detects game results from screenshots"""
    
    def __init__(self):
        # Win/Loss text patterns for different games
        self.win_patterns = [
            "VICTORY", "WINNER", "YOU WIN", "CHAMPION", 
            "FIRST PLACE", "#1", "VICTORY ROYALE", "WIN"
        ]
        
        self.loss_patterns = [
            "DEFEAT", "GAME OVER", "YOU LOSE", "ELIMINATED",
            "BETTER LUCK", "TRY AGAIN", "DEFEATED"
        ]
        
        # Game-specific result screens (color patterns)
        self.game_signatures = {
            'pubg_mobile': {
                'win_colors': [(255, 215, 0), (255, 255, 255)],  # Gold/White
                'loss_colors': [(128, 128, 128), (255, 0, 0)]     # Gray/Red
            },
            'fifa': {
                'win_colors': [(0, 255, 0), (255, 255, 255)],     # Green/White
                'loss_colors': [(255, 0, 0), (128, 128, 128)]     # Red/Gray
            }
        }
    
    def analyze_screenshot(self, image_data, game_type):
        """Analyze screenshot to detect win/loss"""
        try:
            # Convert base64 to image
            image = self._decode_image(image_data)
            
            # Method 1: OCR Text Detection
            text_result = self._detect_text_result(image)
            
            # Method 2: Color Pattern Analysis
            color_result = self._detect_color_pattern(image, game_type)
            
            # Method 3: Template Matching (if available)
            template_result = self._template_matching(image, game_type)
            
            # Combine results for confidence score
            confidence = self._calculate_confidence(text_result, color_result, template_result)
            
            return {
                'result': text_result or color_result or 'unknown',
                'confidence': confidence,
                'methods_used': {
                    'text_detection': text_result,
                    'color_analysis': color_result,
                    'template_match': template_result
                }
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'confidence': 0,
                'error': str(e)
            }
    
    def _decode_image(self, image_data):
        """Convert base64 image to OpenCV format"""
        if image_data.startswith('data:image'):
            image_data = image_data.split(',')[1]
        
        image_bytes = base64.b64decode(image_data)
        image = Image.open(io.BytesIO(image_bytes))
        return cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
    
    def _detect_text_result(self, image):
        """Use OCR to detect win/loss text"""
        try:
            # Convert to grayscale for better OCR
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Enhance contrast
            enhanced = cv2.convertScaleAbs(gray, alpha=2.0, beta=50)
            
            # Extract text
            text = pytesseract.image_to_string(enhanced).upper()
            
            # Check for win patterns
            for pattern in self.win_patterns:
                if pattern in text:
                    return 'win'
            
            # Check for loss patterns
            for pattern in self.loss_patterns:
                if pattern in text:
                    return 'loss'
            
            return None
            
        except:
            return None
    
    def _detect_color_pattern(self, image, game_type):
        """Analyze dominant colors to detect result screen"""
        try:
            if game_type not in self.game_signatures:
                return None
            
            # Get dominant colors
            dominant_colors = self._get_dominant_colors(image)
            
            signatures = self.game_signatures[game_type]
            
            # Check for win color patterns
            win_match = self._match_color_signature(dominant_colors, signatures['win_colors'])
            if win_match > 0.7:  # 70% confidence threshold
                return 'win'
            
            # Check for loss color patterns
            loss_match = self._match_color_signature(dominant_colors, signatures['loss_colors'])
            if loss_match > 0.7:
                return 'loss'
            
            return None
            
        except:
            return None
    
    def _get_dominant_colors(self, image, k=5):
        """Extract dominant colors from image"""
        # Reshape image to be a list of pixels
        pixels = image.reshape((-1, 3))
        pixels = np.float32(pixels)
        
        # Apply k-means clustering
        criteria = (cv2.TERM_CRITERIA_EPS + cv2.TERM_CRITERIA_MAX_ITER, 20, 1.0)
        _, labels, centers = cv2.kmeans(pixels, k, None, criteria, 10, cv2.KMEANS_RANDOM_CENTERS)
        
        return centers.astype(int)
    
    def _match_color_signature(self, dominant_colors, signature_colors):
        """Calculate how well colors match signature"""
        matches = 0
        total_checks = len(signature_colors)
        
        for sig_color in signature_colors:
            for dom_color in dominant_colors:
                # Calculate color distance
                distance = np.linalg.norm(np.array(sig_color) - np.array(dom_color))
                if distance < 50:  # Threshold for color similarity
                    matches += 1
                    break
        
        return matches / total_checks if total_checks > 0 else 0
    
    def _template_matching(self, image, game_type):
        """Match against known result screen templates"""
        # This would require pre-stored templates for each game
        # For now, return None (not implemented)
        return None
    
    def _calculate_confidence(self, text_result, color_result, template_result):
        """Calculate overall confidence score"""
        confidence = 0
        methods = 0
        
        if text_result:
            confidence += 0.6  # Text detection is most reliable
            methods += 1
        
        if color_result:
            confidence += 0.3  # Color analysis is moderately reliable
            methods += 1
        
        if template_result:
            confidence += 0.4  # Template matching is quite reliable
            methods += 1
        
        return min(confidence, 1.0) if methods > 0 else 0

# Global detector instance
result_detector = GameResultDetector()