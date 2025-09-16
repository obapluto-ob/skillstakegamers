// Security fixes for JavaScript code

// Fix memory leaks from event listeners
class EventManager {
    constructor() {
        this.listeners = new Map();
    }
    
    addListener(element, event, handler) {
        const key = `${element.id || 'anonymous'}_${event}`;
        
        // Remove existing listener if any
        if (this.listeners.has(key)) {
            const oldHandler = this.listeners.get(key);
            element.removeEventListener(event, oldHandler);
        }
        
        element.addEventListener(event, handler);
        this.listeners.set(key, handler);
    }
    
    cleanup() {
        // Remove all tracked event listeners before clearing
        this.listeners.forEach((handler, element) => {
            if (element && element.removeEventListener && handler) {
                element.removeEventListener('click', handler);
                element.removeEventListener('input', handler);
                element.removeEventListener('change', handler);
            }
        });
        this.listeners.clear();
    }
}

// Global event manager
const eventManager = new EventManager();

// Fix interval leaks
class IntervalManager {
    constructor() {
        this.intervals = new Set();
    }
    
    setInterval(callback, delay) {
        const id = setInterval(callback, delay);
        this.intervals.add(id);
        return id;
    }
    
    clearInterval(id) {
        clearInterval(id);
        this.intervals.delete(id);
    }
    
    clearAll() {
        this.intervals.forEach(id => clearInterval(id));
        this.intervals.clear();
    }
}

// Global interval manager
const intervalManager = new IntervalManager();

// Input sanitization
function sanitizeHTML(str) {
    if (typeof str !== 'string') return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function validateNumericInput(value, min = null, max = null) {
    // Prevent NaN injection by strict validation
    if (typeof value === 'string') {
        const lowerValue = value.toLowerCase();
        const dangerousValues = ['nan', 'infinity', 'inf', '-inf', '+inf'];
        if (dangerousValues.some(dangerous => lowerValue.includes(dangerous))) {
            return { valid: false, error: 'Invalid input detected' };
        }
    }
    
    const num = parseFloat(value);
    
    if (isNaN(num) || !isFinite(num)) {
        return { valid: false, error: 'Invalid number' };
    }
    
    if (min !== null && num < min) {
        return { valid: false, error: `Must be at least ${min}` };
    }
    
    if (max !== null && num > max) {
        return { valid: false, error: `Must be at most ${max}` };
    }
    
    return { valid: true, value: num };
}

// Safe JSON parsing without eval
function safeJSONParse(jsonString) {
    try {
        return JSON.parse(jsonString);
    } catch (e) {
        // Don't log sensitive information in production
        return null;
    }
}

// Secure URL validation
function validateURL(url) {
    try {
        const urlObj = new URL(url);
        // Only allow https and http protocols
        return ['https:', 'http:'].includes(urlObj.protocol);
    } catch {
        return false;
    }
}

// Enhanced path traversal protection
function sanitizePath(path) {
    if (typeof path !== 'string') return '';
    
    // Normalize path separators
    path = path.replace(/\\/g, '/');
    
    // Remove path traversal attempts more thoroughly
    path = path.replace(/\.\./g, '');
    path = path.replace(/\.\/|\.\\/g, '');
    
    // Remove dangerous characters
    path = path.replace(/[<>:"|?*\x00-\x1f]/g, '');
    
    // Ensure path doesn't start with /
    path = path.replace(/^\/+/, '');
    
    return path;
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    eventManager.cleanup();
    intervalManager.clearAll();
});

// Page visibility change cleanup
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        intervalManager.clearAll();
    }
});