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
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function validateNumericInput(value, min = null, max = null) {
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