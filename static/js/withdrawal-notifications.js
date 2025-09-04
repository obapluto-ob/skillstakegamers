// Real-time withdrawal notifications system
class WithdrawalNotifications {
    constructor(withdrawalId) {
        this.withdrawalId = withdrawalId;
        this.checkInterval = null;
        this.lastStatus = null;
        this.init();
    }

    init() {
        // Check every 3 seconds for status updates
        this.checkInterval = setInterval(() => {
            this.checkWithdrawalStatus();
        }, 3000);

        // Check immediately
        this.checkWithdrawalStatus();
    }

    async checkWithdrawalStatus() {
        try {
            const response = await fetch(`/api/withdrawal_status/${this.withdrawalId}`);
            const data = await response.json();
            
            if (data.success && data.status !== this.lastStatus) {
                this.handleStatusChange(data);
                this.lastStatus = data.status;
            }
        } catch (error) {
            console.error('Error checking withdrawal status:', error);
        }
    }

    handleStatusChange(data) {
        const { status, message, payment_proof } = data;
        
        switch (status) {
            case 'withdrawal':
                this.showPaymentCompleted(message, payment_proof);
                break;
            case 'rejected_withdrawal':
                this.showRejectionNotice(message);
                break;
            case 'pending_withdrawal':
                this.showPendingStatus();
                break;
        }
    }

    showPaymentCompleted(message, paymentProof) {
        // Stop checking
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
        }

        // Show success notification
        this.showNotification('🎉 Payment Completed!', 'Your withdrawal has been processed successfully!', 'success');
        
        // Update page content
        this.updatePageForCompletion(paymentProof);
        
        // Play success sound
        this.playNotificationSound('success');
        
        // Browser notification
        this.showBrowserNotification('SkillStake - Payment Completed!', 'Your withdrawal has been processed. Check your M-Pesa.');
    }

    showRejectionNotice(message) {
        // Stop checking
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
        }

        // Show rejection notification
        this.showNotification('❌ Withdrawal Rejected', 'Your withdrawal was rejected and money has been refunded.', 'error');
        
        // Update page content
        this.updatePageForRejection();
        
        // Play error sound
        this.playNotificationSound('error');
        
        // Browser notification
        this.showBrowserNotification('SkillStake - Withdrawal Rejected', 'Your withdrawal was rejected. Money has been refunded to your account.');
    }

    showPendingStatus() {
        this.showNotification('⏳ Processing', 'Your withdrawal is being processed by admin...', 'info');
    }

    showNotification(title, message, type) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <h4>${title}</h4>
                <p>${message}</p>
            </div>
            <button class="notification-close" onclick="this.parentElement.remove()">×</button>
        `;
        
        // Add styles
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            max-width: 350px;
            animation: slideIn 0.3s ease;
            ${this.getNotificationColors(type)}
        `;
        
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    getNotificationColors(type) {
        const colors = {
            success: 'background: linear-gradient(135deg, #28a745, #20c997); color: white;',
            error: 'background: linear-gradient(135deg, #dc3545, #fd7e14); color: white;',
            info: 'background: linear-gradient(135deg, #17a2b8, #6f42c1); color: white;'
        };
        return colors[type] || colors.info;
    }

    updatePageForCompletion(paymentProof) {
        // Update withdrawal status display
        const statusElement = document.getElementById('withdrawalStatus');
        if (statusElement) {
            statusElement.innerHTML = `
                <div style="background: linear-gradient(135deg, #d4edda, #c3e6cb); padding: 1.5rem; border-radius: 12px; text-align: center;">
                    <h3 style="color: #155724; margin: 0 0 1rem 0;">🎉 Payment Completed!</h3>
                    <p style="color: #155724; margin: 0;">Your withdrawal has been processed successfully. Check your M-Pesa for confirmation.</p>
                    ${paymentProof ? `
                        <div style="margin-top: 1rem;">
                            <p style="font-size: 0.9rem; color: #155724;">Admin's Payment Screenshot:</p>
                            <img src="data:image/jpeg;base64,${paymentProof}" 
                                 style="max-width: 200px; max-height: 150px; border-radius: 8px; cursor: pointer;" 
                                 onclick="this.style.maxWidth='100%'; this.style.maxHeight='none';">
                        </div>
                    ` : ''}
                </div>
            `;
        }

        // Hide action buttons
        const actionButtons = document.getElementById('withdrawalActions');
        if (actionButtons) {
            actionButtons.style.display = 'none';
        }
    }

    updatePageForRejection() {
        // Update withdrawal status display
        const statusElement = document.getElementById('withdrawalStatus');
        if (statusElement) {
            statusElement.innerHTML = `
                <div style="background: linear-gradient(135deg, #f8d7da, #f5c6cb); padding: 1.5rem; border-radius: 12px; text-align: center;">
                    <h3 style="color: #721c24; margin: 0 0 1rem 0;">❌ Withdrawal Rejected</h3>
                    <p style="color: #721c24; margin: 0;">Your withdrawal was rejected by admin. The money has been refunded to your account.</p>
                    <div style="margin-top: 1rem;">
                        <a href="/wallet" class="btn btn-primary">Return to Wallet</a>
                    </div>
                </div>
            `;
        }

        // Hide action buttons
        const actionButtons = document.getElementById('withdrawalActions');
        if (actionButtons) {
            actionButtons.style.display = 'none';
        }
    }

    playNotificationSound(type) {
        // Create audio context for notification sounds
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            // Different frequencies for different notification types
            const frequencies = {
                success: [523, 659, 784], // C, E, G (major chord)
                error: [440, 370, 330],   // Descending tones
                info: [440, 554]          // Simple two-tone
            };
            
            const freq = frequencies[type] || frequencies.info;
            
            oscillator.frequency.setValueAtTime(freq[0], audioContext.currentTime);
            gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
            
            oscillator.start();
            oscillator.stop(audioContext.currentTime + 0.2);
            
        } catch (error) {
            console.log('Audio notification not supported');
        }
    }

    showBrowserNotification(title, body) {
        // Request permission if not granted
        if ('Notification' in window) {
            if (Notification.permission === 'granted') {
                new Notification(title, {
                    body: body,
                    icon: '/static/favicon.ico',
                    badge: '/static/favicon.ico'
                });
            } else if (Notification.permission !== 'denied') {
                Notification.requestPermission().then(permission => {
                    if (permission === 'granted') {
                        new Notification(title, {
                            body: body,
                            icon: '/static/favicon.ico',
                            badge: '/static/favicon.ico'
                        });
                    }
                });
            }
        }
    }

    destroy() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
        }
    }
}

// CSS for notifications
const notificationStyles = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    .notification {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    
    .notification-content h4 {
        margin: 0 0 0.5rem 0;
        font-size: 1.1rem;
        font-weight: 600;
    }
    
    .notification-content p {
        margin: 0;
        font-size: 0.9rem;
        opacity: 0.9;
    }
    
    .notification-close {
        position: absolute;
        top: 0.5rem;
        right: 0.5rem;
        background: none;
        border: none;
        color: inherit;
        font-size: 1.2rem;
        cursor: pointer;
        opacity: 0.7;
        width: 24px;
        height: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    
    .notification-close:hover {
        opacity: 1;
    }
`;

// Inject styles
const styleSheet = document.createElement('style');
styleSheet.textContent = notificationStyles;
document.head.appendChild(styleSheet);

// Export for use
window.WithdrawalNotifications = WithdrawalNotifications;