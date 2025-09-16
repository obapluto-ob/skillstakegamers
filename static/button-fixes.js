// Fix for user stats and button functionality issues
document.addEventListener('DOMContentLoaded', function() {
    console.log('Button fixes loaded');
    
    // Fix dropdown menu issues
    const dropdowns = document.querySelectorAll('.dropdown');
    dropdowns.forEach(dropdown => {
        const btn = dropdown.querySelector('.dropdown-btn');
        const content = dropdown.querySelector('.dropdown-content');
        
        if (btn && content) {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                
                dropdowns.forEach(other => {
                    if (other !== dropdown) {
                        other.querySelector('.dropdown-content').style.display = 'none';
                    }
                });
                
                if (content.style.display === 'block') {
                    content.style.display = 'none';
                } else {
                    content.style.display = 'block';
                }
            });
            
            // Use single event listener to prevent memory leaks
            if (!dropdown.hasAttribute('data-listener-added')) {
                document.addEventListener('click', function(e) {
                    if (!dropdown.contains(e.target)) {
                        content.style.display = 'none';
                    }
                });
                dropdown.setAttribute('data-listener-added', 'true');
            }
        }
    });
    
    // Fix form submission issues
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Processing...';
                
                setTimeout(() => {
                    submitBtn.disabled = false;
                    submitBtn.textContent = submitBtn.getAttribute('data-original-text') || 'Submit';
                }, 3000);
            }
        });
    });
    
    // Fix stats display issues
    const statCards = document.querySelectorAll('.stat-card');
    statCards.forEach(card => {
        const number = card.querySelector('.stat-number');
        if (number && number.textContent.includes('NaN')) {
            number.textContent = 'KSh 0';
        }
    });
    
    // Auto-refresh balance
    if (window.location.pathname.includes('dashboard')) {
        let balanceInterval = setInterval(function() {
            fetch('/api/user_balance')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const balanceElements = document.querySelectorAll('.balance');
                        balanceElements.forEach(el => {
                            el.textContent = `KSh ${data.balance}`;
                        });
                    }
                })
                .catch(err => console.log('Balance refresh failed'));
        }, 60000);
        
        // Cleanup interval on page unload
        window.addEventListener('beforeunload', function() {
            if (balanceInterval) clearInterval(balanceInterval);
        });
    }
    
    console.log('All button fixes applied successfully');
});

// Gift sending function
window.sendGift = function(streamId, giftType, amount = 1) {
    fetch('/send_gift', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            stream_id: streamId,
            gift_type: giftType,
            amount: amount
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(data.message);
            const balanceElements = document.querySelectorAll('.balance');
            balanceElements.forEach(el => {
                el.textContent = `KSh ${data.new_balance}`;
            });
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(err => {
        console.error('Gift error:', err);
        alert('Failed to send gift');
    });
};

// Stats refresh function
window.refreshUserStats = function() {
    fetch('/api/refresh_dashboard')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                console.log('Stats refreshed:', data.stats);
                location.reload();
            } else {
                console.log('Refresh failed:', data.error);
                location.reload();
            }
        })
        .catch(err => {
            console.log('Refresh error:', err);
            location.reload();
        });
};