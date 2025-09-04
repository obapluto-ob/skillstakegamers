# SkillStake Referral System & Platform Revenue Analysis

## Current Issues Identified

### 1. **Referral System Gaps**
- ✅ Users get KSh 30 signup bonus when someone uses their referral code
- ❌ **MISSING**: No ongoing commission from referred users' activity
- ❌ **MISSING**: Referral template promises "4% of all their losses forever" but this is NOT implemented
- ❌ **MISSING**: No tracking of referred users' match activity for commission calculation

### 2. **Platform Revenue Logic Issues**
- ✅ Match commission: 32% of total pot goes to platform
- ✅ Withdrawal fees: KSh 25 per M-Pesa withdrawal
- ✅ Fraud penalties: KSh 50-100 penalties go to admin
- ❌ **MISSING**: Referral commission system (promised 4% of losses)
- ❌ **MISSING**: Deposit processing fees (currently 0% - should be 2-3%)
- ❌ **MISSING**: Tournament entry fees (15% commission)
- ❌ **MISSING**: Streaming platform fees

### 3. **Money Flow Problems**
When users deposit and spend money:
- User deposits KSh 1000 → Gets full KSh 1000 (no platform fee)
- User loses KSh 500 in match → Platform gets KSh 160 (32% of KSh 500)
- User withdraws KSh 500 → Platform gets KSh 25 fee
- **Total platform revenue: KSh 185 from KSh 1000 transaction**

### 4. **Referral Revenue Missing**
Current code shows:
```python
# Only gives one-time bonus
if referred_by_id:
    c.execute('UPDATE users SET balance = balance + 30 WHERE id = ?', (referred_by_id,))
    c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)', 
             (referred_by_id, 'referral_bonus', 30, f'Referral bonus for inviting {username}'))
    
    # Admin gets KSh 20 profit per referral
    c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)', 
             (1, 'admin_referral_profit', 20, f'Admin profit from {username} referral'))
```

**Missing**: Ongoing commission tracking when referred users lose matches.

## Recommended Fixes

### 1. **Implement Ongoing Referral Commission**
```python
# When a match is completed and someone loses
def process_match_completion(match_id, winner_id, loser_id, bet_amount):
    # Check if loser was referred by someone
    c.execute('SELECT referred_by FROM users WHERE id = ?', (loser_id,))
    referrer = c.fetchone()
    
    if referrer and referrer[0]:
        referral_commission = bet_amount * 0.04  # 4% of loss
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', 
                 (referral_commission, referrer[0]))
        c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                 (referrer[0], 'referral_commission', referral_commission, 
                  f'4% commission from {username} match loss'))
```

### 2. **Add Deposit Processing Fees**
```python
# In add_funds route
processing_fee = amount * 0.03  # 3% deposit fee
net_amount = amount - processing_fee
c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (net_amount, user_id))
c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
         (1, 'deposit_fee', processing_fee, f'3% processing fee from deposit'))
```

### 3. **Fix Platform Revenue Distribution**
Current match commission calculation:
- Total pot: KSh 1000 (KSh 500 × 2 players)
- Winner gets: KSh 680 (68%)
- Platform gets: KSh 320 (32%)

**This is correct** - platform takes 32% commission from total pot.

### 4. **Tournament Revenue System**
```python
# Tournament entry fees
tournament_fee = entry_amount * 0.15  # 15% platform fee
prize_pool = total_entries * entry_amount * 0.85  # 85% to winners
```

## Summary
The main issue is the **missing ongoing referral commission system**. Users are promised "4% of all their losses forever" but this is not implemented. The platform revenue from matches is working correctly at 32% commission.