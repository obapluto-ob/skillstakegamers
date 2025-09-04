# SkillStake Platform Revenue & Referral System Explained

## 🎯 **REFERRAL SYSTEM - HOW IT WORKS**

### **For Users Who Register with Referral Links:**
1. **Immediate Signup Bonus**: Referrer gets KSh 30 instantly when someone uses their code
2. **Ongoing Commission**: Referrer earns **4% of ALL match losses** from referred users **FOREVER**
3. **No Limits**: Can refer unlimited friends and earn from all their activity

### **Example Referral Earnings:**
- Friend signs up with your code → **You get KSh 30**
- Friend loses KSh 500 in a match → **You get KSh 20 (4%)**
- Friend loses KSh 1000 in another match → **You get KSh 40 (4%)**
- **Total from one friend**: KSh 90 (and counting...)

### **What Happens to Referred Users:**
- ✅ They play normally with no restrictions
- ✅ They keep 100% of their winnings
- ✅ Only their **losses** generate commission for referrer
- ✅ They can withdraw money normally
- ✅ They can refer others and earn their own commissions

---

## 💰 **PLATFORM REVENUE BREAKDOWN**

### **Where Platform Money Comes From:**

#### **1. Match Commission (32%)**
- **Total pot**: KSh 1000 (KSh 500 × 2 players)
- **Winner gets**: KSh 680 (68%)
- **Platform gets**: KSh 320 (32%)
- **Referrer gets**: KSh 20 (4% of loser's KSh 500)
- **Net platform**: KSh 300 (after referral payout)

#### **2. Deposit Processing Fees (3%)**
- User deposits KSh 1000 via M-Pesa
- **Platform fee**: KSh 30 (3%)
- **User gets**: KSh 970 credited
- **Purpose**: Covers payment processing costs + profit

#### **3. Withdrawal Fees**
- **M-Pesa**: KSh 25 per withdrawal
- **PayPal**: 5.5% of amount
- **Crypto**: 3.5% of amount
- **Bank**: KSh 50 per withdrawal

#### **4. Tournament Fees (15%)**
- Entry fee: KSh 100
- **Prize pool**: KSh 85 (85%)
- **Platform fee**: KSh 15 (15%)

#### **5. Fraud Penalties**
- Fake screenshot: KSh 50-100 penalty
- **Platform gets**: 100% of penalty
- **Purpose**: Deterrent + revenue

#### **6. Referral Profit**
- Referrer gets KSh 30, platform pays KSh 50 total cost
- **Platform profit**: KSh 20 per referral
- **Long-term**: Platform saves 4% on referred user losses

---

## 🔄 **MONEY FLOW EXAMPLE**

### **Scenario**: User deposits KSh 1000, loses KSh 500 in match, withdraws KSh 500

1. **Deposit**: 
   - User sends KSh 1000
   - Platform keeps KSh 30 (3% fee)
   - User gets KSh 970

2. **Match Loss**:
   - User loses KSh 500
   - Platform gets KSh 160 (32% of KSh 500)
   - If referred: Referrer gets KSh 20, platform gets KSh 140

3. **Withdrawal**:
   - User withdraws KSh 470 remaining
   - Platform gets KSh 25 withdrawal fee
   - User receives KSh 445

4. **Total Platform Revenue**: KSh 215 (KSh 30 + KSh 140 + KSh 25)

---

## 📊 **CURRENT IMPLEMENTATION STATUS**

### ✅ **IMPLEMENTED**
- Match commission system (32%)
- Referral signup bonuses (KSh 30)
- **NEW**: Ongoing referral commissions (4% of losses)
- Withdrawal fees (KSh 25)
- Fraud penalty system
- **NEW**: Deposit processing fees (3%)

### 🔧 **HOW REFERRAL COMMISSIONS WORK**
```python
# When a match is completed:
def calculate_referral_commission(match_id, winner_id, loser_id, bet_amount):
    # Check if loser was referred by someone
    referrer = get_referrer(loser_id)
    if referrer:
        commission = bet_amount * 0.04  # 4% of loss
        credit_referrer(referrer, commission)
        record_transaction(referrer, 'referral_commission', commission)
        return commission
    return 0
```

### 📈 **REVENUE TRACKING**
- All commissions tracked in `referral_commissions` table
- Platform commission reduced by referral payouts
- Admin dashboard shows net revenue after referral costs
- Users see total referral earnings (signup + ongoing)

---

## 🎮 **USER EXPERIENCE**

### **For Referrers:**
- See total earnings breakdown in Referrals section
- Track individual friend contributions
- Earn passively from friend activity
- No limits on referral count

### **For Referred Users:**
- Play normally with no restrictions
- Unaware of commission system (transparent)
- Keep all winnings, only losses generate commission
- Can become referrers themselves

### **For Platform:**
- Sustainable revenue model
- Incentivizes user acquisition
- Reduces customer acquisition cost
- Creates viral growth loop

---

## 💡 **BUSINESS LOGIC**

### **Why This System Works:**
1. **User Acquisition**: Referrers actively bring new users
2. **Revenue Sharing**: Platform shares revenue to grow user base
3. **Sustainable**: 4% commission is small enough to not hurt users
4. **Viral Growth**: Successful referrers become advocates
5. **Long-term Value**: Ongoing commissions vs one-time bonuses

### **Platform Profitability:**
- **Break-even**: After referred user loses KSh 750 (30 ÷ 0.04)
- **Profit**: Every loss after KSh 750 is pure profit
- **Average user**: Loses KSh 2000+ over lifetime = KSh 50+ profit per referral

This system ensures both users and platform benefit from growth! 🚀