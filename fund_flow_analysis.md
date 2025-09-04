# Fund Flow Analysis - SkillStake

## Current System Logic

### 💰 DEPOSITS
```
User Deposits KSh 1000 via M-Pesa/PayPal/Crypto
├── 3% Fee Deducted (KSh 30)
├── User Gets: KSh 970
└── Admin Gets: KSh 30 (commission)
```

### 💸 WITHDRAWALS
```
M-Pesa Withdrawal (KSh 500)
├── Fixed Fee: KSh 25
├── Processing Fee: 2% (KSh 10)
├── Total Fees: KSh 35
├── User Receives: KSh 465
└── Admin Gets: KSh 35

PayPal Withdrawal (KSh 500)  
├── PayPal Fee: 5.5% (KSh 27.50)
├── Processing Fee: 2% (KSh 10)
├── Total Fees: KSh 37.50
├── User Receives: KSh 462.50
└── Admin Gets: KSh 37.50

Crypto Withdrawal (KSh 1625)
├── Crypto Fee: 3.5% (KSh 56.88)
├── Processing Fee: 2% (KSh 32.50)
├── Total Fees: KSh 89.38
├── User Receives: KSh 1535.62
└── Admin Gets: KSh 89.38
```

### 🔄 REFUND SCENARIOS

#### User Cancels Withdrawal
```
1. User requests KSh 500 withdrawal
2. System deducts KSh 500 from balance
3. User cancels before admin processes
4. System refunds FULL KSh 500 (no fees charged)
5. Admin gets: KSh 0
```

#### Admin Rejects Withdrawal
```
1. User requests KSh 500 withdrawal  
2. System deducts KSh 500 from balance
3. Admin rejects with reason
4. System refunds FULL KSh 500
5. Admin gets: KSh 0 (no fees on rejected withdrawals)
```

#### Auto-Refund (30min timeout)
```
1. User requests KSh 500 withdrawal
2. System deducts KSh 500 from balance
3. Admin inactive for 30+ minutes
4. User claims auto-refund
5. System refunds FULL KSh 500
6. Admin gets: KSh 0
```

### ⚔️ MATCH SYSTEM
```
Match Pot: KSh 400 (2 players × KSh 200 each)
├── Admin Commission: 32% (KSh 128)
├── Winner Gets: KSh 272
└── Loser Gets: KSh 0

Player 1 Balance: 1000 - 200 + 272 = 1072
Player 2 Balance: 1000 - 200 + 0 = 800
```

### 🚨 FRAUD PENALTIES
```
Fake Screenshot Detected:
├── User Penalty: KSh 50
├── Admin Commission: KSh 50
└── Match continues for other player
```

## 🔍 POTENTIAL ISSUES TO TEST

### 1. Double Processing
- ✅ User cancels withdrawal but admin also processes it
- ✅ User gets refunded twice
- ✅ Admin loses money

### 2. Race Conditions  
- ✅ User cancels while admin is processing
- ✅ Multiple admins process same withdrawal
- ✅ Auto-refund triggers during manual processing

### 3. Fee Calculation Errors
- ✅ Rounding errors in percentage calculations
- ✅ Negative balances after fees
- ✅ Commission not properly credited to admin

### 4. Refund Logic
- ✅ Partial refunds vs full refunds
- ✅ Fee refunds on cancellations
- ✅ Multiple refund attempts

## 🧪 TESTING RECOMMENDATIONS

### Run the Test Suite:
```bash
cd c:\Windows\System32\gamers
python fund_flow_test.py
```

### Manual Testing Checklist:
1. **Deposit KSh 1000** → Check user gets KSh 970, admin gets KSh 30
2. **Withdraw KSh 500 via M-Pesa** → Check fees calculated correctly
3. **Cancel withdrawal** → Check full refund (no fees)
4. **Admin reject withdrawal** → Check full refund + reason
5. **Auto-refund after 30min** → Check timeout logic
6. **Create match KSh 200** → Check commission split
7. **Submit fake screenshot** → Check penalty applied
8. **Multiple rapid transactions** → Check for race conditions

### Database Integrity Checks:
```sql
-- Check if money is being created/destroyed
SELECT 
  SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as money_in,
  SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) as money_out,
  SUM(amount) as net_change
FROM transactions;

-- Check admin commission tracking
SELECT type, SUM(amount) as total 
FROM transactions 
WHERE user_id = 1 
GROUP BY type;

-- Check user balance vs transaction history
SELECT 
  u.id, u.username, u.balance,
  COALESCE(SUM(t.amount), 0) as transaction_total
FROM users u 
LEFT JOIN transactions t ON u.id = t.user_id 
WHERE u.username != 'admin'
GROUP BY u.id;
```

## 🛡️ SAFETY MEASURES NEEDED

1. **Transaction Locks** - Prevent double processing
2. **Balance Validation** - Check sufficient funds before deduction  
3. **Audit Trail** - Log all balance changes with reasons
4. **Rollback Mechanism** - Undo transactions if errors detected
5. **Daily Reconciliation** - Check total money in system matches records

## 💡 RECOMMENDATIONS

1. **Add transaction status tracking** (pending/completed/failed)
2. **Implement atomic operations** for balance changes
3. **Add balance validation** before any deduction
4. **Create admin dashboard** showing money flow
5. **Add alerts** for unusual transactions
6. **Implement daily balance reports**