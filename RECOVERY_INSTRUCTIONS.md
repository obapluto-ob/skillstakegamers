# USER RECOVERY SYSTEM

## Current Status ✅
- **14 users** currently in database with **KSh 10,811** total balances
- **No lost users with money** found in transaction history
- **All user data is safe and protected**

## Recovery Options

### 1. **If You Remember Lost Users**
```bash
# Add single user
python manual_user_recovery.py add username phone balance

# Example:
python manual_user_recovery.py add john 0712345678 500
```

### 2. **Bulk Recovery (Multiple Users)**
```bash
python manual_user_recovery.py bulk
```
Then enter users in format: `username,phone,balance`

### 3. **From Backup File**
```bash
python manual_user_recovery.py backup filename.json
```

### 4. **Check Current Users**
```bash
python manual_user_recovery.py list
```

## Safe Deployment Process

### Before Every Render Deployment:
1. **Create Backup:**
   ```bash
   python safe_backup.py
   ```

2. **Copy Environment Variable:**
   - Open `.env.backup` file
   - Copy the `USER_BACKUP_DATA` content
   - Add to Render Environment Variables

3. **Deploy Safely:**
   - Users will auto-restore if database is empty
   - No data loss guaranteed

## Emergency Recovery
If users are lost after deployment:
```bash
python recover_users.py
```

## Contact Lost Users
If you know users who lost access:
1. Ask them to re-register with **same phone number**
2. Use manual recovery to restore their balance
3. Password will be reset to `password123`

## Current Protected Users:
- plutomania: KSh 4,391.16
- kolu: KSh 3,099.24  
- kaleb: KSh 1,242.50
- kasongomustgo: KSh 523.50
- kasongo: KSh 335.00
- pluto: KSh 150.00
- obapluto: KSh 79.50
- Others: KSh 0.00

**Total Protected: KSh 10,811**