# Gmail Email Verification Setup

## Quick Setup (5 minutes)

### 1. Enable 2-Factor Authentication
1. Go to [Google Account Settings](https://myaccount.google.com/)
2. Click "Security" → "2-Step Verification"
3. Follow setup instructions

### 2. Generate App Password
1. In Google Account → Security
2. Click "App passwords" 
3. Select "Mail" and "Other (custom name)"
4. Enter "SkillStake Gaming"
5. Copy the 16-character password

### 3. Add to Environment Variables
Create/update your `.env` file:
```bash
GMAIL_USER=your_email@gmail.com
GMAIL_PASS=your_16_character_app_password
```

### 4. Test Email System
```bash
python test_email_system.py
```

## How It Works

### Registration Flow
1. User enters email and password
2. System sends 6-digit code to email
3. User enters code to verify email
4. Account created with verified email

### Login Flow  
1. User enters email/username and password
2. System sends login code to registered email
3. User enters code to complete login

### Email Template
```
Subject: SkillStake - Verify Your Account

Welcome to SkillStake Gaming Platform!

Your verification code is: 123456

This code will expire in 10 minutes.

Please enter this code to complete your registration.

If you didn't create an account, please ignore this email.

Best regards,
SkillStake Team
```

## Benefits of Email Verification

✅ **Free** - No SMS costs
✅ **Reliable** - Gmail has 99.9% delivery rate
✅ **Secure** - Email verification is industry standard
✅ **User Friendly** - Most users check email regularly
✅ **No Phone Required** - Users can register without phone
✅ **International** - Works worldwide

## Phone Number Usage

- **Registration**: Phone optional (for M-Pesa payments)
- **Verification**: Email only
- **Payments**: Phone used for M-Pesa transactions
- **Login**: Email verification

## Production Recommendations

### For Small Scale (< 100 emails/day)
- Use **Gmail SMTP** (free)
- Cost: $0

### For Medium Scale (100-1000 emails/day)
- Use **SendGrid** (100 free emails/day)
- Cost: $15/month after free tier

### For Large Scale (1000+ emails/day)
- Use **AWS SES** or **Mailgun**
- Cost: $1 per 1000 emails

## Security Features

✅ **10-minute expiry** - Codes expire automatically
✅ **3 attempts max** - Prevents brute force
✅ **Rate limiting** - Max 5 emails per hour per address
✅ **Memory storage** - Codes not stored in database
✅ **Thread-safe** - Handles concurrent requests

## Troubleshooting

### "Gmail authentication failed"
1. Check 2FA is enabled
2. Verify app password is correct
3. Check Gmail account isn't locked

### "Email not received"
1. Check spam folder
2. Verify email address is correct
3. Try different email provider

### "Code expired"
- Codes expire after 10 minutes
- Request new code if needed

## Alternative Email Providers

### SendGrid Setup
```bash
SENDGRID_API_KEY=your_sendgrid_api_key
```

### Mailgun Setup  
```bash
MAILGUN_API_KEY=your_mailgun_api_key
MAILGUN_DOMAIN=your_domain.com
```

Your email verification system is now ready for production! 🎉