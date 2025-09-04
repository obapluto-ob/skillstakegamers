# SkillStake Deployment Guide - EASY STEPS

## Step 1: Push to GitHub (5 minutes)

1. Open Command Prompt in your project folder
2. Run these commands one by one:

```bash
git add .
git commit -m "PostgreSQL migration complete"
git push origin main
```

## Step 2: Deploy on Render (10 minutes)

### A. Create Web Service
1. Go to https://render.com
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Choose your skillstake repository

### B. Configure Settings
- **Name**: skillstake-gaming
- **Environment**: Python 3
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `python app.py`

### C. Add Environment Variables (CRITICAL)
Click "Advanced" → Add these EXACT variables:

```
DATABASE_URL = postgresql://skillstake_user:LpB5yOlwXhgQpH1AD2jZr2widqkcIqwX@dpg-d2t195je5dus73dckdh0-a.oregon-postgres.render.com/skillstake_db

SECRET_KEY = gamebet_secret_key_2024_secure_random_string

ADMIN_PASSWORD = your-admin-password-here

PAYPAL_CLIENT_ID = AT-oazZhMmPUtklfCvlFyO9qL3FypQWL4VE-03iehC1wgrTaWRh4C3J6CBh2fykV-xUUrZ9KEjdC8lDq

PAYPAL_CLIENT_SECRET = EGmDqVftpYT7vR1fS1BprWAZ4xL4hIFGkSIkAbaMSzj3cLrMs5hHVMY871sVzlzjo3OkivzdLTl8pEtn

NOWPAYMENTS_API_KEY = YSRK1WV-3AF4QJ8-MWQ7V1D-BZK2018
```

### D. Deploy
1. Click "Create Web Service"
2. Wait 5-10 minutes for deployment
3. Your app will be live at: https://skillstake-gaming.onrender.com

## Step 3: Verify Everything Works

1. Visit your live site
2. Login as admin (username: admin, password: your-admin-password)
3. Check admin dashboard - you should see 10 users with KSh 10,790.90 total

## ✅ Success Indicators

- ✅ 10 users automatically restored
- ✅ Total balance: KSh 10,790.90
- ✅ No more data loss on redeployments
- ✅ PostgreSQL database working

## 🆘 If Something Goes Wrong

1. Check Render logs for errors
2. Verify all environment variables are set correctly
3. Make sure DATABASE_URL is exactly as shown above

## 🎉 You're Done!

Your users' money is now permanently safe. No more data loss ever again!