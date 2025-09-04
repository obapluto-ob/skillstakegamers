# SkillStake Gaming Platform

## Deploy to Render

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/skillstake-gaming.git
git push -u origin main
```

### 2. Deploy on Render
1. Go to [render.com](https://render.com)
2. Connect your GitHub repository
3. Choose "Web Service"
4. Set environment variables:
   - `SECRET_KEY`: Auto-generated
   - `ADMIN_PASSWORD`: Your secure admin password
   - `NOWPAYMENTS_API_KEY`: Your NOWPayments API key
   - `PAYPAL_CLIENT_ID`: Your PayPal client ID
   - `PAYPAL_CLIENT_SECRET`: Your PayPal client secret

### 3. Environment Variables
Copy `.env.example` to `.env` and fill in your values:
```bash
cp .env.example .env
```

### 4. Local Development
```bash
pip install -r requirements.txt
python app.py
```

## Security Features
- ✅ Login required for all user endpoints
- ✅ Admin authorization for admin endpoints  
- ✅ Environment variables for secrets
- ✅ Secure session configuration
- ✅ CSRF protection ready