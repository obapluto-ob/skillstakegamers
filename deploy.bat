@echo off
echo ========================================
echo SkillStake Deployment Helper
echo ========================================
echo.

echo Step 1: Adding all files...
git add .

echo Step 2: Committing changes...
git commit -m "PostgreSQL migration - user data protection complete"

echo Step 3: Pushing to GitHub...
git push origin main

echo.
echo ========================================
echo SUCCESS! Code pushed to GitHub
echo ========================================
echo.
echo Next steps:
echo 1. Go to render.com
echo 2. Create new Web Service
echo 3. Connect your GitHub repo
echo 4. Add environment variables from DEPLOY_STEPS.md
echo 5. Deploy!
echo.
pause