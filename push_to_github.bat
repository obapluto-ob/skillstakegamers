@echo off
echo Pushing SkillStake Gaming Platform to GitHub...
echo.
echo Repository: https://github.com/obapluto-ob/skillstakegamers.git
echo.

git status
echo.

echo Pushing to GitHub (you may need to enter credentials)...
git push -f origin main

echo.
echo If push successful, your project is now on GitHub!
echo Next: Deploy on Render.com
pause