@echo off
echo ========================================
echo SkillStake AI System Setup (Windows)
echo ========================================

echo.
echo 1. Installing Python packages...
pip install --upgrade pip
pip install -r requirements.txt

echo.
echo 2. Checking Tesseract OCR...
tesseract --version >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Tesseract OCR not found!
    echo Please install from: https://github.com/UB-Mannheim/tesseract/wiki
    echo Add to PATH: C:\Program Files\Tesseract-OCR
) else (
    echo Tesseract OCR found!
)

echo.
echo 3. Testing AI dependencies...
python install_ai_dependencies.py

echo.
echo 4. Starting application...
echo Visit: http://localhost:5000/admin/test_ai_system
python app.py

pause