@echo off
echo ========================================
echo Installing Tesseract OCR for Windows
echo ========================================

echo.
echo 1. Downloading Tesseract OCR installer...
echo Opening download page in browser...
start https://github.com/UB-Mannheim/tesseract/wiki

echo.
echo 2. Installation Instructions:
echo    - Download tesseract-ocr-w64-setup-5.3.3.20231005.exe
echo    - Run the installer as Administrator
echo    - Install to: C:\Program Files\Tesseract-OCR
echo    - Check "Add to PATH" during installation

echo.
echo 3. After installation, restart this terminal and run:
echo    tesseract --version

echo.
echo 4. Then start the application:
echo    python app.py

echo.
echo Press any key to continue after installing Tesseract...
pause

echo.
echo Testing Tesseract installation...
tesseract --version
if %errorlevel% equ 0 (
    echo ✅ Tesseract installed successfully!
    echo.
    echo Starting SkillStake application...
    python app.py
) else (
    echo ❌ Tesseract not found. Please:
    echo 1. Restart terminal after installation
    echo 2. Verify PATH includes: C:\Program Files\Tesseract-OCR
    echo 3. Run: tesseract --version
)

pause