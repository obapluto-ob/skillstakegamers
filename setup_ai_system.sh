#!/bin/bash

echo "========================================"
echo "SkillStake AI System Setup (Linux/Mac)"
echo "========================================"

echo
echo "1. Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt

echo
echo "2. Installing Tesseract OCR..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt update
    sudo apt install -y tesseract-ocr
elif [[ "$OSTYPE" == "darwin"* ]]; then
    brew install tesseract
fi

echo
echo "3. Testing AI dependencies..."
python3 install_ai_dependencies.py

echo
echo "4. Starting application..."
echo "Visit: http://localhost:5000/admin/test_ai_system"
python3 app.py