@echo off
REM GoCertif Web — Script de démarrage Windows
title GoCertif Web — HAS V2025

cd /d "%~dp0"

echo ==========================================
echo   GoCertif Web — HAS V2025
echo ==========================================

REM Vérifier Python
python --version >nul 2>&1
if errorlevel 1 (
    echo Erreur : Python n'est pas installe.
    echo Telechargez-le sur https://www.python.org
    pause
    exit /b
)

echo Verification des dependances...
python -c "import tornado" 2>nul || pip install tornado
python -c "import openpyxl" 2>nul || pip install openpyxl
python -c "import reportlab" 2>nul || pip install reportlab

echo Lancement du serveur sur http://localhost:5050
echo Fermez cette fenetre pour arreter le serveur
echo.

REM Ouvrir le navigateur après 2s
start /b cmd /c "timeout /t 2 >nul && start http://localhost:5050"

python app.py
pause
