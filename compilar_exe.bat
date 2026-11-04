@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [1/3] Ativando ambiente virtual...
call .venv\Scripts\activate.bat

echo [2/3] Instalando/verificando dependencias...
pip install -r requirements.txt

echo [3/3] Gerando executavel nativo standalone via PyInstaller...
pyinstaller --noconfirm --onefile --windowed --name "NetPulseTactical" --collect-all customtkinter main.py

echo.
echo Concluido! Executavel disponivel em: dist\NetPulseTactical.exe
pause
