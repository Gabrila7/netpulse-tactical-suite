@echo off
chcp 65001 >nul
title Enviar NetPulse para o GitHub
cd /d "%~dp0"

echo =======================================================
echo    ENVIAR NETPULSE TACTICAL SUITE PARA O GITHUB
echo =======================================================
echo.

set /p GITHUB_URL="Cole o link do seu repositorio (ex: https://github.com/Usuario/repo.git): "

if "%GITHUB_URL%"=="" (
    echo [ERRO] Link invalido ou vazio!
    pause
    exit /b
)

echo.
echo [1/5] Inicializando Git...
git init

echo.
echo [2/5] Adicionando arquivos do projeto...
git add .

echo.
echo [3/5] Criando o commit inicial...
git commit -m "feat: initial commit - NetPulse Tactical Suite v2.5"

echo.
echo [4/5] Configurando branch principal (main)...
git branch -M main

echo.
echo [5/5] Vinculando repositorio e enviando para o GitHub...
git remote remove origin 2>nul
git remote add origin %GITHUB_URL%
git push -u origin main

echo.
echo =======================================================
echo   Processo finalizado com sucesso!
echo =======================================================
pause
