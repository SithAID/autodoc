@echo off
chcp 65001 >nul 2>&1
title AutoDoc

echo.
echo   AutoDoc - Local Dev Server
echo   ===========================
echo.

where node >nul 2>&1
if %errorlevel% neq 0 (
  echo   ERROR: Node.js not found.
  echo   Download from: https://nodejs.org
  echo   Install Node.js 18 or newer, then run this again.
  echo.
  pause
  exit /b 1
)

node start.js

if %errorlevel% neq 0 (
  echo.
  echo   Server stopped.
  pause
)
