@echo off
title SecuNik LogX
color 0A

echo ====================================================
echo    SECUNIK LOGX - Starting Services
echo ====================================================
echo.

:: Create required directories
if not exist "storage\uploads" mkdir storage\uploads
if not exist "storage\parsed" mkdir storage\parsed
if not exist "storage\analysis" mkdir storage\analysis
if not exist "storage\temp" mkdir storage\temp
if not exist "rules\custom" mkdir rules\custom
if not exist "storage\history.json" echo [] > storage\history.json

:: Install frontend dependencies if needed
if not exist "frontend\node_modules" (
    echo Installing frontend dependencies (first time only)...
    cd frontend
    call npm install
    cd ..
)

:: Start Backend
echo Starting Backend Server...
start "Backend" cmd /k "cd backend && venv\Scripts\activate && python -m uvicorn main:app --reload"

timeout /t 3 /nobreak > nul

:: Start Frontend
echo Starting Frontend Server...
start "Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo ====================================================
echo    Services starting...
echo.
echo    Frontend: http://localhost:5173
echo    Backend:  http://localhost:8000
echo    API Docs: http://localhost:8000/docs
echo ====================================================
echo.
pause