@echo off
cd /d "%~dp0"

:: Kill port 3013 if busy
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 3013 -EA SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue }"

:: Install deps if needed
if not exist "node_modules" (
    echo Installing dependencies...
    npm install
)

:: Open browser after 3s (gives server time to bind)
start "" powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep 3; Start-Process 'http://localhost:3063'"

:: /D sets working directory for the new window — no cd escaping needed
start "PC Pulse Pro" /D "%~dp0" cmd /k npm run dev
