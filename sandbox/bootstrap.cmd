@echo off
REM Wait for mapped folders to be available (LogonCommand runs before mappings are ready)
REM Timeout after 120 attempts (240 seconds) so sandbox exits cleanly instead of spinning forever
set /a attempts=0
:waitloop
if exist "C:\sandbox\scripts\setup.ps1" goto launch
set /a attempts+=1
if %attempts% GEQ 60 (
    echo FATAL: Mapped folders not available after 120s. Exiting sandbox.
    shutdown /s /t 5
    exit /b 1
)
timeout /t 2 /nobreak >nul
goto waitloop

:launch
REM Copy setup script to local disk and launch visibly
copy /Y "C:\sandbox\scripts\setup.ps1" "C:\setup.ps1"
start powershell -NoExit -ExecutionPolicy Bypass -File "C:\setup.ps1"
