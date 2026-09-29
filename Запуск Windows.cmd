@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
set "PYTHONUTF8=1"
cd /d "%~dp0"
if errorlevel 1 exit /b 1
set "CARRIER_PY="
for %%V in (3.14 3.13 3.12 3.11) do (
    py -%%V -c "import sys; assert sys.version_info >= (3,11) and sys.maxsize > 2**32" >nul 2>&1
    if not errorlevel 1 (
        set "CARRIER_PY=py -%%V"
        goto run
    )
)
py -3 -c "import sys; assert sys.version_info >= (3,11) and sys.maxsize > 2**32" >nul 2>&1
if not errorlevel 1 (
    set "CARRIER_PY=py -3"
    goto run
)
python -c "import sys; assert sys.version_info >= (3,11) and sys.maxsize > 2**32" >nul 2>&1
if not errorlevel 1 (
    set "CARRIER_PY=python"
    goto run
)
echo Установите Python 3.11 или новее, x64: https://www.python.org/downloads/windows/
set "CARRIER_STATUS=1"
goto finish
:run
%CARRIER_PY% -u launch.py %*
set "CARRIER_STATUS=%ERRORLEVEL%"
:finish
if not "%CARRIER_STATUS%"=="0" if "%~1"=="" pause
exit /b %CARRIER_STATUS%
