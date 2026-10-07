@echo off
chcp 65001 >nul
echo ========================================================
echo               ВИДАЛЕННЯ GAMETRACKER
echo ========================================================

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [УВАГА] Цей скрипт потребує прав Адміністратора!
    echo Запустіть файл від імені адміністратора.
    pause
    exit /b 1
)

echo [1/3] Зупинка служби...
taskkill /F /IM GameTrackerService.exe >nul 2>&1

echo [2/3] Видалення завдання автозапуску...
schtasks /Delete /F /TN "GameTrackerService" >nul 2>&1

echo [3/3] Очищення файлів програми...
set "INSTALL_DIR=%ProgramFiles%\GameTracker"
if exist "%INSTALL_DIR%" rmdir /S /Q "%INSTALL_DIR%"

echo.
echo GameTracker успішно видалено з системи.
pause
