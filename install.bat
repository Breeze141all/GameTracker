@echo off
chcp 65001 >nul
echo ========================================================
echo             ВСТАНОВЛЕННЯ GAMETRACKER
echo ========================================================

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [УВАГА] Цей інсталятор потребує прав Адміністратора!
    echo Будь ласка, клацніть правою кнопкою миші на install.bat
    echo і оберіть: "Запустити від імені адміністратора" (Run as administrator).
    echo.
    pause
    exit /b 1
)

set "SOURCE_DIR=%~dp0dist"
if not exist "%SOURCE_DIR%\GameTrackerService.exe" (
    echo [ПОМИЛКА] Файл GameTrackerService.exe не знайдено в папці dist!
    echo Запустіть спочатку build_and_install.bat.
    pause
    exit /b 1
)

echo [1/3] Копіювання файлів програми у C:\Program Files\GameTracker...
set "INSTALL_DIR=%ProgramFiles%\GameTracker"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
copy /Y "%SOURCE_DIR%\GameTrackerService.exe" "%INSTALL_DIR%\" >nul
copy /Y "%SOURCE_DIR%\gametracker.exe" "%INSTALL_DIR%\" >nul

echo [2/3] Реєстрація системної служби в автозавантаженні Windows...
schtasks /Create /F /SC ONSTART /TN "GameTrackerService" /TR "\"%INSTALL_DIR%\GameTrackerService.exe\"" /RU "SYSTEM" /RL "HIGHEST" >nul

echo [3/3] Запуск служби...
schtasks /Run /TN "GameTrackerService" >nul

echo.
echo ========================================================
echo         ПРОГРАМУ УСПІШНО ВСТАНОВЛЕНО ТА ЗАПУЩЕНО!
echo ========================================================
echo Служба контролю часу працює у фоні з найвищими привілеями SYSTEM.
echo Вона захищена від закриття через Диспетчер завдань та від переводу годинника.
echo.
echo Поточний статус:
"%INSTALL_DIR%\gametracker.exe" status
echo.
pause
