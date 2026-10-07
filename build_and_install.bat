@echo off
chcp 65001 >nul
echo ========================================================
echo       ВСТАНОВЛЕННЯ ТА ЗБІРКА GAMETRACKER (WINDOWS)
echo ========================================================

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [УВАГА] Цей скрипт потребує прав Адміністратора!
    echo Будь ласка, клацніть правою кнопкою миші на цей файл
    echo і оберіть: "Запустити від імені адміністратора" (Run as administrator).
    echo.
    pause
    exit /b 1
)

echo [1/5] Перевірка Python...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ПОМИЛКА] Python не знайдено в системі!
    echo Встановіть Python 3.10+ з python.org і поставте галочку "Add to PATH".
    pause
    exit /b 1
)

echo [2/5] Перевірка PyInstaller...
python -c "import PyInstaller" >nul 2>&1
if %errorLevel% neq 0 (
    echo Встановлення PyInstaller...
    python -m pip install pyinstaller
)

echo [3/5] Компіляція бінарників (.exe)...
pyinstaller --onefile --noconsole --name GameTrackerService --clean run_service.py
if %errorLevel% neq 0 (
    echo [ПОМИЛКА] Збірка GameTrackerService.exe не вдалася.
    pause
    exit /b 1
)

pyinstaller --onefile --console --name gametracker --clean run_cli.py
if %errorLevel% neq 0 (
    echo [ПОМИЛКА] Збірка gametracker.exe не вдалася.
    pause
    exit /b 1
)

echo [4/5] Встановлення файлів у C:\Program Files\GameTracker...
set "INSTALL_DIR=%ProgramFiles%\GameTracker"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
copy /Y "dist\GameTrackerService.exe" "%INSTALL_DIR%\" >nul
copy /Y "dist\gametracker.exe" "%INSTALL_DIR%\" >nul

echo [5/5] Реєстрація служби автозапуску Windows...
schtasks /Create /F /SC ONSTART /TN "GameTrackerService" /TR "\"%INSTALL_DIR%\GameTrackerService.exe\"" /RU "SYSTEM" /RL "HIGHEST" >nul
schtasks /Run /TN "GameTrackerService" >nul

echo.
echo ========================================================
echo         ВСТАНОВЛЕННЯ УСПІШНО ЗАВЕРШЕНО!
echo ========================================================
echo Служба GameTrackerService запущена та додана в автозавантаження.
echo Вона працює у фоновому режимі як системний процес.
echo.
echo Перевірка поточного стану:
"%INSTALL_DIR%\gametracker.exe" status
echo.
pause
