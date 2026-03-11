@echo off
setlocal EnableDelayedExpansion

echo.
echo   ========================================
echo        Cajal ICBM Installer (Windows)
echo   ========================================
echo.

:: ── Detect winget ────────────────────────────────────────────────────────────
set "HAS_WINGET=0"
where winget >nul 2>&1
if %errorlevel% equ 0 set "HAS_WINGET=1"

if "!HAS_WINGET!"=="0" (
    echo   winget not found — using direct download fallback.
    echo.
)

:: ── Install Git ──────────────────────────────────────────────────────────────
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Git...
    if "!HAS_WINGET!"=="1" (
        winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
    ) else (
        powershell -Command "Invoke-WebRequest -Uri 'https://github.com/git-for-windows/git/releases/download/v2.44.0.windows.1/Git-2.44.0-64-bit.exe' -OutFile '%TEMP%\git-installer.exe'"
        "%TEMP%\git-installer.exe" /VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS="icons,ext\reg\shellhere,assoc,assoc_sh"
    )
    if !errorlevel! neq 0 (
        echo ERROR: Failed to install Git.
        pause
        exit /b 1
    )
    echo   Git installed.
    echo.

    :: Refresh PATH
    for /f "tokens=2*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "SYS_PATH=%%B"
    for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "USR_PATH=%%B"
    set "PATH=!SYS_PATH!;!USR_PATH!"

    where git >nul 2>&1
    if !errorlevel! neq 0 (
        echo WARNING: Git was installed but is not yet on PATH.
        echo          Close this window, open a new one, and re-run install.bat
        pause
        exit /b 1
    )
) else (
    echo   Git already installed.
)

:: ── Install Node.js 20 ───────────────────────────────────────────────────────
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Node.js 20...
    if "!HAS_WINGET!"=="1" (
        winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
    ) else (
        powershell -Command "Invoke-WebRequest -Uri 'https://nodejs.org/dist/v20.12.2/node-v20.12.2-x64.msi' -OutFile '%TEMP%\node-installer.msi'"
        msiexec /i "%TEMP%\node-installer.msi" /qn /norestart
    )
    if !errorlevel! neq 0 (
        echo ERROR: Failed to install Node.js.
        pause
        exit /b 1
    )
    echo   Node.js installed.
    echo.

    :: Refresh PATH
    for /f "tokens=2*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "SYS_PATH=%%B"
    for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "USR_PATH=%%B"
    set "PATH=!SYS_PATH!;!USR_PATH!"

    where node >nul 2>&1
    if !errorlevel! neq 0 (
        echo WARNING: Node.js was installed but is not yet on PATH.
        echo          Close this window, open a new one, and re-run install.bat
        pause
        exit /b 1
    )
) else (
    for /f "tokens=1 delims=." %%M in ('node -e "process.stdout.write(process.version.slice(1))"') do set "NODE_MAJOR=%%M"
    if !NODE_MAJOR! LSS 20 (
        echo   Node.js found but v20+ required. Upgrading...
        if "!HAS_WINGET!"=="1" (
            winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
        ) else (
            powershell -Command "Invoke-WebRequest -Uri 'https://nodejs.org/dist/v20.12.2/node-v20.12.2-x64.msi' -OutFile '%TEMP%\node-installer.msi'"
            msiexec /i "%TEMP%\node-installer.msi" /qn /norestart
        )
    ) else (
        echo   Node.js already installed.
    )
)

:: ── Install Docker ───────────────────────────────────────────────────────────
where docker >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Docker...
    echo   This may take a few minutes and require a restart.
    echo.
    if "!HAS_WINGET!"=="1" (
        winget install --id Docker.DockerDesktop -e --accept-source-agreements --accept-package-agreements --silent
    ) else (
        powershell -Command "Invoke-WebRequest -Uri 'https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe' -OutFile '%TEMP%\DockerDesktopInstaller.exe'"
        "%TEMP%\DockerDesktopInstaller.exe" install --quiet --accept-license
    )
    if !errorlevel! neq 0 (
        echo ERROR: Failed to install Docker.
        echo        You can install it manually from https://docker.com/get-docker
        pause
        exit /b 1
    )
    echo.
    echo   Docker installed.
    echo.
    echo   IMPORTANT: You must restart your computer, then:
    echo     1. Open Docker Desktop and complete setup
    echo     2. Re-run this install.bat script
    echo.
    pause
    exit /b 0
) else (
    echo   Docker already installed.
)

:: ── Verify docker is actually running ────────────────────────────────────────
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   Docker is installed but not running.
    echo   Please start Docker Desktop, wait for it to finish loading,
    echo   then re-run this script.
    echo.
    pause
    exit /b 1
)

:: ── Clone Cajal ──────────────────────────────────────────────────────────────
set "INSTALL_DIR=%USERPROFILE%\cajal"

if exist "%INSTALL_DIR%" (
    echo   %INSTALL_DIR% already exists. Pulling latest...
    cd /d "%INSTALL_DIR%"
    git pull --ff-only || echo   Pull failed, continuing with existing files.
) else (
    echo Cloning Cajal...
    git clone https://github.com/nniell90/cajal.git "%INSTALL_DIR%"
    if !errorlevel! neq 0 (
        echo ERROR: Failed to clone repository.
        pause
        exit /b 1
    )
    cd /d "%INSTALL_DIR%"
    echo   Cloned to %INSTALL_DIR%
)

:: ── Create .env from example if missing ──────────────────────────────────────
if not exist .env (
    if exist .env.example (
        copy .env.example .env >nul
        echo   INFO: .env created from .env.example
    ) else (
        echo ERROR: .env file is missing and no .env.example found.
        pause
        exit /b 1
    )
)

:: ── Auto-generate CAJAL_CONFIG_KEY if missing ────────────────────────────────
findstr /B "CAJAL_CONFIG_KEY=" .env >nul 2>&1
if %errorlevel% neq 0 (
    for /f %%K in ('node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"') do set "NEW_KEY=%%K"
    echo CAJAL_CONFIG_KEY=!NEW_KEY!>> .env
    echo   INFO: CAJAL_CONFIG_KEY auto-generated
)

:: ── Auto-generate CAJAL_DB_PASSWORD if missing ───────────────────────────────
findstr /B "CAJAL_DB_PASSWORD=" .env >nul 2>&1
if %errorlevel% neq 0 (
    for /f %%P in ('node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"') do set "NEW_PASS=%%P"
    echo CAJAL_DB_PASSWORD=!NEW_PASS!>> .env
    echo   INFO: CAJAL_DB_PASSWORD auto-generated
)

:: ── Sync .db_password file from CAJAL_DB_PASSWORD ────────────────────────────
for /f "tokens=2 delims==" %%D in ('findstr /B "CAJAL_DB_PASSWORD=" .env') do (
    echo|set /p="%%D"> .db_password
    echo   INFO: .db_password synced from .env
)

:: ── Auto-generate CAJAL_WATCHTOWER_TOKEN if missing ──────────────────────────
findstr /B "CAJAL_WATCHTOWER_TOKEN=" .env >nul 2>&1
if %errorlevel% neq 0 (
    for /f %%T in ('node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"') do set "NEW_TOKEN=%%T"
    echo CAJAL_WATCHTOWER_TOKEN=!NEW_TOKEN!>> .env
    echo   INFO: CAJAL_WATCHTOWER_TOKEN auto-generated
)

:: ── Build and start ──────────────────────────────────────────────────────────
echo.
echo Building and starting Cajal...
echo.
docker compose up -d --build
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Docker build failed. Check the output above.
    pause
    exit /b 1
)

echo.
echo   ========================================
echo        Installation complete!
echo.
echo     Open: http://localhost:4000
echo.
echo     Create your admin account on
echo     first login.
echo   ========================================
echo.
pause
