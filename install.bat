@echo off
setlocal EnableDelayedExpansion

echo.
echo   ========================================
echo        Cajal ICBM Installer (Windows)
echo   ========================================
echo.

:: ── Refresh PATH from registry (picks up previously installed tools) ─────────
for /f "tokens=2*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "SYS_PATH=%%B"
for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "USR_PATH=%%B"
if defined SYS_PATH set "PATH=!SYS_PATH!;!USR_PATH!"

:: ── Detect winget ────────────────────────────────────────────────────────────
set "HAS_WINGET=0"
where winget >nul 2>&1
if %errorlevel% equ 0 set "HAS_WINGET=1"

if "!HAS_WINGET!"=="0" (
    echo   winget not found — using direct download fallback.
    echo.
)

goto :after_fns

:: ════════════════════════════════════════════════════════════════════════════
:: :download  <url>  <outfile>
:: ════════════════════════════════════════════════════════════════════════════
:download
    curl -L --progress-bar -o "%~2" "%~1" 2>&1
    if !errorlevel! neq 0 (
        bitsadmin /transfer cajal_dl /download /priority normal "%~1" "%~2" >nul 2>&1
    )
    exit /b !errorlevel!

:: ════════════════════════════════════════════════════════════════════════════
:: :spinner  <message>  <process_name>
::   Prints a spinning indicator until <process_name> is no longer running.
:: ════════════════════════════════════════════════════════════════════════════
:spinner
    set "_MSG=%~1"
    set "_PROC=%~2"
    set "_FRAMES=\|/-"
    set "_FI=0"
    :_spin_loop
        tasklist /fi "imagename eq !_PROC!" 2>nul | find /i "!_PROC!" >nul
        if !errorlevel! neq 0 goto :_spin_done
        set /a "_FI=(_FI+1) %% 4"
        set "_CH=!_FRAMES:~%_FI%,1!"
        <nul set /p="  [!_CH!] !_MSG!   "
        echo.& <nul set /p="[1A"
        ping -n 2 127.0.0.1 >nul
    goto :_spin_loop
    :_spin_done
    echo   [+] !_MSG! done.
    exit /b 0

:after_fns

:: ── Install Git ──────────────────────────────────────────────────────────────
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   [1/4] Git
    if "!HAS_WINGET!"=="1" (
        winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
    ) else (
        echo   Downloading Git...
        call :download "https://github.com/git-for-windows/git/releases/download/v2.44.0.windows.1/Git-2.44.0-64-bit.exe" "%TEMP%\git-installer.exe"
        echo   Installing Git...
        start /b "" "%TEMP%\git-installer.exe" /VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS="icons,ext\reg\shellhere,assoc,assoc_sh"
        call :spinner "Installing Git" "Git-2.44.0-64-bit.exe"
    )
    if !errorlevel! neq 0 (
        echo.
        echo   ERROR: Failed to install Git.
        pause
        exit /b 1
    )

    for /f "tokens=2*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "SYS_PATH=%%B"
    for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "USR_PATH=%%B"
    set "PATH=!SYS_PATH!;!USR_PATH!"

    where git >nul 2>&1
    if !errorlevel! neq 0 (
        echo.
        echo   WARNING: Git installed but not yet on PATH.
        echo            Close this window, open a new one, and re-run install.bat
        pause
        exit /b 1
    )
) else (
    echo   [1/4] Git .................. already installed
)

:: ── Install Node.js 20 ───────────────────────────────────────────────────────
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   [2/4] Node.js
    if "!HAS_WINGET!"=="1" (
        winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
    ) else (
        echo   Downloading Node.js...
        call :download "https://nodejs.org/dist/v20.12.2/node-v20.12.2-x64.msi" "%TEMP%\node-installer.msi"
        echo   Installing Node.js...
        start /b "" msiexec /i "%TEMP%\node-installer.msi" /qn /norestart
        call :spinner "Installing Node.js" "msiexec.exe"
    )
    if !errorlevel! neq 0 (
        echo.
        echo   ERROR: Failed to install Node.js.
        pause
        exit /b 1
    )

    for /f "tokens=2*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "SYS_PATH=%%B"
    for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "USR_PATH=%%B"
    set "PATH=!SYS_PATH!;!USR_PATH!"

    where node >nul 2>&1
    if !errorlevel! neq 0 (
        echo.
        echo   WARNING: Node.js installed but not yet on PATH.
        echo            Close this window, open a new one, and re-run install.bat
        pause
        exit /b 1
    )
) else (
    for /f "tokens=1 delims=." %%M in ('node -e "process.stdout.write(process.version.slice(1))"') do set "NODE_MAJOR=%%M"
    if !NODE_MAJOR! LSS 20 (
        echo.
        echo   [2/4] Node.js — upgrading to v20+...
        if "!HAS_WINGET!"=="1" (
            winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
        ) else (
            echo   Downloading Node.js...
            call :download "https://nodejs.org/dist/v20.12.2/node-v20.12.2-x64.msi" "%TEMP%\node-installer.msi"
            start /b "" msiexec /i "%TEMP%\node-installer.msi" /qn /norestart
            call :spinner "Upgrading Node.js" "msiexec.exe"
        )
    ) else (
        echo   [2/4] Node.js .............. already installed
    )
)

:: ── Install Docker ───────────────────────────────────────────────────────────
where docker >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   [3/4] Docker Desktop
    if "!HAS_WINGET!"=="1" (
        winget install --id Docker.DockerDesktop -e --accept-source-agreements --accept-package-agreements --silent
    ) else (
        echo   Downloading Docker Desktop (this is large, please wait)...
        call :download "https://desktop.docker.com/win/main/amd64/Docker Desktop Installer.exe" "%TEMP%\DockerDesktopInstaller.exe"
        echo   Installing Docker Desktop...
        start /b "" "%TEMP%\DockerDesktopInstaller.exe" install --quiet --accept-license
        call :spinner "Installing Docker Desktop" "DockerDesktopInstaller.exe"
    )
    if !errorlevel! neq 0 (
        echo.
        echo   ERROR: Failed to install Docker.
        echo          You can install it manually from https://docker.com/get-docker
        pause
        exit /b 1
    )
    echo.
    echo   IMPORTANT: You must restart your computer, then:
    echo     1. Open Docker Desktop and complete setup
    echo     2. Re-run this install.bat script
    echo.
    pause
    exit /b 0
) else (
    echo   [3/4] Docker ............... already installed
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

:: ── Clone / update Cajal ─────────────────────────────────────────────────────
echo.
echo   [4/4] Cajal
set "INSTALL_DIR=%USERPROFILE%\cajal"

if exist "%INSTALL_DIR%" (
    echo   Pulling latest updates...
    cd /d "%INSTALL_DIR%"
    git pull --ff-only || echo   Pull failed, continuing with existing files.
) else (
    echo   Cloning repository...
    git clone https://github.com/nniell90/cajal.git "%INSTALL_DIR%"
    if !errorlevel! neq 0 (
        echo   ERROR: Failed to clone repository.
        pause
        exit /b 1
    )
    cd /d "%INSTALL_DIR%"
)

:: ── Create .env from example if missing ──────────────────────────────────────
if not exist .env (
    if exist .env.example (
        copy .env.example .env >nul
        echo   INFO: .env created from .env.example
    ) else (
        echo   ERROR: .env file is missing and no .env.example found.
        pause
        exit /b 1
    )
)

:: ── Auto-generate secrets ─────────────────────────────────────────────────────
findstr /B "CAJAL_CONFIG_KEY=" .env >nul 2>&1
if %errorlevel% neq 0 (
    for /f %%K in ('node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"') do set "NEW_KEY=%%K"
    echo CAJAL_CONFIG_KEY=!NEW_KEY!>> .env
    echo   INFO: CAJAL_CONFIG_KEY auto-generated
)

findstr /B "CAJAL_DB_PASSWORD=" .env >nul 2>&1
if %errorlevel% neq 0 (
    for /f %%P in ('node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"') do set "NEW_PASS=%%P"
    echo CAJAL_DB_PASSWORD=!NEW_PASS!>> .env
    echo   INFO: CAJAL_DB_PASSWORD auto-generated
)

for /f "tokens=2 delims==" %%D in ('findstr /B "CAJAL_DB_PASSWORD=" .env') do (
    echo|set /p="%%D"> .db_password
    echo   INFO: .db_password synced from .env
)

findstr /B "CAJAL_WATCHTOWER_TOKEN=" .env >nul 2>&1
if %errorlevel% neq 0 (
    for /f %%T in ('node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"') do set "NEW_TOKEN=%%T"
    echo CAJAL_WATCHTOWER_TOKEN=!NEW_TOKEN!>> .env
    echo   INFO: CAJAL_WATCHTOWER_TOKEN auto-generated
)

:: ── Build and start ──────────────────────────────────────────────────────────
echo.
echo   Building and starting Cajal (this may take a few minutes)...
echo.
docker compose up -d --build
if %errorlevel% neq 0 (
    echo.
    echo   ERROR: Docker build failed. Check the output above.
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
