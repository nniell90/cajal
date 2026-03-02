#!/usr/bin/env bash
set -euo pipefail

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║       Cajal ICBM Installer           ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# ── Detect OS ────────────────────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID="${ID:-unknown}"
else
  OS_ID="unknown"
fi

if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" && "$OS_ID" != "kubuntu" ]]; then
  echo "WARNING: This script is designed for Ubuntu/Debian/Kubuntu."
  echo "         Detected: $OS_ID. Proceeding anyway..."
  echo ""
fi

# ── Helper: check if command exists ──────────────────────────────────────────
need_install() { ! command -v "$1" >/dev/null 2>&1; }

# ── Install Git ──────────────────────────────────────────────────────────────
if need_install git; then
  echo "Installing git..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq git >/dev/null
  echo "  git installed."
else
  echo "  git already installed."
fi

# ── Install Node.js 20 ──────────────────────────────────────────────────────
if need_install node; then
  echo "Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >/dev/null 2>&1
  sudo apt-get install -y -qq nodejs >/dev/null
  echo "  Node.js $(node --version) installed."
else
  NODE_MAJOR=$(node --version | cut -d. -f1 | tr -d 'v')
  if [ "$NODE_MAJOR" -lt 20 ]; then
    echo "  Node.js $(node --version) found but v20+ required. Upgrading..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >/dev/null 2>&1
    sudo apt-get install -y -qq nodejs >/dev/null
    echo "  Node.js $(node --version) installed."
  else
    echo "  Node.js $(node --version) already installed."
  fi
fi

# ── Install Docker ───────────────────────────────────────────────────────────
if need_install docker; then
  echo "Installing Docker..."
  curl -fsSL https://get.docker.com | sudo sh >/dev/null 2>&1
  sudo usermod -aG docker "$USER" 2>/dev/null || true
  echo "  Docker installed."
  echo ""
  echo "  NOTE: You may need to log out and back in for Docker"
  echo "        permissions to take effect. If the build fails,"
  echo "        log out, log back in, and re-run this script."
  echo ""
else
  echo "  Docker already installed."
fi

# ── Install Docker Compose plugin (if missing) ──────────────────────────────
if ! docker compose version >/dev/null 2>&1; then
  echo "Installing Docker Compose plugin..."
  sudo apt-get install -y -qq docker-compose-plugin >/dev/null 2>&1 || true
  if docker compose version >/dev/null 2>&1; then
    echo "  Docker Compose plugin installed."
  else
    echo "  Docker Compose plugin not available (fallback mode will be used)."
  fi
else
  echo "  Docker Compose already installed."
fi

# ── Clone Cajal ──────────────────────────────────────────────────────────────
INSTALL_DIR="${HOME}/cajal"

if [ -d "$INSTALL_DIR" ]; then
  echo "  $INSTALL_DIR already exists. Pulling latest..."
  cd "$INSTALL_DIR"
  git pull --ff-only || true
else
  echo "Cloning Cajal..."
  git clone https://github.com/nniell90/cajal.git "$INSTALL_DIR"
  cd "$INSTALL_DIR"
  echo "  Cloned to $INSTALL_DIR"
fi

# ── Build and start ─────────────────────────────────────────────────────────
echo ""
echo "Building and starting Cajal..."
echo ""
bash docker-reload.sh rebuild

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║     Installation complete!           ║"
echo "  ║                                      ║"
echo "  ║  Open: http://localhost:4000         ║"
echo "  ║                                      ║"
echo "  ║  Create your admin account on        ║"
echo "  ║  first login.                        ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
