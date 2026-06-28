#!/usr/bin/env bash
# scripts/arch_setup.sh
# ---------------------
# One-shot environment setup for Arch Linux.
#
# The problem: Arch ships Python 3.14 (rolling release).
# Two packages fail to build from source on 3.14:
#   • pydantic-core — uses PyO3 0.22.x, which only supports CPython ≤ 3.13
#   • tokenizers    — its bundled oniguruma C library triggers GCC 15 C23
#                     strict pointer-type errors
#
# The fix: use pyenv to install Python 3.12 (LTS, all packages have
# pre-built wheels, zero source compilation needed).
#
# Usage:
#   chmod +x scripts/arch_setup.sh
#   ./scripts/arch_setup.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_VERSION="3.12.10"   # latest stable 3.12 as of late 2025

# ── 0. Sanity check ───────────────────────────────────────────────────────────
info "Project directory: $PROJECT_DIR"
cd "$PROJECT_DIR"

current_py="$(python --version 2>&1 || true)"
info "System Python: $current_py"

# ── 1. Install pyenv if missing ───────────────────────────────────────────────
if ! command -v pyenv &>/dev/null; then
    warn "pyenv not found — installing via pacman..."
    # Try official Arch repos first (python-pyenv package)
    if sudo pacman -Sy --noconfirm pyenv 2>/dev/null; then
        info "pyenv installed via pacman."
    else
        warn "Not in official repos. Installing via pyenv-installer script..."
        curl https://pyenv.run | bash
        info "pyenv installed. You may need to add these lines to ~/.bashrc:"
        echo '  export PYENV_ROOT="$HOME/.pyenv"'
        echo '  export PATH="$PYENV_ROOT/bin:$PATH"'
        echo '  eval "$(pyenv init -)"'
        warn "Run: source ~/.bashrc   then re-run this script."
        exit 0
    fi
fi

# Make sure pyenv is initialised in this shell session
export PYENV_ROOT="${PYENV_ROOT:-$HOME/.pyenv}"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)" 2>/dev/null || true

info "pyenv version: $(pyenv --version)"

# ── 2. Install build dependencies for pyenv python compilation ────────────────
info "Installing Python build dependencies..."
sudo pacman -Sy --noconfirm --needed \
    base-devel \
    openssl \
    zlib \
    xz \
    tk \
    sqlite \
    readline \
    bzip2 \
    libffi \
    ncurses \
    2>/dev/null || warn "Some pacman packages may have failed — continuing anyway."

# ── 3. Install Python 3.12 via pyenv ─────────────────────────────────────────
if pyenv versions --bare | grep -q "^${PYTHON_VERSION}$"; then
    info "Python ${PYTHON_VERSION} already installed via pyenv."
else
    info "Installing Python ${PYTHON_VERSION} (this takes 2–5 minutes)..."
    pyenv install "${PYTHON_VERSION}"
    info "Python ${PYTHON_VERSION} installed."
fi

# ── 4. Pin the version for this project ──────────────────────────────────────
pyenv local "${PYTHON_VERSION}"
info "Pinned Python ${PYTHON_VERSION} for this project (wrote .python-version)."

# Verify
actual="$(python --version)"
info "Active Python: $actual"
if [[ "$actual" != *"3.12"* ]]; then
    error "pyenv local didn't take effect. Make sure pyenv init is in your shell config."
fi

# ── 5. Create virtual environment ─────────────────────────────────────────────
if [ -d ".venv" ]; then
    warn ".venv already exists. Removing and recreating with Python 3.12..."
    rm -rf .venv
fi

python -m venv .venv
info "Virtual environment created with: $(.venv/bin/python --version)"

# ── 6. Install dependencies ───────────────────────────────────────────────────
info "Installing Python dependencies (pre-built wheels preferred)..."
.venv/bin/pip install --upgrade pip setuptools wheel --quiet

# --prefer-binary: grab pre-built wheels instead of compiling from source.
# This is what avoids the PyO3 / GCC-15 compilation errors entirely.
.venv/bin/pip install \
    --prefer-binary \
    -r requirements.txt \
    --quiet

.venv/bin/pip install -e . --quiet
info "All dependencies installed."

# ── 7. Print next steps ───────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Environment ready!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Activate:   source .venv/bin/activate"
echo "  Then run:   cp .env.example .env"
echo "              ollama serve          # terminal 1"
echo "              ollama pull codellama:7b"
echo "              python scripts/setup_db.py"
echo "              streamlit run src/vuln_scanner/ui/app.py"
echo ""
