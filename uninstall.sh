#!/usr/bin/env bash
#
# SecretLens Uninstaller
# Removes all SecretLens installations
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }

INSTALL_DIR="$HOME/.secretlens"
GIT_TEMPLATE_DIR="$HOME/.git-templates"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    SecretLens Uninstaller                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

log_warn "This will remove:"
echo "  - $INSTALL_DIR"
echo "  - $GIT_TEMPLATE_DIR (git hooks template)"
echo "  - PATH modifications in ~/.bashrc, ~/.zshrc, ~/.profile"
echo "  - Desktop entry"
echo ""

read -p "Are you sure? [y/N] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Remove binary
rm -rf "$INSTALL_DIR"
log_success "Removed $INSTALL_DIR"

# Remove git template
rm -rf "$GIT_TEMPLATE_DIR"
log_success "Removed $GIT_TEMPLATE_DIR"

# Remove from PATH in shell configs
for rc_file in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [[ -f "$rc_file" ]]; then
        sed -i '/# SecretLens/,/secretlens\/bin/d' "$rc_file" 2>/dev/null || true
    fi
done
log_success "Removed PATH modifications"

# Remove desktop entry
rm -f "$HOME/.local/share/applications/secretlens.desktop"
log_success "Removed desktop entry"

echo ""
echo "Uninstallation complete!"
echo ""
