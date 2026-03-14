#!/usr/bin/env bash
#
# SecretLens Installer
# Installs the SecretLens engine and git hooks globally
#

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ─── Constants ─────────────────────────────────────────────────────────────
INSTALL_DIR="$HOME/.secretlens"
BIN_DIR="$INSTALL_DIR/bin"
GIT_TEMPLATE_DIR="$HOME/.git-templates"
HOOKS_DIR="$GIT_TEMPLATE_DIR/hooks"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Helpers ─────────────────────────────────────────────────────────────
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║            SecretLens Installer v1.0.0                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --engine          Install the SecretLens engine (default: yes)"
    echo "  --hooks           Install git hooks globally (default: yes)"
    echo "  --desktop         Install desktop app shortcut (default: no)"
    echo "  --path            Add to PATH in shell config (default: yes)"
    echo "  --uninstall       Uninstall SecretLens"
    echo "  --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                  # Install everything"
    echo "  $0 --engine --hooks # Install engine and hooks only"
    echo "  $0 --uninstall      # Uninstall everything"
}

# ─── Prerequisites ───────────────────────────────────────────────────────
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v git &>/dev/null; then
        log_error "Git is not installed. Please install Git first."
        exit 1
    fi

    # Check if running from repo root
    if [[ ! -f "$SCRIPT_DIR/Cargo.toml" ]]; then
        log_warn "Not running from SecretLens repository root."
        log_warn "Some features may not work correctly."
    fi

    log_success "Prerequisites check passed"
}

# ─── Build Engine ───────────────────────────────────────────────────────
build_engine() {
    log_info "Building SecretLens engine..."

    if [[ -f "$SCRIPT_DIR/target/release/secretlens" ]]; then
        log_info "Binary already exists, skipping build."
        return 0
    fi

    if [[ ! -f "$SCRIPT_DIR/Cargo.toml" ]]; then
        log_error "Cannot build: Cargo.toml not found in $SCRIPT_DIR"
        log_error "Please run this script from the SecretLens repository root."
        exit 1
    fi

    log_info "Building release binary (this may take a few minutes)..."
    if command -v cargo &>/dev/null; then
        cd "$SCRIPT_DIR"
        cargo build --release 2>&1
    else
        log_error "Cargo not found. Please install Rust: https://rustup.rs/"
        exit 1
    fi

    log_success "Engine built successfully"
}

# ─── Install Engine ─────────────────────────────────────────────────────
install_engine() {
    log_info "Installing SecretLens engine to $BIN_DIR..."

    mkdir -p "$BIN_DIR"

    local binary_path=""
    if [[ -f "$SCRIPT_DIR/target/release/secretlens" ]]; then
        binary_path="$SCRIPT_DIR/target/release/secretlens"
    elif [[ -f "$SCRIPT_DIR/target/debug/secretlens" ]]; then
        binary_path="$SCRIPT_DIR/target/debug/secretlens"
    elif command -v secretlens &>/dev/null; then
        log_info "Using system-installed secretlens"
        return 0
    else
        log_error "SecretLens binary not found. Please build first."
        exit 1
    fi

    cp "$binary_path" "$BIN_DIR/secretlens"
    chmod +x "$BIN_DIR/secretlens"

    # Copy rules directory
    if [[ -d "$SCRIPT_DIR/rules" ]]; then
        mkdir -p "$BIN_DIR"
        cp -r "$SCRIPT_DIR/rules" "$BIN_DIR/"
        log_info "Copied rules directory"
    fi

    log_success "Engine installed to $BIN_DIR/secretlens"
}

# ─── Install Git Hooks ──────────────────────────────────────────────────
install_hooks() {
    log_info "Installing git hooks globally..."

    # Create git template directory
    mkdir -p "$HOOKS_DIR"

    # Copy pre-commit hook
    if [[ -f "$SCRIPT_DIR/hooks/pre-commit" ]]; then
        cp "$SCRIPT_DIR/hooks/pre-commit" "$HOOKS_DIR/"
        chmod +x "$HOOKS_DIR/pre-commit"
        log_success "Hook installed to $HOOKS_DIR/pre-commit"
    else
        log_error "Hook file not found at $SCRIPT_DIR/hooks/pre-commit"
        exit 1
    fi

    # Configure git to use template directory
    if [[ "$(git config --global init.templateDir 2>/dev/null)" != "$GIT_TEMPLATE_DIR" ]]; then
        git config --global init.templateDir "$GIT_TEMPLATE_DIR"
        log_info "Configured git to use template directory"
    fi

    log_success "Git hooks configured"
    echo ""
    log_info "Note: Existing repositories need to re-initialize:"
    echo "       cd <your-repo> && git init"
}

# ─── Add to PATH ─────────────────────────────────────────────────────────
add_to_path() {
    log_info "Adding SecretLens to PATH..."

    local shell_config=""
    local rc_file=""

    if [[ -n "${BASH_VERSION:-}" ]]; then
        rc_file="$HOME/.bashrc"
    elif [[ -n "${ZSH_VERSION:-}" ]]; then
        rc_file="$HOME/.zshrc"
    else
        rc_file="$HOME/.profile"
    fi

    local path_line="export PATH=\"\$HOME/.secretlens/bin:\$PATH\""

    if grep -q "$BIN_DIR" "$rc_file" 2>/dev/null; then
        log_info "PATH already configured in $rc_file"
    else
        echo "" >> "$rc_file"
        echo "# SecretLens" >> "$rc_file"
        echo "$path_line" >> "$rc_file"
        log_success "Added to PATH in $rc_file"
    fi

    # Also add to current shell
    export PATH="$BIN_DIR:$PATH"

    log_success "PATH configured"
}

# ─── Install Desktop App ───────────────────────────────────────────────
install_desktop_app() {
    log_info "Setting up desktop app..."

    if [[ ! -d "$SCRIPT_DIR/desktop" ]]; then
        log_warn "Desktop app not found. Skipping."
        return 0
    fi

    # Create desktop entry
    local desktop_entry="$HOME/.local/share/applications/secretlens.desktop"
    mkdir -p "$(dirname "$desktop_entry")"

    cat > "$desktop_entry" << EOF
[Desktop Entry]
Name=SecretLens
Comment=AI-Powered Pre-Commit Security Guardian
Exec=$SCRIPT_DIR/desktop/secretlens-desktop
Icon=$SCRIPT_DIR/desktop/resources/icon.png
Terminal=false
Type=Application
Categories=Development;Security;
EOF

    log_success "Desktop entry created"
}

# ─── Uninstall ──────────────────────────────────────────────────────────
uninstall() {
    log_warn "Uninstalling SecretLens..."

    # Remove binary
    rm -rf "$INSTALL_DIR"
    log_info "Removed $INSTALL_DIR"

    # Remove git template hook
    rm -rf "$GIT_TEMPLATE_DIR"
    log_info "Removed $GIT_TEMPLATE_DIR"

    # Remove from PATH in shell configs
    for rc_file in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [[ -f "$rc_file" ]]; then
            sed -i '/# SecretLens/,/secretlens\/bin/d' "$rc_file" 2>/dev/null || true
        fi
    done

    # Remove desktop entry
    rm -f "$HOME/.local/share/applications/secretlens.desktop"

    log_success "Uninstallation complete"
}

# ─── Verify Installation ───────────────────────────────────────────────
verify_installation() {
    log_info "Verifying installation..."

    if [[ ! -x "$BIN_DIR/secretlens" ]]; then
        log_error "Engine binary not found or not executable"
        exit 1
    fi

    # Test engine
    if echo '{"command":"analyze","payload":{"files":[{"filePath":"test.py","content":"print(1)"}]}}' \
        | "$BIN_DIR/secretlens" --mode pipe --format json 2>/dev/null \
        | grep -q "status"; then
        log_success "Engine works correctly"
    else
        log_error "Engine test failed"
        exit 1
    fi

    log_success "Installation verified!"
}

# ─── Main ───────────────────────────────────────────────────────────────
main() {
    local install_engine_flag=true
    local install_hooks_flag=true
    local install_desktop_flag=false
    local add_path_flag=true
    local uninstall_flag=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --engine)
                install_engine_flag=true
                shift
                ;;
            --hooks)
                install_hooks_flag=true
                shift
                ;;
            --desktop)
                install_desktop_flag=true
                shift
                ;;
            --path)
                add_path_flag=true
                shift
                ;;
            --uninstall)
                uninstall_flag=true
                shift
                ;;
            --help|-h)
                print_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done

    print_header

    if [[ "$uninstall_flag" == true ]]; then
        uninstall
        exit 0
    fi

    check_prerequisites

    if [[ "$install_engine_flag" == true ]]; then
        if [[ -f "$SCRIPT_DIR/Cargo.toml" ]]; then
            build_engine
        fi
        install_engine
    fi

    if [[ "$install_hooks_flag" == true ]]; then
        install_hooks
    fi

    if [[ "$add_path_flag" == true ]]; then
        add_to_path
    fi

    if [[ "$install_desktop_flag" == true ]]; then
        install_desktop_app
    fi

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    INSTALLATION COMPLETE                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Next steps:"
    echo "  1. Restart your terminal or run: source ~/.bashrc"
    echo "  2. For existing repos, run: git init"
    echo "  3. Test with: secretlens --help"
    echo ""
}

main "$@"
