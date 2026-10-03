#!/usr/bin/env bash
# ==============================================================================
# SentinOps Environment Bootstrapper & Pre-flight Diagnostics
# ==============================================================================
set -euo pipefail

# Color Codes for Terminal Output
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1${NC}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS] $(date +'%Y-%m-%d %H:%M:%S') - $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}[WARN] $(date +'%Y-%m-%d %H:%M:%S') - $1${NC}"
}

log_error() {
    echo -e "${RED}[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1${NC}"
}

# Trap unexpected errors
trap 'log_error "Bootstrap script failed on line $LINENO. Exiting."' ERR

main() {
    log_info "=========================================================="
    log_info "    SENTINOPS AIOPS PLATFORM BOOTSTRAP INITIALIZATION     "
    log_info "=========================================================="

    # Verify Operating System Architecture
    local os_type
    os_type=$(uname -s)
    log_info "Detected Host OS: ${os_type} ($(uname -m))"

    # Verify Python Runtime
    if command -v python3 >/dev/null 2>&1; then
        local py_ver
        py_ver=$(python3 --version)
        log_success "Python environment found: ${py_ver}"
    else
        log_error "Python 3 is required but not installed."
        exit 1
    fi

    # Verify Ansible availability (optional / pluggable)
    if command -v ansible-playbook >/dev/null 2>&1; then
        log_success "Ansible CLI detected: $(ansible-playbook --version | head -n 1)"
    else
        log_warn "Ansible CLI not found in system PATH. Enabling High-Fidelity Emulated Execution Engine."
    fi

    # Verify Database directory and permissions
    mkdir -p data/ logs/
    log_success "Data & Logging directories initialized."

    log_success "Pre-flight checks passed successfully. SentinOps is ready to start."
}

main "$@"
