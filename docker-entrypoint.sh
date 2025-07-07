#!/bin/bash
# Docker entrypoint script for Fedora Security Hardening Toolkit
# Provides flexible container execution options

set -euo pipefail

# Default values
DEFAULT_COMMAND="python security_audit.py"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
AUDIT_OUTPUT_DIR="${AUDIT_OUTPUT_DIR:-/app/reports}"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $*${NC}" >&2
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*${NC}" >&2
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $*${NC}" >&2
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $*${NC}" >&2
}

# Function to display help
show_help() {
    cat << EOF
Fedora Security Hardening Toolkit - Docker Container

Usage: docker run [OPTIONS] fedora-security-toolkit [COMMAND] [ARGS...]

Commands:
  audit                 Run security audit (default)
  audit --verbose       Run verbose security audit
  hardening            Run security hardening (requires privileged mode)
  validation           Run security validation
  test                 Run test suite
  lint                 Run code quality checks
  shell                Start interactive shell
  help                 Show this help message

Environment Variables:
  LOG_LEVEL            Set logging level (DEBUG, INFO, WARNING, ERROR)
  AUDIT_OUTPUT_DIR     Directory for audit reports (default: /app/reports)
  DEVELOPMENT          Enable development mode (1 or 0)

Examples:
  # Run security audit
  docker run --rm fedora-security-toolkit

  # Run verbose audit with volume mount for reports
  docker run --rm -v \$(pwd)/reports:/app/reports fedora-security-toolkit audit --verbose

  # Run security hardening (requires privileged mode)
  docker run --rm --privileged -v /etc:/host/etc fedora-security-toolkit hardening

  # Start interactive shell for development
  docker run --rm -it fedora-security-toolkit shell

  # Run tests
  docker run --rm fedora-security-toolkit test

Security Notes:
  - For audit operations, no special privileges required
  - For hardening operations, use --privileged flag
  - Mount host directories as needed for configuration access
  - Reports are saved to /app/reports by default

EOF
}

# Function to setup environment
setup_environment() {
    log "Setting up container environment..."
    
    # Create output directory if it doesn't exist
    mkdir -p "$AUDIT_OUTPUT_DIR"
    
    # Set Python environment
    export PYTHONPATH="/app:${PYTHONPATH:-}"
    export PYTHONUNBUFFERED=1
    export PYTHONDONTWRITEBYTECODE=1
    
    # Set logging level
    export LOG_LEVEL="$LOG_LEVEL"
    
    log "Environment setup complete"
}

# Function to run security audit
run_audit() {
    log "Starting security audit..."
    
    local audit_args=("$@")
    
    # Ensure output directory exists
    mkdir -p "$AUDIT_OUTPUT_DIR"
    
    # Run the audit
    if python security_audit.py "${audit_args[@]}"; then
        log_success "Security audit completed successfully"
        
        # Copy reports to output directory if they exist
        if ls security_audit_report_*.json 1> /dev/null 2>&1; then
            cp security_audit_report_*.json "$AUDIT_OUTPUT_DIR/"
            log "Audit reports saved to $AUDIT_OUTPUT_DIR"
        fi
    else
        log_error "Security audit failed"
        return 1
    fi
}

# Function to run security hardening
run_hardening() {
    log "Starting security hardening..."
    
    # Check if running with sufficient privileges
    if [[ $EUID -ne 0 ]]; then
        log_error "Security hardening requires root privileges"
        log_error "Run container with --privileged flag or --user root"
        return 1
    fi
    
    # Check if host directories are mounted
    if [[ ! -d "/host/etc" ]]; then
        log_warning "Host /etc directory not mounted"
        log_warning "Mount with: -v /etc:/host/etc"
    fi
    
    # Run hardening script
    if ./security_hardening.sh "$@"; then
        log_success "Security hardening completed successfully"
    else
        log_error "Security hardening failed"
        return 1
    fi
}

# Function to run security validation
run_validation() {
    log "Starting security validation..."
    
    if ./security_validation.sh "$@"; then
        log_success "Security validation completed successfully"
    else
        log_error "Security validation failed"
        return 1
    fi
}

# Function to run tests
run_tests() {
    log "Running test suite..."
    
    if python -m pytest tests/ -v "$@"; then
        log_success "All tests passed"
    else
        log_error "Some tests failed"
        return 1
    fi
}

# Function to run linting
run_lint() {
    log "Running code quality checks..."
    
    local lint_failed=false
    
    # Run black
    if ! black --check --diff .; then
        log_error "Black formatting check failed"
        lint_failed=true
    fi
    
    # Run isort
    if ! isort --check-only --diff .; then
        log_error "Import sorting check failed"
        lint_failed=true
    fi
    
    # Run flake8
    if ! flake8 .; then
        log_error "Flake8 linting failed"
        lint_failed=true
    fi
    
    # Run shellcheck if available
    if command -v shellcheck &> /dev/null; then
        if ! find . -name "*.sh" -exec shellcheck {} \;; then
            log_error "ShellCheck failed"
            lint_failed=true
        fi
    fi
    
    if $lint_failed; then
        log_error "Code quality checks failed"
        return 1
    else
        log_success "All code quality checks passed"
    fi
}

# Function to start interactive shell
start_shell() {
    log "Starting interactive shell..."
    exec /bin/bash "$@"
}

# Main execution logic
main() {
    # Setup environment
    setup_environment
    
    # Handle empty arguments
    if [[ $# -eq 0 ]]; then
        log "No command specified, running default audit"
        run_audit
        return $?
    fi
    
    # Parse command
    local command="$1"
    shift
    
    case "$command" in
        "audit")
            run_audit "$@"
            ;;
        "hardening")
            run_hardening "$@"
            ;;
        "validation")
            run_validation "$@"
            ;;
        "test")
            run_tests "$@"
            ;;
        "lint")
            run_lint "$@"
            ;;
        "shell")
            start_shell "$@"
            ;;
        "help"|"--help"|"-h")
            show_help
            ;;
        "python")
            # Allow direct python execution
            exec python "$@"
            ;;
        "bash")
            # Allow direct bash execution
            exec bash "$@"
            ;;
        *)
            # Try to execute as direct command
            log "Executing command: $command $*"
            exec "$command" "$@"
            ;;
    esac
}

# Trap signals for graceful shutdown
trap 'log "Received signal, shutting down..."; exit 0' SIGTERM SIGINT

# Run main function
main "$@"
