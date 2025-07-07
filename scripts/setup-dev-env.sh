#!/bin/bash
# Modern Development Environment Setup Script
# Sets up a complete development environment with best practices

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

print_header() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           DEVELOPMENT ENVIRONMENT SETUP                     ║"
    echo "║        Fedora Security Hardening Toolkit v1.0.0            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

check_python_version() {
    print_step "Checking Python Version"
    
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    local python_version
    python_version=$(python3 --version | cut -d' ' -f2)
    local major_version
    major_version=$(echo "$python_version" | cut -d'.' -f1)
    local minor_version
    minor_version=$(echo "$python_version" | cut -d'.' -f2)
    
    if [[ "$major_version" -lt 3 ]] || [[ "$major_version" -eq 3 && "$minor_version" -lt 8 ]]; then
        print_error "Python 3.8+ required, found $python_version"
        exit 1
    fi
    
    print_success "Python $python_version detected"
}

setup_virtual_environment() {
    print_step "Setting Up Virtual Environment"
    
    if [[ -d "venv" ]]; then
        print_warning "Virtual environment already exists"
        read -p "Remove existing venv and create new one? [y/N]: " -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf venv
        else
            print_success "Using existing virtual environment"
            return 0
        fi
    fi
    
    python3 -m venv venv
    print_success "Virtual environment created"
    
    # Activate virtual environment
    # shellcheck source=/dev/null
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel
    print_success "Virtual environment activated and pip upgraded"
}

install_dependencies() {
    print_step "Installing Dependencies"
    
    # Ensure we're in virtual environment
    if [[ -z "${VIRTUAL_ENV:-}" ]]; then
        print_warning "Activating virtual environment..."
        # shellcheck source=/dev/null
        source venv/bin/activate
    fi
    
    # Install development dependencies
    echo "Installing development dependencies..."
    pip install -r requirements-dev.txt
    
    # Install package in editable mode
    echo "Installing package in editable mode..."
    pip install -e .
    
    print_success "All dependencies installed"
}

setup_pre_commit() {
    print_step "Setting Up Pre-commit Hooks"
    
    if [[ -z "${VIRTUAL_ENV:-}" ]]; then
        # shellcheck source=/dev/null
        source venv/bin/activate
    fi
    
    # Install pre-commit hooks
    pre-commit install
    pre-commit install --hook-type commit-msg
    
    # Run pre-commit on all files to ensure everything works
    echo "Running pre-commit on all files..."
    pre-commit run --all-files || true
    
    print_success "Pre-commit hooks installed and configured"
}

setup_git_hooks() {
    print_step "Setting Up Additional Git Hooks"
    
    # Create git hooks directory if it doesn't exist
    mkdir -p .git/hooks
    
    # Create commit message template
    cat > .git/hooks/prepare-commit-msg << 'EOF'
#!/bin/bash
# Prepare commit message with conventional commit format

COMMIT_MSG_FILE=$1
COMMIT_SOURCE=$2

# Only add template for new commits (not amends, merges, etc.)
if [ -z "$COMMIT_SOURCE" ]; then
    # Add conventional commit template if message is empty
    if [ ! -s "$COMMIT_MSG_FILE" ]; then
        cat > "$COMMIT_MSG_FILE" << 'TEMPLATE'
# <type>(<scope>): <description>
#
# <body>
#
# <footer>
#
# Types: feat, fix, docs, style, refactor, test, chore, security
# Example: feat(audit): add SSH key rotation detection
TEMPLATE
    fi
fi
EOF
    
    chmod +x .git/hooks/prepare-commit-msg
    print_success "Git hooks configured"
}

setup_ide_configuration() {
    print_step "Setting Up IDE Configuration"
    
    # VS Code settings
    mkdir -p .vscode
    
    cat > .vscode/settings.json << 'EOF'
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.linting.flake8Enabled": true,
    "python.linting.mypyEnabled": true,
    "python.formatting.provider": "black",
    "python.sortImports.args": ["--profile", "black"],
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    },
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true,
        ".pytest_cache": true,
        ".mypy_cache": true,
        "htmlcov": true,
        ".coverage": true,
        "*.egg-info": true
    },
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["tests"],
    "shellcheck.enable": true,
    "shellcheck.executablePath": "shellcheck"
}
EOF
    
    # VS Code extensions recommendations
    cat > .vscode/extensions.json << 'EOF'
{
    "recommendations": [
        "ms-python.python",
        "ms-python.black-formatter",
        "ms-python.isort",
        "ms-python.pylint",
        "ms-python.mypy-type-checker",
        "timonwong.shellcheck",
        "redhat.vscode-yaml",
        "ms-vscode.makefile-tools",
        "github.vscode-github-actions",
        "ms-python.pytest"
    ]
}
EOF
    
    print_success "IDE configuration created"
}

run_initial_tests() {
    print_step "Running Initial Tests"
    
    if [[ -z "${VIRTUAL_ENV:-}" ]]; then
        # shellcheck source=/dev/null
        source venv/bin/activate
    fi
    
    # Run linting
    echo "Running code quality checks..."
    make lint || print_warning "Some linting issues found - check output above"
    
    # Run tests
    echo "Running test suite..."
    make test || print_warning "Some tests failed - check output above"
    
    # Run security scan
    echo "Running security scan..."
    make security-scan || print_warning "Security scan completed with warnings"
    
    print_success "Initial validation complete"
}

create_development_scripts() {
    print_step "Creating Development Scripts"
    
    mkdir -p scripts
    
    # Create quick test script
    cat > scripts/quick-test.sh << 'EOF'
#!/bin/bash
# Quick development test script
set -euo pipefail

echo "Running quick development tests..."

# Activate virtual environment
source venv/bin/activate

# Run unit tests only
python -m pytest tests/ -m "unit" -v --tb=short

# Run basic linting
black --check .
isort --check-only .
flake8 . --select=E9,F63,F7,F82

echo "Quick tests complete!"
EOF
    
    chmod +x scripts/quick-test.sh
    
    # Create development server script
    cat > scripts/dev-audit.sh << 'EOF'
#!/bin/bash
# Development audit script with verbose output
set -euo pipefail

# Activate virtual environment
source venv/bin/activate

echo "Running development security audit..."
python security_audit.py --verbose

echo "Development audit complete!"
EOF
    
    chmod +x scripts/dev-audit.sh
    
    print_success "Development scripts created"
}

display_next_steps() {
    print_step "Development Environment Ready!"
    
    echo -e "${GREEN}🎉 Development environment setup complete!${NC}"
    echo ""
    echo -e "${BOLD}Next steps:${NC}"
    echo "1. Activate virtual environment: ${CYAN}source venv/bin/activate${NC}"
    echo "2. Run tests: ${CYAN}make test${NC}"
    echo "3. Run linting: ${CYAN}make lint${NC}"
    echo "4. Quick development test: ${CYAN}./scripts/quick-test.sh${NC}"
    echo "5. Development audit: ${CYAN}./scripts/dev-audit.sh${NC}"
    echo ""
    echo -e "${BOLD}Available make commands:${NC}"
    echo "  ${CYAN}make help${NC}              - Show all available commands"
    echo "  ${CYAN}make install-dev${NC}       - Install development dependencies"
    echo "  ${CYAN}make test${NC}              - Run test suite"
    echo "  ${CYAN}make lint${NC}              - Run code quality checks"
    echo "  ${CYAN}make security-scan${NC}     - Run security analysis"
    echo "  ${CYAN}make clean${NC}             - Clean build artifacts"
    echo ""
    echo -e "${BOLD}Development workflow:${NC}"
    echo "1. Make changes to code"
    echo "2. Run ${CYAN}./scripts/quick-test.sh${NC} for rapid feedback"
    echo "3. Run ${CYAN}make check-all${NC} before committing"
    echo "4. Commit with conventional commit format"
    echo "5. Pre-commit hooks will run automatically"
    echo ""
    echo -e "${YELLOW}Happy coding! 🚀${NC}"
}

main() {
    print_header
    
    # Check if we're in the right directory
    if [[ ! -f "security_audit.py" ]]; then
        print_error "Please run this script from the project root directory"
        exit 1
    fi
    
    # Run setup steps
    check_python_version
    setup_virtual_environment
    install_dependencies
    setup_pre_commit
    setup_git_hooks
    setup_ide_configuration
    create_development_scripts
    run_initial_tests
    display_next_steps
}

# Run main function
main "$@"
