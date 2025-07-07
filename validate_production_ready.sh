#!/bin/bash
# Production Readiness Validation Script
# Ensures all components meet production-grade standards

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

print_header() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           PRODUCTION READINESS VALIDATION                   ║"
    echo "║        Fedora Security Hardening Toolkit v1.0.0            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${BOLD}${YELLOW}=== $1 ===${NC}"
}

print_pass() {
    echo -e "${GREEN}✅ $1${NC}"
    ((PASSED_CHECKS++))
    ((TOTAL_CHECKS++))
}

print_fail() {
    echo -e "${RED}❌ $1${NC}"
    ((FAILED_CHECKS++))
    ((TOTAL_CHECKS++))
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

check_file_exists() {
    local file="$1"
    local description="$2"
    
    if [[ -f "$file" ]]; then
        print_pass "$description exists: $file"
        return 0
    else
        print_fail "$description missing: $file"
        return 1
    fi
}

check_executable() {
    local file="$1"
    local description="$2"
    
    if [[ -x "$file" ]]; then
        print_pass "$description is executable: $file"
        return 0
    else
        print_fail "$description not executable: $file"
        return 1
    fi
}

validate_python_syntax() {
    print_section "PYTHON SYNTAX VALIDATION"
    
    local python_files=("security_audit.py")
    
    for file in "${python_files[@]}"; do
        if [[ -f "$file" ]]; then
            if python3 -m py_compile "$file" 2>/dev/null; then
                print_pass "Python syntax valid: $file"
            else
                print_fail "Python syntax error: $file"
            fi
        else
            print_fail "Python file missing: $file"
        fi
    done
}

validate_shell_syntax() {
    print_section "SHELL SCRIPT SYNTAX VALIDATION"
    
    local shell_files=("security_hardening.sh" "security_validation.sh" "validate_production_ready.sh")
    
    for file in "${shell_files[@]}"; do
        if [[ -f "$file" ]]; then
            if bash -n "$file" 2>/dev/null; then
                print_pass "Shell syntax valid: $file"
            else
                print_fail "Shell syntax error: $file"
            fi
        else
            print_fail "Shell script missing: $file"
        fi
    done
}

validate_shellcheck() {
    print_section "SHELLCHECK VALIDATION"
    
    if ! command -v shellcheck &> /dev/null; then
        print_info "ShellCheck not available - skipping advanced shell validation"
        return 0
    fi
    
    local shell_files=("security_hardening.sh" "security_validation.sh")
    local shellcheck_passed=true
    
    for file in "${shell_files[@]}"; do
        if [[ -f "$file" ]]; then
            # Run shellcheck and capture output
            local shellcheck_output
            if shellcheck_output=$(shellcheck "$file" 2>&1); then
                print_pass "ShellCheck passed: $file"
            else
                # Count only errors, not warnings
                local error_count
                error_count=$(echo "$shellcheck_output" | grep -c "error:" || echo "0")
                if [[ "$error_count" -eq 0 ]]; then
                    print_pass "ShellCheck passed (warnings only): $file"
                else
                    print_fail "ShellCheck errors in: $file ($error_count errors)"
                    shellcheck_passed=false
                fi
            fi
        fi
    done
    
    if $shellcheck_passed; then
        print_pass "All shell scripts pass ShellCheck validation"
    fi
}

validate_documentation() {
    print_section "DOCUMENTATION VALIDATION"
    
    local required_docs=(
        "README.md:Main documentation"
        "LICENSE:License file"
        "CONTRIBUTING.md:Contribution guidelines"
        "CHANGELOG.md:Change log"
    )
    
    for doc_spec in "${required_docs[@]}"; do
        local file="${doc_spec%:*}"
        local description="${doc_spec#*:}"
        check_file_exists "$file" "$description"
    done
    
    # Check README completeness
    if [[ -f "README.md" ]]; then
        local required_sections=(
            "What This Toolkit Does"
            "Quick Start"
            "Installation"
            "Security"
            "Troubleshooting"
        )
        
        for section in "${required_sections[@]}"; do
            if grep -q "$section" README.md; then
                print_pass "README contains section: $section"
            else
                print_fail "README missing section: $section"
            fi
        done
    fi
}

validate_configuration_files() {
    print_section "CONFIGURATION FILES VALIDATION"
    
    local config_files=(
        "pyproject.toml:Python project configuration"
        ".pylintrc:Python linting configuration"
        ".pre-commit-config.yaml:Pre-commit hooks configuration"
        "Makefile:Build and development commands"
        "setup.py:Python package setup"
        "VERSION:Version information"
    )
    
    for config_spec in "${config_files[@]}"; do
        local file="${config_spec%:*}"
        local description="${config_spec#*:}"
        check_file_exists "$file" "$description"
    done
}

validate_github_workflows() {
    print_section "GITHUB WORKFLOWS VALIDATION"
    
    if [[ -d ".github/workflows" ]]; then
        print_pass "GitHub workflows directory exists"
        
        if [[ -f ".github/workflows/ci.yml" ]]; then
            print_pass "CI/CD workflow configuration exists"
            
            # Check for required workflow components
            local required_jobs=("lint" "security" "test" "build")
            for job in "${required_jobs[@]}"; do
                if grep -q "$job:" .github/workflows/ci.yml; then
                    print_pass "CI workflow includes job: $job"
                else
                    print_fail "CI workflow missing job: $job"
                fi
            done
        else
            print_fail "CI/CD workflow configuration missing"
        fi
    else
        print_fail "GitHub workflows directory missing"
    fi
}

validate_script_permissions() {
    print_section "SCRIPT PERMISSIONS VALIDATION"
    
    local executable_files=(
        "security_hardening.sh:Security hardening script"
        "security_validation.sh:Security validation script"
        "validate_production_ready.sh:Production validation script"
    )
    
    for file_spec in "${executable_files[@]}"; do
        local file="${file_spec%:*}"
        local description="${file_spec#*:}"
        
        if [[ -f "$file" ]]; then
            check_executable "$file" "$description"
        else
            print_fail "Executable file missing: $file"
        fi
    done
}

validate_python_imports() {
    print_section "PYTHON IMPORT VALIDATION"
    
    if [[ -f "security_audit.py" ]]; then
        # Test that the script can be imported without errors
        if python3 -c "import security_audit" 2>/dev/null; then
            print_pass "Python script imports successfully"
        else
            print_fail "Python script import failed"
        fi
        
        # Test command line interface
        if python3 security_audit.py --help &>/dev/null; then
            print_pass "Python script CLI works"
        else
            print_fail "Python script CLI failed"
        fi
    fi
}

validate_cross_platform_compatibility() {
    print_section "CROSS-PLATFORM COMPATIBILITY"
    
    # Check for hardcoded paths that might not work across distributions
    local problematic_patterns=(
        "/etc/redhat-release"
        "/etc/debian_version"
        "yum install"
        "apt-get install"
    )
    
    local compatibility_issues=false
    
    for pattern in "${problematic_patterns[@]}"; do
        if grep -r "$pattern" . --include="*.py" --include="*.sh" &>/dev/null; then
            print_fail "Found distribution-specific code: $pattern"
            compatibility_issues=true
        fi
    done
    
    if ! $compatibility_issues; then
        print_pass "No obvious cross-platform compatibility issues found"
    fi
    
    # Check for proper package manager abstraction
    if grep -q "get_package_manager" security_hardening.sh; then
        print_pass "Package manager abstraction implemented"
    else
        print_fail "Package manager abstraction missing"
    fi
}

generate_summary() {
    print_section "VALIDATION SUMMARY"
    
    local success_rate=0
    if [[ $TOTAL_CHECKS -gt 0 ]]; then
        success_rate=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
    fi
    
    echo -e "${BOLD}Validation Results:${NC}"
    echo "==================="
    echo "Total Checks: $TOTAL_CHECKS"
    echo -e "${GREEN}Passed: $PASSED_CHECKS${NC}"
    echo -e "${RED}Failed: $FAILED_CHECKS${NC}"
    echo "Success Rate: ${success_rate}%"
    
    if [[ $FAILED_CHECKS -eq 0 ]]; then
        echo -e "\n${GREEN}🎉 ALL VALIDATIONS PASSED!${NC}"
        echo -e "${GREEN}Repository is production-ready!${NC}"
        return 0
    elif [[ $success_rate -ge 90 ]]; then
        echo -e "\n${YELLOW}⚠️  Minor issues detected (${success_rate}% success rate)${NC}"
        echo -e "${YELLOW}Repository is mostly production-ready${NC}"
        return 1
    else
        echo -e "\n${RED}❌ Significant issues detected (${success_rate}% success rate)${NC}"
        echo -e "${RED}Repository needs attention before production use${NC}"
        return 1
    fi
}

main() {
    print_header
    
    # Run all validation checks
    validate_python_syntax
    validate_shell_syntax
    validate_shellcheck
    validate_documentation
    validate_configuration_files
    validate_github_workflows
    validate_script_permissions
    validate_python_imports
    validate_cross_platform_compatibility
    
    # Generate final summary
    generate_summary
}

# Run main function
main "$@"
