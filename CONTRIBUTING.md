# Contributing to Fedora Security Hardening Toolkit

Thank you for your interest in contributing to the Fedora Security Hardening Toolkit! This document provides guidelines for contributing to this project.

## 🎯 **Project Goals**

- Provide enterprise-grade security hardening for Fedora Linux systems
- Maintain cross-platform compatibility and hardware agnosticism
- Follow industry standards (CIS Controls v8, NIST Cybersecurity Framework)
- Ensure transparent, user-empowering security implementations
- Maintain production-grade code quality

## 🛠️ **Development Setup**

### Prerequisites
- Python 3.8 or higher
- Git
- Bash shell
- sudo access for testing security scripts

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/your-org/fedora-security-hardening-toolkit.git
cd fedora-security-hardening-toolkit

# Set up development environment
make dev-setup

# Verify setup
make check-all
```

## 📋 **Development Workflow**

### 1. Code Quality Standards
All code must pass our quality gates:

```bash
# Run all quality checks
make check-all

# Individual checks
make lint          # Code linting
make format        # Code formatting
make test          # Test suite
make security-scan # Security analysis
```

### 2. Pre-commit Hooks
We use pre-commit hooks to ensure code quality:

```bash
# Install pre-commit hooks (done automatically in dev-setup)
pre-commit install

# Run hooks manually
pre-commit run --all-files
```

### 3. Testing Requirements
- All Python code must have type hints
- Shell scripts must pass ShellCheck
- Security scripts must be tested in isolated environments
- New features require corresponding tests

## 🔒 **Security Guidelines**

### Code Security
- Never hardcode credentials or sensitive data
- Use secure defaults for all configurations
- Validate all user inputs
- Follow principle of least privilege
- Document security implications of changes

### Testing Security Scripts
- Test in isolated VMs or containers
- Never test on production systems
- Verify rollback procedures work
- Document any system changes made during testing

## 📝 **Coding Standards**

### Python Code
- Follow PEP 8 style guide
- Use type hints for all functions
- Maximum line length: 100 characters
- Use docstrings for all public functions
- Handle exceptions gracefully

Example:
```python
def audit_security_control(
    control_name: str, 
    check_function: Callable[[], bool]
) -> Dict[str, Union[str, bool]]:
    """
    Audit a specific security control.
    
    Args:
        control_name: Name of the security control
        check_function: Function that returns True if control is properly configured
        
    Returns:
        Dictionary with audit results
        
    Raises:
        SecurityAuditError: If audit cannot be completed
    """
    try:
        result = check_function()
        return {
            'control': control_name,
            'status': 'PASS' if result else 'FAIL',
            'compliant': result
        }
    except Exception as e:
        raise SecurityAuditError(f"Failed to audit {control_name}: {e}")
```

### Shell Script Standards
- Use `set -euo pipefail` for error handling
- Quote all variables
- Use functions for reusable code
- Provide comprehensive error messages
- Include rollback procedures

Example:
```bash
#!/bin/bash
set -euo pipefail

configure_security_control() {
    local control_name="$1"
    local config_file="$2"
    
    # Validate inputs
    if [[ -z "$control_name" ]] || [[ -z "$config_file" ]]; then
        print_error "Missing required parameters"
        return 1
    fi
    
    # Create backup before changes
    backup_config "$config_file"
    
    # Apply configuration with error handling
    if ! apply_security_config "$control_name" "$config_file"; then
        print_error "Failed to configure $control_name"
        restore_backup "$config_file"
        return 1
    fi
    
    print_success "Successfully configured $control_name"
}
```

## 🧪 **Testing Guidelines**

### Unit Tests
- Test individual functions in isolation
- Mock external dependencies
- Cover both success and failure cases
- Use descriptive test names

### Integration Tests
- Test complete workflows
- Use isolated test environments
- Verify rollback procedures
- Test cross-platform compatibility

### Security Tests
- Validate security controls are effective
- Test against known attack patterns
- Verify compliance with standards
- Test in various system configurations

## 📚 **Documentation Standards**

### Code Documentation
- All public functions must have docstrings
- Include type hints for parameters and return values
- Document security implications
- Provide usage examples

### User Documentation
- Update README.md for new features
- Include step-by-step instructions
- Explain security benefits
- Provide troubleshooting guidance

## 🚀 **Submission Process**

### 1. Fork and Branch
```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/your-username/fedora-security-hardening-toolkit.git

# Create feature branch
git checkout -b feature/your-feature-name
```

### 2. Development
```bash
# Make your changes
# Run quality checks
make check-all

# Commit with descriptive message
git commit -m "feat: add SSH key rotation automation

- Implement automated SSH key rotation
- Add compliance check for key age
- Include rollback procedure for failed rotations
- Update documentation with usage examples"
```

### 3. Testing
```bash
# Test in isolated environment
# Verify all quality checks pass
make production-ready

# Test cross-platform compatibility if applicable
```

### 4. Pull Request
- Create pull request with clear description
- Reference any related issues
- Include testing evidence
- Request review from maintainers

## 🏷️ **Commit Message Format**

Use conventional commits format:
```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

Examples:
```
feat(audit): add SELinux compliance checking
fix(hardening): resolve SSH configuration backup issue
docs(readme): update installation instructions
```

## 🐛 **Bug Reports**

When reporting bugs, include:
- System information (distribution, version, architecture)
- Steps to reproduce
- Expected vs actual behavior
- Error messages and logs
- Security implications (if any)

## 💡 **Feature Requests**

For new features, provide:
- Use case description
- Security benefits
- Compliance framework alignment
- Implementation approach
- Testing strategy

## 📞 **Getting Help**

- Check existing issues and documentation
- Join our community discussions
- Contact maintainers for security-sensitive issues

## 🙏 **Recognition**

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for helping make Fedora systems more secure! 🛡️
