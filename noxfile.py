"""
Nox configuration for Fedora Security Hardening Toolkit
Modern Python testing and automation with Nox
"""

import nox

# Supported Python versions
PYTHON_VERSIONS = ["3.8", "3.9", "3.10", "3.11", "3.12"]
LINT_PYTHON_VERSION = "3.11"

# Nox options
nox.options.error_on_missing_interpreters = False
nox.options.reuse_existing_virtualenvs = True
nox.options.sessions = ["lint", "type_check", "security", "tests"]


@nox.session(python=PYTHON_VERSIONS)
def tests(session):
    """Run the test suite with pytest."""
    session.install("-r", "requirements-test.txt")
    session.run(
        "pytest",
        "--cov=.",
        "--cov-report=term-missing",
        "--cov-report=html",
        "--cov-report=xml",
        "tests/",
        *session.posargs
    )


@nox.session(python=LINT_PYTHON_VERSION)
def lint(session):
    """Run linting tools."""
    session.install("-r", "requirements-dev.txt")
    
    # Python code formatting and linting
    session.run("black", "--check", "--diff", ".")
    session.run("isort", "--check-only", "--diff", ".")
    session.run("flake8", ".")
    session.run("pylint", "security_audit.py")
    
    # Shell script linting
    session.run("shellcheck", "security_hardening.sh", "security_validation.sh")


@nox.session(python=LINT_PYTHON_VERSION)
def format_code(session):
    """Format code with black and isort."""
    session.install("-r", "requirements-dev.txt")
    session.run("black", ".")
    session.run("isort", ".")


@nox.session(python=LINT_PYTHON_VERSION)
def type_check(session):
    """Run type checking with mypy."""
    session.install("-r", "requirements-dev.txt")
    session.run("mypy", "security_audit.py", "--strict", "--show-error-codes")


@nox.session(python=LINT_PYTHON_VERSION)
def security(session):
    """Run security scanning tools."""
    session.install("-r", "requirements-dev.txt")
    
    # Python security scanning
    session.run("bandit", "-r", ".", "--severity-level", "medium")
    session.run("safety", "check")
    
    # Note: Advanced security scanning tools like semgrep can be added here
    session.log("Basic security scanning complete")


@nox.session(python=LINT_PYTHON_VERSION)
def docs(session):
    """Build documentation."""
    session.install("-r", "requirements-dev.txt")
    session.run("sphinx-build", "-W", "-b", "html", "docs", "docs/_build/html")


@nox.session(python=LINT_PYTHON_VERSION)
def coverage(session):
    """Generate coverage report."""
    session.install("-r", "requirements-test.txt")
    session.run(
        "pytest",
        "--cov=.",
        "--cov-report=html",
        "--cov-report=xml",
        "--cov-report=term",
        "--cov-fail-under=80",
        "tests/"
    )


@nox.session(python=LINT_PYTHON_VERSION)
def performance(session):
    """Run performance benchmarks."""
    session.install("-r", "requirements-test.txt")
    session.run(
        "pytest",
        "tests/performance/",
        "--benchmark-only",
        "--benchmark-sort=mean",
        *session.posargs
    )


@nox.session(python=LINT_PYTHON_VERSION)
def integration(session):
    """Run integration tests."""
    session.install("-r", "requirements-test.txt")
    session.env["INTEGRATION_TESTS"] = "1"
    session.run("pytest", "tests/integration/", "-v", "--tb=long", *session.posargs)


@nox.session(python=LINT_PYTHON_VERSION)
def build(session):
    """Build distribution packages."""
    session.install("build", "twine")
    session.run("python", "-m", "build")
    session.run("twine", "check", "dist/*")


@nox.session(python=LINT_PYTHON_VERSION)
def deps_update(session):
    """Update dependencies."""
    session.install("pip-tools")
    session.run("pip-compile", "--upgrade", "requirements.in")
    session.run("pip-compile", "--upgrade", "requirements-dev.in")
    session.run("pip-compile", "--upgrade", "requirements-test.in")


@nox.session(python=LINT_PYTHON_VERSION)
def deps_check(session):
    """Check for dependency vulnerabilities."""
    session.install("-r", "requirements-dev.txt")
    session.run("safety", "check")
    session.run("pip-audit")


@nox.session(python=LINT_PYTHON_VERSION)
def clean(session):
    """Clean up build artifacts and cache files."""
    import shutil
    import os
    
    dirs_to_clean = [
        "build",
        "dist", 
        ".pytest_cache",
        "htmlcov",
        ".coverage*",
        ".mypy_cache",
        "__pycache__",
        "*.egg-info"
    ]
    
    for dir_pattern in dirs_to_clean:
        try:
            if "*" in dir_pattern:
                import glob
                for path in glob.glob(dir_pattern):
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
            else:
                if os.path.exists(dir_pattern):
                    if os.path.isdir(dir_pattern):
                        shutil.rmtree(dir_pattern)
                    else:
                        os.remove(dir_pattern)
            session.log(f"Cleaned: {dir_pattern}")
        except Exception as e:
            session.log(f"Could not clean {dir_pattern}: {e}")


@nox.session(python=PYTHON_VERSIONS)
def cross_platform_test(session):
    """Test across different Python versions."""
    session.install("-r", "requirements-test.txt")
    session.run("python", "--version")
    session.run("pytest", "tests/", "-v", "--tb=short")


@nox.session(python=LINT_PYTHON_VERSION)
def pre_commit(session):
    """Run pre-commit hooks."""
    session.install("pre-commit")
    session.run("pre-commit", "run", "--all-files")


@nox.session(python=LINT_PYTHON_VERSION)
def validate_production(session):
    """Validate production readiness."""
    session.install("-r", "requirements-dev.txt")
    
    # Run all quality checks
    session.run("black", "--check", ".")
    session.run("isort", "--check-only", ".")
    session.run("flake8", ".")
    session.run("mypy", "security_audit.py", "--strict")
    session.run("bandit", "-r", ".")
    session.run("safety", "check")
    
    # Run tests
    session.run("pytest", "tests/", "--cov=.", "--cov-fail-under=80")
    
    # Validate shell scripts
    session.run("shellcheck", "security_hardening.sh", "security_validation.sh")
    
    session.log("✅ All production readiness checks passed!")


@nox.session(python=LINT_PYTHON_VERSION)
def release_check(session):
    """Check if ready for release."""
    session.install("-r", "requirements-dev.txt")
    session.install("build", "twine")
    
    # Build and check distribution
    session.run("python", "-m", "build")
    session.run("twine", "check", "dist/*")
    
    # Run full test suite
    session.run("pytest", "tests/", "--cov=.", "--cov-fail-under=90")
    
    # Security checks
    session.run("bandit", "-r", ".", "--severity-level", "high")
    session.run("safety", "check")
    
    session.log("✅ Ready for release!")


@nox.session(python=LINT_PYTHON_VERSION, venv_backend="conda")
def conda_test(session):
    """Test with conda environment."""
    session.conda_install("pytest", "pytest-cov")
    session.run("pytest", "tests/", "-v")
