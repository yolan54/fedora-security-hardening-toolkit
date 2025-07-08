#!/usr/bin/env python3
"""
Setup script for Fedora Security Hardening Toolkit

This setup script provides a production-grade installation and configuration
system for the security hardening toolkit.
"""

from setuptools import setup, find_packages
import sys

# Ensure Python 3.8+
if sys.version_info < (3, 8):
    print("Error: Fedora Security Hardening Toolkit requires Python 3.8 or higher")
    print(f"Current Python version: {sys.version}")
    sys.exit(1)


# Read long description from README
def read_long_description():
    """Read the long description from README.md"""
    try:
        with open("README.md", "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return "Comprehensive security hardening toolkit for Fedora Linux systems"


# Read version from file or set default
def get_version():
    """Get version from version file or set default"""
    try:
        with open("VERSION", "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "1.0.0"


# Development dependencies
dev_requirements = [
    "pylint>=2.15.0",
    "black>=22.0.0",
    "isort>=5.10.0",
    "mypy>=0.991",
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "pre-commit>=2.20.0",
    "bandit>=1.7.0",
    "safety>=2.0.0",
    "flake8>=5.0.0",
    "flake8-docstrings>=1.6.0",
    "flake8-security>=1.2.0",
    "shellcheck-py>=0.9.0",
]

setup(
    name="fedora-security-hardening-toolkit",
    version=get_version(),
    author="Security Hardening Toolkit Team",
    author_email="security@example.com",
    description="Comprehensive security hardening toolkit for Fedora Linux systems",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/security-toolkit/fedora-security-hardening-toolkit",
    project_urls={
        "Bug Tracker": "https://github.com/security-toolkit/fedora-security-hardening-toolkit/issues",
        "Documentation": "https://github.com/security-toolkit/fedora-security-hardening-toolkit/blob/main/README.md",
        "Source Code": "https://github.com/security-toolkit/fedora-security-hardening-toolkit",
        "Changelog": "https://github.com/security-toolkit/fedora-security-hardening-toolkit/blob/main/CHANGELOG.md",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    python_requires=">=3.8",
    install_requires=[
        # No external dependencies for core functionality
        # This ensures the toolkit works in minimal environments
    ],
    extras_require={
        "dev": dev_requirements,
        "testing": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
        "linting": [
            "pylint>=2.15.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "mypy>=0.991",
            "flake8>=5.0.0",
        ],
        "security": [
            "bandit>=1.7.0",
            "safety>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "security-audit=security_audit:main",
        ],
    },
    scripts=[
        "security_hardening.sh",
        "security_validation.sh",
    ],
    include_package_data=True,
    package_data={
        "": [
            "README.md",
            "LICENSE",
            "CHANGELOG.md",
            "CONTRIBUTING.md",
            "*.sh",
            "*.yml",
            "*.yaml",
            "*.toml",
            "*.cfg",
        ],
    },
    zip_safe=False,
    keywords="security hardening fedora linux cis nist compliance",
    platforms=["Linux"],
)
