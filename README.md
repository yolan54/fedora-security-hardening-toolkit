# Fedora Security Hardening Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Bash](https://img.shields.io/badge/shell-bash-green.svg)](https://www.gnu.org/software/bash/)
[![CIS Controls](https://img.shields.io/badge/compliance-CIS%20Controls%20v8-blue.svg)](https://www.cisecurity.org/controls/)
[![NIST CSF](https://img.shields.io/badge/compliance-NIST%20CSF-blue.svg)](https://www.nist.gov/cyberframework)

A comprehensive, research-based security hardening toolkit for Fedora Linux systems. Built with enterprise-grade UX principles, transparent security implementation, and cross-platform compatibility.

## Security

This toolkit provides comprehensive security hardening for Fedora Linux systems with enterprise-grade UX principles and transparent implementation.

## 🎯 **What This Toolkit Does**

This toolkit provides **three complementary tools** that work together to secure your Fedora system:

### **1. Security Audit Script** (`security_audit.py`)
- **What**: Comprehensive security assessment and compliance checking
- **Why**: Know your current security posture before making changes
- **When**: Run first to establish baseline, then periodically for monitoring

### **2. Security Hardening Script** (`security_hardening.sh`)
- **What**: Implements industry-standard security controls with user transparency
- **Why**: Apply proven security measures based on official documentation
- **When**: Run after audit to implement recommended security controls

### **3. Security Validation Script** (`security_validation.sh`)
- **What**: Validates that security controls are working correctly
- **Why**: Confirm your security implementation is effective
- **When**: Run after hardening to verify everything works as expected

## 🏗️ **Architecture & Design Philosophy**

### **Cross-Platform Compatibility**
- ✅ **Hardware Agnostic**: Works on any x86_64, ARM64, or other architectures
- ✅ **Distribution Support**: Fedora (primary), RHEL, CentOS Stream, Rocky Linux
- ✅ **Environment Flexible**: Physical machines, VMs, containers, cloud instances

### **Enterprise-Grade UX Principles**
- 🔍 **Transparency**: Always show current state before making changes
- 🎯 **User Agency**: Interactive confirmations with preview options
- 🛡️ **Safety First**: Comprehensive backups with auto-rollback capabilities
- 📊 **Risk Communication**: Color-coded, prioritized security assessments
- ✅ **Verification**: Confirm changes worked as expected
- 📚 **Education**: Provide commands for ongoing management

### **Compliance Framework Integration**
- **CIS Controls v8**: Specific control mapping and implementation
- **NIST Cybersecurity Framework**: Identify, Protect, Detect, Respond, Recover
- **Industry Standards**: Based on official documentation and best practices

## Usage

This toolkit provides three main scripts for comprehensive security management:

1. **Security Audit**: `sudo python3 security_audit.py` - Assess current security posture
2. **Security Hardening**: `sudo ./security_hardening.sh` - Apply security controls
3. **Security Validation**: `sudo ./security_validation.sh` - Verify implementation

See the Quick Start Guide below for detailed instructions.

## 🚀 **Quick Start Guide**

### **Prerequisites**
```bash
# Ensure you have required tools (Fedora/RHEL/CentOS)
sudo dnf install -y python3 python3-pip bash curl wget

# For Debian/Ubuntu systems
sudo apt update && sudo apt install -y python3 python3-pip bash curl wget
```

## Installation
```bash
# Clone the repository
git clone https://github.com/your-org/fedora-security-hardening-toolkit.git
cd fedora-security-hardening-toolkit

# Make scripts executable
chmod +x security_audit.py security_hardening.sh security_validation.sh

# Optional: Install development dependencies
make install-dev
```

### **Step 1: Security Assessment** (5 minutes)
```bash
# Run comprehensive security audit
sudo python3 security_audit.py

# For verbose output with detailed logging
sudo python3 security_audit.py --verbose

# Review the generated report
cat security_audit_report_*.json
```

**What you'll see:**
- Current security score (0-100%)
- Specific vulnerabilities identified
- Compliance gaps with CIS/NIST frameworks
- Prioritized recommendations

### **Step 2: Security Hardening** (15-20 minutes)
```bash
# Apply security hardening with interactive confirmation
chmod +x security_hardening.sh
sudo ./security_hardening.sh

# The script will:
# 1. Show current configuration analysis
# 2. Preview proposed changes
# 3. Ask for your confirmation
# 4. Create comprehensive backups
# 5. Apply security controls
# 6. Verify implementation
```

**What gets hardened:**
- **Fail2ban**: Intrusion prevention with SSH protection
- **Firewalld**: Zone-based network security
- **SSH**: Key-based authentication and protocol hardening
- **Kernel**: Network security parameters
- **Audit**: Comprehensive security event logging

### **Step 3: Security Validation** (5 minutes)
```bash
# Validate security implementation
chmod +x security_validation.sh
sudo ./security_validation.sh

# Review validation results
# Security score should now be 90%+ if hardening was successful
```

## 📊 **Understanding Security Scores**

### **Scoring System**
- **90-100%**: 🟢 **Excellent** - Enterprise-grade security posture
- **75-89%**: 🟡 **Good** - Minor improvements recommended
- **50-74%**: 🟠 **Moderate** - Several issues need attention
- **Below 50%**: 🔴 **Critical** - Immediate action required

### **Score Components**
| Component | Weight | What It Measures |
|-----------|--------|------------------|
| **Intrusion Prevention** | 30% | Fail2ban configuration and effectiveness |
| **Network Security** | 25% | Firewall rules and network hardening |
| **Access Control** | 25% | SSH security and authentication |
| **System Hardening** | 20% | Kernel parameters and audit logging |

## 🔧 **Detailed Component Explanations**

### **Fail2ban (Intrusion Prevention)**
**What it does:**
- Monitors log files for malicious activity patterns
- Automatically bans IP addresses that show suspicious behavior
- Protects against brute force attacks, DDoS attempts, and repeat offenders

**Why it matters:**
- Prevents 99%+ of automated attacks
- Reduces server load from malicious traffic
- Provides early warning of attack attempts

**How our implementation works:**
```bash
# SSH Protection Jail
[sshd]
maxretry = 3        # Only 3 failed attempts allowed
bantime = 1h        # 1 hour ban for violations
findtime = 10m      # Detection window

# DDoS Protection Jail  
[sshd-ddos]
maxretry = 2        # Only 2 rapid connections allowed
bantime = 2h        # 2 hour ban for DDoS attempts

# Repeat Offender Jail
[recidive]
maxretry = 5        # 5 separate bans triggers this
bantime = 1w        # 1 week ban for persistent attackers
```

### **Firewalld (Network Security)**
**What it does:**
- Controls network traffic with zone-based rules
- Blocks unnecessary services and ports
- Logs security events for monitoring

**Why it matters:**
- Reduces attack surface by blocking unused services
- Provides network-level protection
- Enables traffic monitoring and analysis

**How our implementation works:**
```bash
# Zone Configuration
Default Zone: drop          # Most restrictive - deny by default
Trusted Zone: 192.168.1.0/24  # Local network access
Public Zone: SSH only        # Minimal external access

# Service Controls
SSH: Allowed with rate limiting
HTTP/HTTPS: Only if web server detected
FTP/Telnet: Blocked (insecure protocols)
```

### **SSH Hardening (Access Control)**
**What it does:**
- Enforces strong authentication methods
- Limits connection attempts and sessions
- Uses modern cryptographic standards

**Why it matters:**
- SSH is the primary remote access method
- Weak SSH = complete system compromise
- Proper SSH config prevents 95% of remote attacks

**How our implementation works:**
```bash
# Authentication Security
PasswordAuthentication no    # Key-based auth only
PermitRootLogin no          # No direct root access
MaxAuthTries 3              # Limit brute force attempts

# Protocol Security
Protocol 2                  # Modern SSH protocol only
Ciphers: ChaCha20, AES-256  # Strong encryption
MACs: SHA-256, SHA-512      # Secure message authentication
```

## 🛡️ **Safety Features & Rollback**

### **Comprehensive Backup System**
Every change creates timestamped backups:
```bash
/root/security_backups_YYYYMMDD_HHMMSS/
├── fail2ban_backup/
│   ├── jail.local.backup
│   └── restore_fail2ban.sh     # Auto-generated rollback script
├── firewall_backup/
│   ├── firewall_rules.backup
│   └── restore_firewall.sh
└── ssh_backup/
    ├── sshd_config.backup
    └── restore_ssh.sh
```

### **Emergency Rollback**
If something goes wrong:
```bash
# Find your backup directory
ls /root/security_backups_*

# Run the appropriate rollback script
sudo /root/security_backups_YYYYMMDD_HHMMSS/restore_fail2ban.sh
sudo /root/security_backups_YYYYMMDD_HHMMSS/restore_firewall.sh
sudo /root/security_backups_YYYYMMDD_HHMMSS/restore_ssh.sh
```

## 📈 **Monitoring & Maintenance**

### **Daily Monitoring Commands**
```bash
# Check fail2ban status and banned IPs
sudo fail2ban-client status
sudo fail2ban-client status sshd

# Review firewall logs
sudo journalctl -u firewalld -n 50

# Check SSH authentication attempts
sudo journalctl -u sshd -n 50 | grep -i failed

# Monitor system security events
sudo ausearch -m avc -ts recent
```

### **Weekly Maintenance Tasks**
```bash
# Re-run security validation
sudo ./security_validation.sh

# Update security software
sudo dnf update fail2ban firewalld openssh-server

# Review and rotate logs
sudo logrotate -f /etc/logrotate.conf

# Check for security updates
sudo dnf check-update --security
```

### **Monthly Security Reviews**
```bash
# Full security re-assessment
sudo python3 security_audit.py

# Review banned IP patterns
sudo fail2ban-client status | grep "Currently banned"

# Analyze attack patterns
sudo grep "Ban " /var/log/fail2ban.log | tail -50

# Update security configurations if needed
sudo ./security_hardening.sh
```

## 🔍 **Troubleshooting Guide**

### **Common Issues & Solutions**

#### **Issue: SSH Access Denied After Hardening**
```bash
# Symptoms: Can't SSH to server
# Cause: SSH keys not properly configured

# Solution 1: Use console/physical access
sudo systemctl status sshd
sudo journalctl -u sshd -n 20

# Solution 2: Rollback SSH configuration
sudo /root/security_backups_*/restore_ssh.sh

# Solution 3: Temporarily allow password auth
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

#### **Issue: Fail2ban Not Starting**
```bash
# Check configuration syntax
sudo fail2ban-client --test

# Check log files exist
ls -la /var/log/secure /var/log/auth.log

# Review fail2ban logs
sudo journalctl -u fail2ban -n 50

# Rollback if needed
sudo /root/security_backups_*/restore_fail2ban.sh
```

#### **Issue: Firewall Blocking Required Services**
```bash
# Check current rules
sudo firewall-cmd --list-all

# Temporarily allow service
sudo firewall-cmd --add-service=http --timeout=300

# Make permanent if needed
sudo firewall-cmd --add-service=http --permanent
sudo firewall-cmd --reload
```

## 📚 **Learning Resources**

### **Understanding the Security Controls**
- [CIS Controls v8 Documentation](https://www.cisecurity.org/controls/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Fedora Security Guide](https://docs.fedoraproject.org/en-US/quick-docs/securing-fedora/)

### **Advanced Configuration**
- [Fail2ban Official Documentation](https://github.com/fail2ban/fail2ban)
- [Firewalld Documentation](https://firewalld.org/documentation/)
- [OpenSSH Security Best Practices](https://www.ssh.com/academy/ssh/sshd_config)

### **Security Monitoring**
- [Linux Security Monitoring](https://www.cyberciti.biz/tips/linux-security.html)
- [Log Analysis Techniques](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-overview.html)

## 🤝 **Contributing**

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- [How To Secure A Linux Server](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server) - Comprehensive security guide
- [CIS Controls](https://www.cisecurity.org/controls/) - Industry security standards
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Government security guidelines
- Fedora Security Team - Official distribution security guidance
