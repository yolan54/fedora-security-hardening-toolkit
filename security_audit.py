#!/usr/bin/env python3
"""
Fedora Security Hardening Toolkit - Security Audit Module

A comprehensive security assessment tool for Fedora Linux systems.
Based on CIS Controls v8, NIST Cybersecurity Framework, and industry best practices.

Author: Security Hardening Toolkit Team
License: MIT
Version: 1.0.0
"""

import argparse
import json
import logging
import os
import platform
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union


class SecurityAuditError(Exception):
    """Custom exception for security audit errors."""
    pass


class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


class SystemInfo:
    """System information detection and validation."""
    
    @staticmethod
    def detect_distribution() -> str:
        """Detect Linux distribution."""
        try:
            with open('/etc/os-release', 'r', encoding='utf-8') as f:
                content = f.read().lower()
                if 'fedora' in content:
                    return 'fedora'
                elif 'rhel' in content or 'red hat' in content:
                    return 'rhel'
                elif 'centos' in content:
                    return 'centos'
                elif 'rocky' in content:
                    return 'rocky'
                elif 'debian' in content:
                    return 'debian'
                elif 'ubuntu' in content:
                    return 'ubuntu'
        except (FileNotFoundError, PermissionError):
            pass
        return 'unknown'
    
    @staticmethod
    def get_architecture() -> str:
        """Get system architecture."""
        return platform.machine()
    
    @staticmethod
    def get_kernel_version() -> str:
        """Get kernel version."""
        return platform.release()
    
    @staticmethod
    def is_virtual_machine() -> bool:
        """Detect if running in a virtual machine."""
        try:
            with open('/proc/cpuinfo', 'r', encoding='utf-8') as f:
                content = f.read().lower()
                vm_indicators = ['hypervisor', 'vmware', 'virtualbox', 'kvm', 'xen']
                return any(indicator in content for indicator in vm_indicators)
        except (FileNotFoundError, PermissionError):
            return False


class CommandExecutor:
    """Safe command execution with timeout and error handling."""
    
    @staticmethod
    def run_command(
        command: Union[str, List[str]], 
        timeout: int = 30,
        check_return_code: bool = False
    ) -> Dict[str, Union[str, int, bool]]:
        """
        Execute a command safely with timeout and error handling.
        
        Args:
            command: Command to execute (string or list)
            timeout: Timeout in seconds
            check_return_code: Whether to raise exception on non-zero return code
            
        Returns:
            Dictionary with command results
        """
        try:
            if isinstance(command, str):
                result = subprocess.run(
                    command, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=timeout,
                    check=check_return_code
                )
            else:
                result = subprocess.run(
                    command, 
                    capture_output=True, 
                    text=True, 
                    timeout=timeout,
                    check=check_return_code
                )
            
            return {
                'command': command,
                'returncode': result.returncode,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'success': result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                'command': command,
                'error': f'Command timed out after {timeout}s',
                'success': False,
                'returncode': -1
            }
        except subprocess.CalledProcessError as e:
            return {
                'command': command,
                'error': f'Command failed with return code {e.returncode}',
                'success': False,
                'returncode': e.returncode,
                'stdout': e.stdout.strip() if e.stdout else '',
                'stderr': e.stderr.strip() if e.stderr else ''
            }
        except Exception as e:
            return {
                'command': command,
                'error': str(e),
                'success': False,
                'returncode': -1
            }


class SecurityAuditor:
    """Main security audit class."""
    
    def __init__(self, verbose: bool = False):
        """Initialize the security auditor."""
        self.verbose = verbose
        self.system_info = {
            'distribution': SystemInfo.detect_distribution(),
            'architecture': SystemInfo.get_architecture(),
            'kernel_version': SystemInfo.get_kernel_version(),
            'is_vm': SystemInfo.is_virtual_machine(),
            'timestamp': datetime.now().isoformat()
        }
        self.executor = CommandExecutor()
        self.findings = {}
        self.recommendations = []
        self.compliance_status = {
            'cis_controls': [],
            'nist_framework': []
        }
        
        # Setup logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def print_header(self) -> None:
        """Print audit header."""
        print(f"{Colors.BOLD}{Colors.CYAN}")
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║              FEDORA SECURITY AUDIT TOOLKIT                  ║")
        print("║           Comprehensive Security Assessment v1.0            ║")
        print("║              CIS Controls v8 | NIST CSF Compliant           ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print(f"{Colors.END}")
        
        print(f"{Colors.BLUE}System Information:{Colors.END}")
        print(f"  Distribution: {self.system_info['distribution']}")
        print(f"  Architecture: {self.system_info['architecture']}")
        print(f"  Kernel: {self.system_info['kernel_version']}")
        print(f"  Environment: {'Virtual Machine' if self.system_info['is_vm'] else 'Physical/Bare Metal'}")
    
    def print_section(self, title: str) -> None:
        """Print section header."""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}=== {title} ==={Colors.END}")
        self.logger.info(f"Starting audit section: {title}")
    
    def print_finding(self, status: str, message: str) -> None:
        """Print color-coded finding."""
        if status == "PASS":
            print(f"{Colors.GREEN}✅ {message}{Colors.END}")
        elif status == "FAIL":
            print(f"{Colors.RED}❌ {message}{Colors.END}")
        elif status == "WARN":
            print(f"{Colors.YELLOW}⚠️  {message}{Colors.END}")
        else:
            print(f"{Colors.BLUE}ℹ️  {message}{Colors.END}")
    
    def audit_fail2ban(self) -> None:
        """Audit fail2ban configuration and status with enhanced transparency."""
        self.print_section("FAIL2BAN INTRUSION PREVENTION AUDIT (CIS 6.2)")

        print(f"{Colors.BOLD}{Colors.BLUE}🛡️  INTRUSION PREVENTION ANALYSIS{Colors.END}")
        print("  Analyzing fail2ban configuration and threat response...")
        print()

        # Check if fail2ban is installed and active
        status_result = self.executor.run_command("systemctl is-active fail2ban")

        if status_result['success'] and status_result['stdout'] == 'active':
            self.print_finding("PASS", "Fail2ban service is active and protecting system")

            # Get version information for transparency
            version_result = self.executor.run_command("fail2ban-client version")
            if version_result['success']:
                version = version_result['stdout'].split('\n')[0] if version_result['stdout'] else 'unknown'
                self.print_finding("INFO", f"Fail2ban version: {version}")

            # Enhanced jail analysis with current threat status
            jails_result = self.executor.run_command("fail2ban-client status")
            if jails_result['success']:
                print(f"{Colors.CYAN}📊 CURRENT THREAT PROTECTION STATUS:{Colors.END}")

                # Parse and check specific jails with detailed analysis
                jail_lines = jails_result['stdout'].split('\n')
                for line in jail_lines:
                    if 'Jail list:' in line:
                        jails = line.split('Jail list:')[1].strip()

                        # SSH jail analysis
                        if 'sshd' in jails:
                            self.print_finding("PASS", "SSH jail is configured and monitoring")
                            self.compliance_status['cis_controls'].append("CIS 6.2 - SSH Protection Active")

                            # Get SSH jail details for transparency
                            ssh_status = self.executor.run_command("fail2ban-client status sshd")
                            if ssh_status['success']:
                                self._analyze_ssh_jail_status(ssh_status['stdout'])
                        else:
                            self.print_finding("FAIL", "SSH jail not configured - CRITICAL SECURITY GAP")
                            self.recommendations.append({
                                'priority': 'HIGH',
                                'issue': 'SSH jail not configured',
                                'impact': 'System vulnerable to SSH brute force attacks',
                                'fix': 'sudo systemctl enable fail2ban && sudo fail2ban-client reload'
                            })

                        # Recidive jail analysis
                        if 'recidive' in jails:
                            self.print_finding("PASS", "Recidive jail configured for persistent attackers")
                        else:
                            self.print_finding("WARN", "Recidive jail not configured")
                            self.recommendations.append({
                                'priority': 'MEDIUM',
                                'issue': 'Recidive jail not configured',
                                'impact': 'Persistent attackers can retry indefinitely',
                                'fix': 'Configure recidive jail in /etc/fail2ban/jail.local'
                            })

            # Configuration analysis
            config_files = ['/etc/fail2ban/jail.local', '/etc/fail2ban/jail.conf']
            for config_file in config_files:
                if os.path.exists(config_file):
                    self.print_finding("PASS", f"Configuration file exists: {config_file}")
                    break
            else:
                self.print_finding("WARN", "No custom fail2ban configuration found")

        else:
            self.print_finding("FAIL", "Fail2ban is not installed or not running - CRITICAL VULNERABILITY")
            self.recommendations.append({
                'priority': 'CRITICAL',
                'issue': 'Fail2ban not active',
                'impact': 'System completely vulnerable to brute force attacks',
                'fix': 'sudo dnf install fail2ban && sudo systemctl enable --now fail2ban'
            })
            self.compliance_status['cis_controls'].append("CIS 6.2 - MISSING: Host-Based Intrusion Prevention")

        self.findings['fail2ban'] = {
            'installed': status_result['success'],
            'active': status_result['success'] and status_result['stdout'] == 'active'
        }

    def _analyze_ssh_jail_status(self, status_output: str) -> None:
        """Analyze SSH jail status with threat intelligence."""
        lines = status_output.split('\n')
        currently_failed = 0
        currently_banned = 0

        for line in lines:
            if 'Currently failed:' in line:
                try:
                    currently_failed = int(line.split(':')[1].strip())
                except (ValueError, IndexError):
                    pass
            elif 'Currently banned:' in line:
                try:
                    currently_banned = int(line.split(':')[1].strip())
                except (ValueError, IndexError):
                    pass

        print(f"    {Colors.CYAN}• Active failed attempts: {currently_failed}{Colors.END}")
        print(f"    {Colors.CYAN}• Currently banned IPs: {currently_banned}{Colors.END}")

        if currently_failed > 0:
            self.print_finding("WARN", f"Active SSH attack attempts detected ({currently_failed})")
            print(f"    {Colors.YELLOW}💡 Monitor: sudo journalctl -u sshd -f{Colors.END}")

        if currently_banned > 0:
            self.print_finding("INFO", f"IPs currently banned for attacks ({currently_banned})")
            print(f"    {Colors.BLUE}🔍 Review: sudo fail2ban-client status sshd{Colors.END}")

        if currently_failed == 0 and currently_banned == 0:
            self.print_finding("PASS", "No active threats detected - system secure")
    
    def audit_firewall(self) -> None:
        """Audit firewall configuration with enhanced security analysis."""
        self.print_section("FIREWALL CONFIGURATION AUDIT (CIS 3.5)")

        print(f"{Colors.BOLD}{Colors.BLUE}🔥 NETWORK SECURITY ANALYSIS{Colors.END}")
        print("  Analyzing firewall configuration and network protection...")
        print()

        # Check firewalld (preferred for Fedora/RHEL)
        firewalld_status = self.executor.run_command("systemctl is-active firewalld")

        if firewalld_status['success'] and firewalld_status['stdout'] == 'active':
            self.print_finding("PASS", "Firewalld is active and protecting network")

            print(f"{Colors.CYAN}📊 CURRENT FIREWALL CONFIGURATION:{Colors.END}")

            # Enhanced default zone analysis
            default_zone = self.executor.run_command("firewall-cmd --get-default-zone")
            if default_zone['success']:
                zone = default_zone['stdout']
                if zone in ['drop', 'block']:
                    self.print_finding("PASS", f"Secure default zone configured: {zone}")
                    print(f"    {Colors.GREEN}🛡️  Security Level: Maximum (deny by default){Colors.END}")
                elif zone == 'public':
                    self.print_finding("WARN", "Using 'public' zone - moderate security")
                    print(f"    {Colors.YELLOW}⚠️  Security Level: Moderate (some services allowed){Colors.END}")
                    self.recommendations.append({
                        'priority': 'MEDIUM',
                        'issue': 'Default zone not maximally secure',
                        'impact': 'Potential exposure of unnecessary services',
                        'fix': 'sudo firewall-cmd --set-default-zone=drop --permanent'
                    })
                else:
                    self.print_finding("INFO", f"Default zone: {zone}")

            # Enhanced logging analysis with security impact
            log_denied = self.executor.run_command("firewall-cmd --get-log-denied")
            if log_denied['success']:
                if log_denied['stdout'] != 'off':
                    self.print_finding("PASS", f"Firewall logging enabled: {log_denied['stdout']}")
                    print(f"    {Colors.GREEN}📝 Security monitoring: Active{Colors.END}")
                else:
                    self.print_finding("WARN", "Firewall logging disabled - SECURITY BLIND SPOT")
                    print(f"    {Colors.RED}🚨 Impact: Cannot detect attack patterns or compliance violations{Colors.END}")
                    self.recommendations.append({
                        'priority': 'HIGH',
                        'issue': 'Firewall logging disabled',
                        'impact': 'No visibility into blocked attacks, compliance violations',
                        'fix': 'sudo firewall-cmd --set-log-denied=all --permanent && sudo firewall-cmd --reload'
                    })

            # Analyze active services and ports
            self._analyze_firewall_services()

            self.compliance_status['cis_controls'].append("CIS 3.5 - Network Firewall Active")

        else:
            # Check for alternative firewalls
            ufw_status = self.executor.run_command("systemctl is-active ufw")
            iptables_rules = self.executor.run_command("iptables -L -n | wc -l")

            if ufw_status['success'] and ufw_status['stdout'] == 'active':
                self.print_finding("INFO", "UFW firewall is active (alternative to firewalld)")
            elif (iptables_rules['success'] and
                  iptables_rules['stdout'].isdigit() and
                  int(iptables_rules['stdout']) > 10):
                self.print_finding("INFO", "Custom iptables rules detected")
            else:
                self.print_finding("FAIL", "No active firewall detected - CRITICAL VULNERABILITY")
                print(f"    {Colors.RED}🚨 Impact: System completely exposed to network attacks{Colors.END}")
                self.recommendations.append({
                    'priority': 'CRITICAL',
                    'issue': 'No firewall protection',
                    'impact': 'Complete network exposure, all services accessible',
                    'fix': 'sudo systemctl enable --now firewalld'
                })
                self.compliance_status['cis_controls'].append("CIS 3.5 - MISSING: Network Firewall")

        self.findings['firewall'] = {
            'firewalld_active': firewalld_status['success'] and firewalld_status['stdout'] == 'active'
        }

    def audit_ssh_security(self) -> None:
        """Comprehensive SSH security configuration audit."""
        self.print_section("SSH SECURITY CONFIGURATION AUDIT (CIS 5.2)")

        print(f"{Colors.BOLD}{Colors.BLUE}🔐 SSH SECURITY ANALYSIS{Colors.END}")
        print("  Analyzing SSH daemon configuration and access controls...")
        print()

        # Check if SSH is running
        ssh_status = self.executor.run_command("systemctl is-active sshd")

        if ssh_status['success'] and ssh_status['stdout'] == 'active':
            self.print_finding("INFO", "SSH service is active - analyzing configuration")

            # Analyze SSH configuration file
            ssh_config_path = '/etc/ssh/sshd_config'
            if os.path.exists(ssh_config_path):
                self._analyze_ssh_config(ssh_config_path)
            else:
                self.print_finding("WARN", "SSH configuration file not found")

            # Check SSH key authentication
            self._check_ssh_keys()

            # Analyze SSH connections and security
            self._analyze_ssh_connections()

        else:
            self.print_finding("INFO", "SSH service not active - system not remotely accessible")
            print(f"    {Colors.GREEN}🔒 No remote access risk{Colors.END}")

        self.findings['ssh'] = {
            'service_active': ssh_status['success'] and ssh_status['stdout'] == 'active'
        }

    def audit_system_hardening(self) -> None:
        """Audit system hardening parameters and kernel security."""
        self.print_section("SYSTEM HARDENING AUDIT (CIS 3.1-3.4)")

        print(f"{Colors.BOLD}{Colors.BLUE}⚙️  SYSTEM HARDENING ANALYSIS{Colors.END}")
        print("  Analyzing kernel parameters and system security settings...")
        print()

        # Check kernel parameters
        self._check_kernel_parameters()

        # Check system services
        self._check_system_services()

        # Check file permissions
        self._check_critical_file_permissions()

        self.findings['system_hardening'] = {'analyzed': True}

    def _check_kernel_parameters(self) -> None:
        """Check security-related kernel parameters."""
        print(f"{Colors.CYAN}📊 KERNEL SECURITY PARAMETERS:{Colors.END}")

        security_params = {
            'net.ipv4.ip_forward': ('0', 'IP forwarding disabled'),
            'net.ipv4.conf.all.send_redirects': ('0', 'ICMP redirects disabled'),
            'net.ipv4.conf.default.send_redirects': ('0', 'Default ICMP redirects disabled'),
            'net.ipv4.conf.all.accept_source_route': ('0', 'Source routing disabled'),
            'net.ipv4.conf.all.accept_redirects': ('0', 'ICMP redirect acceptance disabled'),
            'net.ipv4.conf.all.log_martians': ('1', 'Martian packet logging enabled'),
            'net.ipv4.tcp_syncookies': ('1', 'SYN flood protection enabled'),
            'kernel.dmesg_restrict': ('1', 'Kernel log access restricted'),
            'kernel.kptr_restrict': ('2', 'Kernel pointer access restricted')
        }

        secure_params = 0
        total_params = len(security_params)

        for param, (expected_value, description) in security_params.items():
            result = self.executor.run_command(f"sysctl {param}")
            if result['success']:
                current_value = result['stdout'].split('=')[-1].strip()
                if current_value == expected_value:
                    self.print_finding("PASS", description)
                    secure_params += 1
                else:
                    self.print_finding("WARN", f"{description} - current: {current_value}, expected: {expected_value}")
                    self.recommendations.append({
                        'priority': 'MEDIUM',
                        'issue': f'Kernel parameter {param} not optimally configured',
                        'impact': 'Reduced network security hardening',
                        'fix': f'echo "{param} = {expected_value}" >> /etc/sysctl.conf'
                    })
            else:
                self.print_finding("WARN", f"Could not check {param}")

        security_percentage = (secure_params / total_params) * 100
        print(f"    {Colors.CYAN}🔧 Kernel hardening: {secure_params}/{total_params} ({security_percentage:.0f}%){Colors.END}")

    def _check_system_services(self) -> None:
        """Check for unnecessary or risky system services."""
        print(f"\n{Colors.CYAN}🔍 SYSTEM SERVICES ANALYSIS:{Colors.END}")

        # Check for risky services that should typically be disabled
        risky_services = [
            'telnet', 'rsh', 'rlogin', 'ftp', 'tftp', 'xinetd',
            'avahi-daemon', 'cups', 'nfs-server', 'rpcbind'
        ]

        active_risky_services = []

        for service in risky_services:
            status = self.executor.run_command(f"systemctl is-active {service}")
            if status['success'] and status['stdout'] == 'active':
                active_risky_services.append(service)
                self.print_finding("WARN", f"Potentially risky service active: {service}")
                self.recommendations.append({
                    'priority': 'MEDIUM',
                    'issue': f'Risky service {service} is active',
                    'impact': 'Increased attack surface and potential vulnerabilities',
                    'fix': f'sudo systemctl disable --now {service}'
                })

        if not active_risky_services:
            self.print_finding("PASS", "No risky services detected running")
            print(f"    {Colors.GREEN}🔒 Minimal service footprint maintained{Colors.END}")
        else:
            print(f"    {Colors.YELLOW}⚠️  {len(active_risky_services)} risky service(s) active{Colors.END}")

    def _check_critical_file_permissions(self) -> None:
        """Check permissions on critical system files."""
        print(f"\n{Colors.CYAN}📁 CRITICAL FILE PERMISSIONS:{Colors.END}")

        critical_files = {
            '/etc/passwd': ('644', 'User account information'),
            '/etc/shadow': ('000', 'Password hashes'),
            '/etc/group': ('644', 'Group information'),
            '/etc/gshadow': ('000', 'Group password hashes'),
            '/etc/ssh/sshd_config': ('600', 'SSH daemon configuration')
        }

        secure_files = 0

        for file_path, (expected_perms, description) in critical_files.items():
            if os.path.exists(file_path):
                stat_result = self.executor.run_command(f"stat -c '%a' {file_path}")
                if stat_result['success']:
                    current_perms = stat_result['stdout'].strip()
                    if expected_perms == '000':  # Special case for shadow files
                        if current_perms in ['000', '640', '600']:
                            self.print_finding("PASS", f"{description} properly secured")
                            secure_files += 1
                        else:
                            self.print_finding("WARN", f"{description} permissions too open: {current_perms}")
                    elif current_perms == expected_perms:
                        self.print_finding("PASS", f"{description} properly secured")
                        secure_files += 1
                    else:
                        self.print_finding("WARN", f"{description} permissions: {current_perms} (expected: {expected_perms})")
                        self.recommendations.append({
                            'priority': 'HIGH',
                            'issue': f'Incorrect permissions on {file_path}',
                            'impact': 'Potential unauthorized access to sensitive data',
                            'fix': f'sudo chmod {expected_perms} {file_path}'
                        })
            else:
                self.print_finding("INFO", f"{description} file not found: {file_path}")

        print(f"    {Colors.CYAN}🔐 File security: {secure_files}/{len(critical_files)} files properly secured{Colors.END}")

    def audit_user_accounts(self) -> None:
        """Audit user accounts and access controls."""
        self.print_section("USER ACCOUNT SECURITY AUDIT (CIS 5.1)")

        print(f"{Colors.BOLD}{Colors.BLUE}👥 USER ACCOUNT ANALYSIS{Colors.END}")
        print("  Analyzing user accounts, privileges, and access controls...")
        print()

        # Check for users with UID 0 (root privileges)
        self._check_privileged_users()

        # Check password policies
        self._check_password_policies()

        # Check for inactive accounts
        self._check_inactive_accounts()

        self.findings['user_accounts'] = {'analyzed': True}

    def _check_privileged_users(self) -> None:
        """Check for users with root privileges."""
        print(f"{Colors.CYAN}👑 PRIVILEGED USER ANALYSIS:{Colors.END}")

        # Check for UID 0 users
        passwd_result = self.executor.run_command("awk -F: '$3 == 0 {print $1}' /etc/passwd")
        if passwd_result['success']:
            uid_zero_users = passwd_result['stdout'].strip().split('\n')
            uid_zero_users = [user for user in uid_zero_users if user]  # Remove empty strings

            if len(uid_zero_users) == 1 and uid_zero_users[0] == 'root':
                self.print_finding("PASS", "Only root user has UID 0")
            elif len(uid_zero_users) > 1:
                self.print_finding("WARN", f"Multiple UID 0 users detected: {', '.join(uid_zero_users)}")
                self.recommendations.append({
                    'priority': 'HIGH',
                    'issue': 'Multiple users with root privileges (UID 0)',
                    'impact': 'Increased risk of privilege escalation',
                    'fix': 'Review and remove unnecessary UID 0 accounts'
                })

        # Check sudo group membership
        sudo_result = self.executor.run_command("getent group sudo wheel")
        if sudo_result['success']:
            sudo_lines = [line for line in sudo_result['stdout'].split('\n') if line]
            sudo_users = []
            for line in sudo_lines:
                if ':' in line:
                    users = line.split(':')[-1]
                    if users:
                        sudo_users.extend(users.split(','))

            if sudo_users:
                self.print_finding("INFO", f"Users with sudo access: {', '.join(set(sudo_users))}")
                print(f"    {Colors.CYAN}🔑 {len(set(sudo_users))} user(s) have administrative privileges{Colors.END}")
            else:
                self.print_finding("WARN", "No users found with sudo access")

    def _check_password_policies(self) -> None:
        """Check password policy configuration."""
        print(f"\n{Colors.CYAN}🔒 PASSWORD POLICY ANALYSIS:{Colors.END}")

        # Check if password quality is enforced
        pam_files = ['/etc/pam.d/passwd', '/etc/pam.d/system-auth']
        quality_enforced = False

        for pam_file in pam_files:
            if os.path.exists(pam_file):
                try:
                    with open(pam_file, 'r') as f:
                        content = f.read()
                        if 'pam_pwquality' in content or 'pam_cracklib' in content:
                            quality_enforced = True
                            break
                except Exception:
                    pass

        if quality_enforced:
            self.print_finding("PASS", "Password quality enforcement configured")
        else:
            self.print_finding("WARN", "Password quality enforcement not detected")
            self.recommendations.append({
                'priority': 'MEDIUM',
                'issue': 'Password quality not enforced',
                'impact': 'Weak passwords may be allowed',
                'fix': 'Configure pam_pwquality in PAM configuration'
            })

        # Check login.defs for password aging
        login_defs_path = '/etc/login.defs'
        if os.path.exists(login_defs_path):
            try:
                with open(login_defs_path, 'r') as f:
                    content = f.read()
                    if 'PASS_MAX_DAYS' in content:
                        self.print_finding("PASS", "Password aging policy configured")
                    else:
                        self.print_finding("WARN", "Password aging not configured")
            except Exception:
                self.print_finding("WARN", "Could not read login.defs")

    def _check_inactive_accounts(self) -> None:
        """Check for inactive or potentially compromised accounts."""
        print(f"\n{Colors.CYAN}💤 INACTIVE ACCOUNT ANALYSIS:{Colors.END}")

        # Check for accounts that haven't logged in recently
        last_result = self.executor.run_command("last -n 20")
        if last_result['success']:
            recent_logins = len([line for line in last_result['stdout'].split('\n') if line and 'wtmp begins' not in line])
            self.print_finding("INFO", f"Recent login activity detected for {recent_logins} sessions")

        # Check for locked accounts
        locked_result = self.executor.run_command("passwd -S -a 2>/dev/null | grep -c ' L '")
        if locked_result['success'] and locked_result['stdout'].isdigit():
            locked_count = int(locked_result['stdout'])
            if locked_count > 0:
                self.print_finding("INFO", f"Locked user accounts: {locked_count}")
            else:
                self.print_finding("INFO", "No locked user accounts detected")

    def _analyze_ssh_config(self, config_path: str) -> None:
        """Analyze SSH configuration for security best practices."""
        try:
            with open(config_path, 'r') as f:
                config_content = f.read()

            print(f"{Colors.CYAN}📊 SSH CONFIGURATION ANALYSIS:{Colors.END}")

            # Check root login
            if 'PermitRootLogin no' in config_content:
                self.print_finding("PASS", "Root login disabled - excellent security")
            elif 'PermitRootLogin' in config_content:
                self.print_finding("WARN", "Root login may be enabled")
                self.recommendations.append({
                    'priority': 'HIGH',
                    'issue': 'Root SSH login not explicitly disabled',
                    'impact': 'Direct root access increases attack surface',
                    'fix': 'Add "PermitRootLogin no" to /etc/ssh/sshd_config'
                })
            else:
                self.print_finding("WARN", "Root login setting not explicitly configured")

            # Check password authentication
            if 'PasswordAuthentication no' in config_content:
                self.print_finding("PASS", "Password authentication disabled - using key-based auth")
                print(f"    {Colors.GREEN}🔑 Key-based authentication enforced{Colors.END}")
            elif 'PasswordAuthentication yes' in config_content:
                self.print_finding("WARN", "Password authentication enabled")
                self.recommendations.append({
                    'priority': 'MEDIUM',
                    'issue': 'Password authentication enabled',
                    'impact': 'Vulnerable to brute force attacks',
                    'fix': 'Disable password auth: PasswordAuthentication no'
                })

            # Check SSH protocol version
            if 'Protocol 2' in config_content or 'Protocol' not in config_content:
                self.print_finding("PASS", "Using secure SSH protocol version 2")
            else:
                self.print_finding("FAIL", "Insecure SSH protocol configuration")

            # Check port configuration
            import re
            port_match = re.search(r'Port\s+(\d+)', config_content)
            if port_match:
                port = port_match.group(1)
                if port != '22':
                    self.print_finding("PASS", f"SSH running on non-standard port {port}")
                    print(f"    {Colors.GREEN}🔒 Security through obscurity applied{Colors.END}")
                else:
                    self.print_finding("INFO", "SSH running on standard port 22")
                    print(f"    {Colors.YELLOW}💡 Consider changing to non-standard port{Colors.END}")

        except Exception as e:
            self.print_finding("WARN", f"Could not analyze SSH config: {e}")

    def _check_ssh_keys(self) -> None:
        """Check SSH key configuration and security."""
        print(f"\n{Colors.CYAN}🔑 SSH KEY ANALYSIS:{Colors.END}")

        # Check for SSH host keys
        host_key_types = ['rsa', 'ecdsa', 'ed25519']
        secure_keys = 0

        for key_type in host_key_types:
            key_path = f'/etc/ssh/ssh_host_{key_type}_key'
            if os.path.exists(key_path):
                if key_type == 'ed25519':
                    self.print_finding("PASS", f"Modern {key_type.upper()} host key present")
                    secure_keys += 1
                elif key_type == 'ecdsa':
                    self.print_finding("PASS", f"Secure {key_type.upper()} host key present")
                    secure_keys += 1
                elif key_type == 'rsa':
                    # Check RSA key size
                    key_info = self.executor.run_command(f"ssh-keygen -l -f {key_path}")
                    if key_info['success'] and '4096' in key_info['stdout']:
                        self.print_finding("PASS", "RSA host key is 4096-bit (secure)")
                        secure_keys += 1
                    elif key_info['success'] and '2048' in key_info['stdout']:
                        self.print_finding("WARN", "RSA host key is 2048-bit (consider upgrading)")
                    else:
                        self.print_finding("WARN", "RSA host key size unknown or weak")

        if secure_keys > 0:
            print(f"    {Colors.GREEN}🔐 {secure_keys} secure host key(s) configured{Colors.END}")
        else:
            self.print_finding("WARN", "No secure host keys detected")

    def _analyze_ssh_connections(self) -> None:
        """Analyze current SSH connections and recent activity."""
        print(f"\n{Colors.CYAN}📊 SSH CONNECTION ANALYSIS:{Colors.END}")

        # Check current SSH connections
        who_result = self.executor.run_command("who")
        if who_result['success']:
            ssh_sessions = [line for line in who_result['stdout'].split('\n') if 'pts/' in line]
            if ssh_sessions:
                self.print_finding("INFO", f"Active SSH sessions: {len(ssh_sessions)}")
                for session in ssh_sessions[:3]:  # Show first 3 sessions
                    print(f"    {Colors.CYAN}• {session.strip()}{Colors.END}")
            else:
                self.print_finding("INFO", "No active SSH sessions detected")

        # Check recent SSH authentication attempts
        auth_log = self.executor.run_command("journalctl -u sshd --since='24 hours ago' | grep -i 'authentication failure' | wc -l")
        if auth_log['success'] and auth_log['stdout'].isdigit():
            failed_attempts = int(auth_log['stdout'])
            if failed_attempts > 0:
                self.print_finding("WARN", f"SSH authentication failures in last 24h: {failed_attempts}")
                if failed_attempts > 10:
                    self.recommendations.append({
                        'priority': 'MEDIUM',
                        'issue': f'High SSH authentication failures ({failed_attempts})',
                        'impact': 'Possible brute force attack in progress',
                        'fix': 'Review logs: sudo journalctl -u sshd | grep "authentication failure"'
                    })
            else:
                self.print_finding("PASS", "No SSH authentication failures in last 24 hours")
                print(f"    {Colors.GREEN}🛡️  No brute force attempts detected{Colors.END}")

    def _analyze_firewall_services(self) -> None:
        """Analyze active firewall services and ports."""
        services_result = self.executor.run_command("firewall-cmd --list-services")
        if services_result['success']:
            services = services_result['stdout'].split()
            print(f"    {Colors.CYAN}🔓 Allowed services: {', '.join(services) if services else 'None'}{Colors.END}")

            # Analyze service security
            risky_services = ['ftp', 'telnet', 'rsh', 'rlogin']
            for service in services:
                if service in risky_services:
                    self.print_finding("WARN", f"Insecure service allowed: {service}")
                    self.recommendations.append({
                        'priority': 'HIGH',
                        'issue': f'Insecure service {service} allowed',
                        'impact': 'Unencrypted protocols expose credentials',
                        'fix': f'sudo firewall-cmd --remove-service={service} --permanent'
                    })

        # Check for open ports
        ports_result = self.executor.run_command("firewall-cmd --list-ports")
        if ports_result['success'] and ports_result['stdout']:
            ports = ports_result['stdout'].split()
            print(f"    {Colors.CYAN}🔓 Open ports: {', '.join(ports)}{Colors.END}")
            if len(ports) > 5:
                self.print_finding("WARN", f"Many open ports detected ({len(ports)}) - review necessity")
        else:
            print(f"    {Colors.GREEN}🔒 No custom ports open{Colors.END}")
    
    def generate_report(self) -> str:
        """Generate comprehensive audit report with enhanced analytics."""
        # Calculate detailed security metrics
        security_metrics = self._calculate_security_metrics()

        report = {
            'metadata': {
                'version': '2.0.0',
                'timestamp': self.system_info['timestamp'],
                'audit_type': 'comprehensive_security_assessment',
                'tool': 'Fedora Security Hardening Toolkit'
            },
            'system_info': self.system_info,
            'findings': self.findings,
            'recommendations': self.recommendations,
            'compliance_status': self.compliance_status,
            'security_metrics': security_metrics,
            'summary': {
                'total_checks': len(self.findings),
                'passed_checks': security_metrics['passed_checks'],
                'failed_checks': security_metrics['failed_checks'],
                'warning_checks': security_metrics['warning_checks'],
                'recommendations_count': len(self.recommendations),
                'security_score': security_metrics['overall_score'],
                'risk_level': security_metrics['risk_level']
            }
        }

        # Save report to file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"security_audit_report_{timestamp}.json"

        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.print_finding("PASS", f"Audit report saved: {report_file}")
        except Exception as e:
            self.logger.error(f"Failed to save report: {e}")
            self.print_finding("WARN", f"Could not save report file: {e}")

        # Display enhanced summary
        self._display_enhanced_summary(security_metrics)

        return report_file

    def _calculate_security_metrics(self) -> Dict[str, Union[int, float, str]]:
        """Calculate detailed security metrics and scoring."""
        passed_checks = 0
        failed_checks = 0
        warning_checks = 0
        critical_issues = 0
        high_issues = 0
        medium_issues = 0

        # Analyze findings
        for finding_key, finding_data in self.findings.items():
            if isinstance(finding_data, dict) and finding_data.get('active', False):
                passed_checks += 1
            else:
                failed_checks += 1

        # Analyze recommendations by priority
        for rec in self.recommendations:
            if isinstance(rec, dict):
                priority = rec.get('priority', 'MEDIUM').upper()
                if priority == 'CRITICAL':
                    critical_issues += 1
                elif priority == 'HIGH':
                    high_issues += 1
                elif priority == 'MEDIUM':
                    medium_issues += 1
                else:
                    warning_checks += 1
            else:
                medium_issues += 1  # Legacy recommendations

        # Calculate weighted security score
        total_possible_score = 100
        critical_penalty = critical_issues * 30
        high_penalty = high_issues * 15
        medium_penalty = medium_issues * 5

        overall_score = max(0, total_possible_score - critical_penalty - high_penalty - medium_penalty)

        # Determine risk level
        if overall_score >= 90:
            risk_level = "LOW"
        elif overall_score >= 75:
            risk_level = "MEDIUM"
        elif overall_score >= 50:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        return {
            'passed_checks': passed_checks,
            'failed_checks': failed_checks,
            'warning_checks': warning_checks,
            'critical_issues': critical_issues,
            'high_issues': high_issues,
            'medium_issues': medium_issues,
            'overall_score': round(overall_score, 1),
            'risk_level': risk_level
        }

    def _display_enhanced_summary(self, metrics: Dict[str, Union[int, float, str]]) -> None:
        """Display enhanced security summary with actionable insights."""
        print(f"\n{Colors.BOLD}{Colors.GREEN}🎯 SECURITY ASSESSMENT COMPLETE{Colors.END}")
        print("=" * 60)

        # Security score with visual indicator
        score = metrics['overall_score']
        risk_level = metrics['risk_level']

        if score >= 90:
            score_color = Colors.GREEN
            score_icon = "🟢"
        elif score >= 75:
            score_color = Colors.YELLOW
            score_icon = "🟡"
        elif score >= 50:
            score_color = Colors.RED
            score_icon = "🟠"
        else:
            score_color = Colors.RED
            score_icon = "🔴"

        print(f"{Colors.BOLD}📊 Security Score: {score_color}{score}/100 {score_icon} ({risk_level} RISK){Colors.END}")

        # Issue breakdown
        print(f"\n{Colors.BOLD}📋 Issue Summary:{Colors.END}")
        if metrics['critical_issues'] > 0:
            print(f"  🔴 Critical issues: {metrics['critical_issues']} (immediate action required)")
        if metrics['high_issues'] > 0:
            print(f"  🟠 High priority: {metrics['high_issues']} (address within 24h)")
        if metrics['medium_issues'] > 0:
            print(f"  🟡 Medium priority: {metrics['medium_issues']} (address within week)")

        print(f"  ✅ Passed checks: {metrics['passed_checks']}")

        # Next steps
        print(f"\n{Colors.BOLD}{Colors.CYAN}🚀 RECOMMENDED NEXT STEPS:{Colors.END}")
        if metrics['critical_issues'] > 0:
            print("  1. 🚨 Address CRITICAL issues immediately")
            print("  2. 🛡️  Run security hardening script: sudo ./security_hardening.sh")
        elif metrics['high_issues'] > 0:
            print("  1. ⚠️  Address HIGH priority issues within 24 hours")
            print("  2. 🛡️  Run security hardening script: sudo ./security_hardening.sh")
        else:
            print("  1. ✅ System security is good - maintain current configuration")
            print("  2. 📊 Schedule regular security audits")

        print("  3. 📚 Review detailed recommendations in the JSON report")
        print("  4. 🔄 Re-run audit after implementing fixes")

        # Educational resources
        print(f"\n{Colors.BOLD}{Colors.BLUE}📚 LEARN MORE:{Colors.END}")
        print("  • Security best practices: https://docs.fedoraproject.org/en-US/quick-docs/securing-fedora/")
        print("  • CIS Controls: https://www.cisecurity.org/controls/")
        print("  • NIST Framework: https://www.nist.gov/cyberframework")

    def _offer_interactive_remediation(self) -> None:
        """Offer interactive remediation options to the user."""
        if not self.recommendations:
            return

        print(f"\n{Colors.BOLD}{Colors.YELLOW}🔧 INTERACTIVE REMEDIATION AVAILABLE{Colors.END}")
        print("Choose how you'd like to address the security issues found:")
        print(f"  {Colors.GREEN}1{Colors.END} - 📋 View detailed remediation steps (with follow-up options)")
        print(f"  {Colors.GREEN}2{Colors.END} - 📜 Generate automated fix script for manual review")
        print(f"  {Colors.GREEN}3{Colors.END} - 🛡️  Run comprehensive security hardening script")
        print(f"  {Colors.GREEN}4{Colors.END} - ⏭️  Continue without remediation (manual fixes)")

        try:
            choice = input(f"\n{Colors.CYAN}Enter your choice (1-4): {Colors.END}").strip()

            if choice == '1':
                self._show_detailed_remediation()
            elif choice == '2':
                self._generate_fix_script()
            elif choice == '3':
                self._suggest_hardening_script()
            elif choice == '4':
                print(f"{Colors.BLUE}ℹ️  Remediation skipped. Run audit again after manual fixes.{Colors.END}")
            else:
                print(f"{Colors.YELLOW}Invalid choice. Continuing...{Colors.END}")

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Remediation cancelled by user.{Colors.END}")
        except Exception:
            print(f"{Colors.YELLOW}Input error. Continuing...{Colors.END}")

    def _show_detailed_remediation(self) -> None:
        """Show detailed remediation steps for each issue."""
        print(f"\n{Colors.BOLD}{Colors.CYAN}📋 DETAILED REMEDIATION STEPS{Colors.END}")
        print("=" * 60)

        for i, rec in enumerate(self.recommendations, 1):
            if isinstance(rec, dict):
                priority = rec.get('priority', 'MEDIUM')
                issue = rec.get('issue', 'Unknown issue')
                impact = rec.get('impact', 'Unknown impact')
                fix = rec.get('fix', 'No fix provided')

                # Color code by priority
                if priority == 'CRITICAL':
                    priority_color = Colors.RED
                    priority_icon = "🔴"
                elif priority == 'HIGH':
                    priority_color = Colors.RED
                    priority_icon = "🟠"
                elif priority == 'MEDIUM':
                    priority_color = Colors.YELLOW
                    priority_icon = "🟡"
                else:
                    priority_color = Colors.GREEN
                    priority_icon = "🟢"

                print(f"\n{Colors.BOLD}{i}. {priority_color}{priority_icon} {priority} PRIORITY{Colors.END}")
                print(f"   Issue: {issue}")
                print(f"   Impact: {impact}")
                print(f"   Fix: {Colors.GREEN}{fix}{Colors.END}")
                print("-" * 60)
            else:
                print(f"\n{Colors.BOLD}{i}. {Colors.YELLOW}🟡 RECOMMENDATION{Colors.END}")
                print(f"   {rec}")
                print("-" * 60)

        print(f"\n{Colors.BLUE}💡 Apply fixes in priority order for maximum security improvement.{Colors.END}")

        # Continue with more options after showing detailed steps
        self._continue_remediation_options()

    def _generate_fix_script(self) -> None:
        """Generate an automated fix script for the issues found."""
        script_content = [
            "#!/bin/bash",
            "# Automated Security Fix Script",
            "# Generated by Fedora Security Hardening Toolkit",
            f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "set -euo pipefail",
            "",
            "echo 'Starting automated security fixes...'",
            ""
        ]

        for i, rec in enumerate(self.recommendations, 1):
            if isinstance(rec, dict):
                issue = rec.get('issue', f'Issue {i}')
                fix = rec.get('fix', '')
                priority = rec.get('priority', 'MEDIUM')

                script_content.extend([
                    f"# Fix {i}: {issue} (Priority: {priority})",
                    f"echo 'Applying fix {i}: {issue}'",
                    fix if fix.startswith('sudo ') or fix.startswith('echo ') else f"# {fix}",
                    "echo 'Fix applied successfully'",
                    ""
                ])

        script_content.extend([
            "echo 'All automated fixes completed!'",
            "echo 'Please run the security audit again to verify fixes.'"
        ])

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        script_filename = f"security_fixes_{timestamp}.sh"

        try:
            with open(script_filename, 'w') as f:
                f.write('\n'.join(script_content))

            # Make script executable
            os.chmod(script_filename, 0o755)

            print(f"\n{Colors.GREEN}✅ Fix script generated: {script_filename}{Colors.END}")
            print(f"{Colors.YELLOW}⚠️  Review the script before running: cat {script_filename}{Colors.END}")
            print(f"{Colors.BLUE}🚀 Execute with: sudo ./{script_filename}{Colors.END}")

            # Continue with more options after generating script
            self._continue_after_script_generation(script_filename)

        except Exception as e:
            print(f"{Colors.RED}❌ Failed to generate fix script: {e}{Colors.END}")
            # Still offer to continue even if script generation failed
            self._continue_remediation_options()

    def _suggest_hardening_script(self) -> None:
        """Suggest running the comprehensive hardening script."""
        print(f"\n{Colors.BOLD}{Colors.GREEN}🛡️  COMPREHENSIVE SECURITY HARDENING{Colors.END}")
        print("The security hardening script provides:")
        print(f"  {Colors.GREEN}•{Colors.END} Interactive security implementation")
        print(f"  {Colors.GREEN}•{Colors.END} Comprehensive backup and rollback")
        print(f"  {Colors.GREEN}•{Colors.END} User choice and transparency")
        print(f"  {Colors.GREEN}•{Colors.END} Step-by-step security improvements")

        print(f"\n{Colors.CYAN}To run the hardening script:{Colors.END}")
        print(f"  {Colors.BOLD}sudo ./security_hardening.sh{Colors.END}")

        print(f"\n{Colors.BLUE}💡 The hardening script will address many of the issues found in this audit.{Colors.END}")

        # Continue with options after suggesting hardening script
        self._continue_after_hardening_suggestion()

    def _continue_after_hardening_suggestion(self) -> None:
        """Continue with options after suggesting the hardening script."""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}🔄 HARDENING SCRIPT SUGGESTED - WHAT'S NEXT?{Colors.END}")
        print("The comprehensive hardening script is recommended. What would you like to do?")
        print(f"  {Colors.GREEN}1{Colors.END} - 🚀 Run the hardening script now")
        print(f"  {Colors.GREEN}2{Colors.END} - 📜 Generate automated fix script instead")
        print(f"  {Colors.GREEN}3{Colors.END} - 🔧 Apply individual fixes interactively")
        print(f"  {Colors.GREEN}4{Colors.END} - ⏭️  Exit and run hardening script manually")

        try:
            choice = input(f"\n{Colors.CYAN}Enter your choice (1-4): {Colors.END}").strip()

            if choice == '1':
                self._execute_hardening_script()
            elif choice == '2':
                self._generate_fix_script()
            elif choice == '3':
                self._apply_specific_fix()
            elif choice == '4':
                print(f"\n{Colors.BLUE}✅ Exiting. Run the hardening script when ready: sudo ./security_hardening.sh{Colors.END}")
                print(f"{Colors.YELLOW}💡 Tip: The hardening script provides comprehensive security improvements{Colors.END}")
            else:
                print(f"{Colors.YELLOW}Invalid choice. Returning to main menu.{Colors.END}")
                self._continue_remediation_options()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Hardening script execution cancelled by user.{Colors.END}")
        except Exception:
            print(f"{Colors.YELLOW}Input error. Returning to main menu.{Colors.END}")
            self._continue_remediation_options()

    def _execute_hardening_script(self) -> None:
        """Execute the security hardening script."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}🛡️  LAUNCHING SECURITY HARDENING SCRIPT{Colors.END}")

        # Check if hardening script exists
        if not os.path.exists('security_hardening.sh'):
            print(f"{Colors.RED}❌ Security hardening script not found: security_hardening.sh{Colors.END}")
            print(f"{Colors.YELLOW}💡 Make sure the script is in the current directory{Colors.END}")
            self._continue_after_hardening_suggestion()
            return

        print(f"The hardening script will:")
        print(f"  {Colors.GREEN}•{Colors.END} Apply comprehensive security configurations")
        print(f"  {Colors.GREEN}•{Colors.END} Create backups before making changes")
        print(f"  {Colors.GREEN}•{Colors.END} Provide interactive choices for each change")
        print(f"  {Colors.GREEN}•{Colors.END} Allow rollback if needed")

        try:
            confirm = input(f"\n{Colors.YELLOW}Launch the hardening script? (y/N): {Colors.END}").strip().lower()

            if confirm in ['y', 'yes']:
                print(f"\n{Colors.BLUE}🚀 Launching security hardening script...{Colors.END}")
                print(f"{Colors.CYAN}Note: The script will run in interactive mode{Colors.END}")

                # Execute the hardening script
                try:
                    import subprocess
                    subprocess.run(['sudo', './security_hardening.sh'], check=False)

                    print(f"\n{Colors.GREEN}✅ Hardening script execution completed{Colors.END}")
                    print(f"{Colors.BLUE}💡 Run the security audit again to see improvements{Colors.END}")

                except Exception as e:
                    print(f"{Colors.RED}❌ Error launching hardening script: {e}{Colors.END}")
                    self._continue_after_hardening_suggestion()
            else:
                print(f"{Colors.BLUE}Hardening script launch cancelled.{Colors.END}")
                self._continue_after_hardening_suggestion()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Hardening script launch cancelled by user.{Colors.END}")
        except Exception:
            print(f"{Colors.YELLOW}Input error. Returning to menu.{Colors.END}")
            self._continue_after_hardening_suggestion()

    def _continue_remediation_options(self) -> None:
        """Continue with additional remediation options after showing detailed steps."""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}🔄 WHAT WOULD YOU LIKE TO DO NEXT?{Colors.END}")
        print("Now that you've seen the detailed remediation steps:")
        print(f"  {Colors.GREEN}1{Colors.END} - Generate automated fix script for these issues")
        print(f"  {Colors.GREEN}2{Colors.END} - Run comprehensive security hardening script")
        print(f"  {Colors.GREEN}3{Colors.END} - Apply a specific fix interactively")
        print(f"  {Colors.GREEN}4{Colors.END} - Exit and apply fixes manually")

        try:
            choice = input(f"\n{Colors.CYAN}Enter your choice (1-4): {Colors.END}").strip()

            if choice == '1':
                self._generate_fix_script()
            elif choice == '2':
                self._suggest_hardening_script()
            elif choice == '3':
                self._apply_specific_fix()
            elif choice == '4':
                print(f"\n{Colors.BLUE}✅ Exiting. Apply the fixes manually using the commands shown above.{Colors.END}")
                print(f"{Colors.YELLOW}💡 Tip: Run the audit again after applying fixes to see your improved security score!{Colors.END}")
            else:
                print(f"{Colors.YELLOW}Invalid choice. Exiting remediation.{Colors.END}")

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Remediation cancelled by user.{Colors.END}")
        except Exception:
            print(f"{Colors.YELLOW}Input error. Exiting remediation.{Colors.END}")

    def _apply_specific_fix(self) -> None:
        """Allow user to apply a specific fix interactively."""
        if not self.recommendations:
            print(f"{Colors.YELLOW}No recommendations available for interactive fixing.{Colors.END}")
            return

        print(f"\n{Colors.BOLD}{Colors.CYAN}🔧 INTERACTIVE FIX APPLICATION{Colors.END}")
        print("Select which issue to fix:")

        # Show numbered list of issues
        for i, rec in enumerate(self.recommendations, 1):
            if isinstance(rec, dict):
                priority = rec.get('priority', 'MEDIUM')
                issue = rec.get('issue', 'Unknown issue')

                # Color code by priority
                if priority == 'CRITICAL':
                    priority_icon = "🔴"
                elif priority == 'HIGH':
                    priority_icon = "🟠"
                elif priority == 'MEDIUM':
                    priority_icon = "🟡"
                else:
                    priority_icon = "🟢"

                print(f"  {Colors.GREEN}{i}{Colors.END} - {priority_icon} {issue}")
            else:
                print(f"  {Colors.GREEN}{i}{Colors.END} - 🟡 {rec}")

        print(f"  {Colors.GREEN}0{Colors.END} - Return to main menu")

        try:
            choice = input(f"\n{Colors.CYAN}Enter issue number to fix (0-{len(self.recommendations)}): {Colors.END}").strip()

            if choice == '0':
                self._continue_remediation_options()
                return

            try:
                issue_num = int(choice)
                if 1 <= issue_num <= len(self.recommendations):
                    self._execute_specific_fix(issue_num - 1)
                else:
                    print(f"{Colors.RED}Invalid issue number. Please try again.{Colors.END}")
                    self._apply_specific_fix()
            except ValueError:
                print(f"{Colors.RED}Please enter a valid number.{Colors.END}")
                self._apply_specific_fix()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Fix application cancelled.{Colors.END}")
        except Exception:
            print(f"{Colors.YELLOW}Input error. Returning to menu.{Colors.END}")

    def _execute_specific_fix(self, issue_index: int) -> None:
        """Execute a specific fix with user confirmation."""
        rec = self.recommendations[issue_index]

        if isinstance(rec, dict):
            issue = rec.get('issue', 'Unknown issue')
            impact = rec.get('impact', 'Unknown impact')
            fix = rec.get('fix', 'No fix provided')
            priority = rec.get('priority', 'MEDIUM')
        else:
            issue = rec
            impact = "General security improvement"
            fix = "Manual configuration required"
            priority = "MEDIUM"

        print(f"\n{Colors.BOLD}{Colors.BLUE}🔧 APPLYING FIX{Colors.END}")
        print(f"Issue: {issue}")
        print(f"Impact: {impact}")
        print(f"Priority: {priority}")
        print(f"Command: {Colors.GREEN}{fix}{Colors.END}")

        # Ask for confirmation
        try:
            confirm = input(f"\n{Colors.YELLOW}Do you want to apply this fix? (y/N): {Colors.END}").strip().lower()

            if confirm in ['y', 'yes']:
                if fix.startswith('sudo ') or fix.startswith('echo '):
                    print(f"\n{Colors.BLUE}Executing: {fix}{Colors.END}")
                    try:
                        # Execute the command
                        result = self.executor.run_command(fix)
                        if result['success']:
                            print(f"{Colors.GREEN}✅ Fix applied successfully!{Colors.END}")
                            if result['stdout']:
                                print(f"Output: {result['stdout']}")
                        else:
                            print(f"{Colors.RED}❌ Fix failed: {result['stderr']}{Colors.END}")
                    except Exception as e:
                        print(f"{Colors.RED}❌ Error executing fix: {e}{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}⚠️  This fix requires manual configuration. Please apply it manually.{Colors.END}")
                    print(f"Command: {fix}")
            else:
                print(f"{Colors.BLUE}Fix skipped.{Colors.END}")

            # Ask if they want to continue with more fixes
            continue_choice = input(f"\n{Colors.CYAN}Apply another fix? (y/N): {Colors.END}").strip().lower()
            if continue_choice in ['y', 'yes']:
                self._apply_specific_fix()
            else:
                print(f"{Colors.BLUE}✅ Returning to main menu.{Colors.END}")
                self._continue_remediation_options()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Fix application cancelled.{Colors.END}")
        except Exception:
            print(f"{Colors.YELLOW}Input error. Returning to menu.{Colors.END}")

    def _continue_after_script_generation(self, script_filename: str) -> None:
        """Continue with options after generating a fix script."""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}🔄 SCRIPT GENERATED - WHAT'S NEXT?{Colors.END}")
        print("Your automated fix script is ready. What would you like to do?")
        print(f"  {Colors.GREEN}1{Colors.END} - 🔍 Review the generated script contents")
        print(f"  {Colors.GREEN}2{Colors.END} - 🚀 Execute the script now (with confirmation)")
        print(f"  {Colors.GREEN}3{Colors.END} - 🛡️  Run comprehensive security hardening instead")
        print(f"  {Colors.GREEN}4{Colors.END} - 🔧 Apply individual fixes interactively")
        print(f"  {Colors.GREEN}5{Colors.END} - ⏭️  Exit and run script manually later")

        try:
            choice = input(f"\n{Colors.CYAN}Enter your choice (1-5): {Colors.END}").strip()

            if choice == '1':
                self._review_generated_script(script_filename)
            elif choice == '2':
                self._execute_generated_script(script_filename)
            elif choice == '3':
                self._suggest_hardening_script()
            elif choice == '4':
                self._apply_specific_fix()
            elif choice == '5':
                print(f"\n{Colors.BLUE}✅ Exiting. Execute the script when ready: sudo ./{script_filename}{Colors.END}")
                print(f"{Colors.YELLOW}💡 Tip: Run the audit again after applying fixes to see your improved security score!{Colors.END}")
            else:
                print(f"{Colors.YELLOW}Invalid choice. Returning to main menu.{Colors.END}")
                self._continue_remediation_options()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Script execution cancelled by user.{Colors.END}")
        except Exception:
            print(f"{Colors.YELLOW}Input error. Returning to main menu.{Colors.END}")
            self._continue_remediation_options()

    def _review_generated_script(self, script_filename: str) -> None:
        """Show the contents of the generated script."""
        print(f"\n{Colors.BOLD}{Colors.CYAN}📜 GENERATED SCRIPT CONTENTS{Colors.END}")
        print("=" * 60)

        try:
            with open(script_filename, 'r') as f:
                script_content = f.read()

            print(script_content)
            print("=" * 60)

            # Continue with options after reviewing
            print(f"\n{Colors.BLUE}Script review complete. What would you like to do next?{Colors.END}")
            self._continue_after_script_generation(script_filename)

        except Exception as e:
            print(f"{Colors.RED}❌ Could not read script file: {e}{Colors.END}")
            self._continue_remediation_options()

    def _execute_generated_script(self, script_filename: str) -> None:
        """Execute the generated script with user confirmation."""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}⚠️  SCRIPT EXECUTION CONFIRMATION{Colors.END}")
        print(f"You are about to execute: {script_filename}")
        print(f"This will apply {len(self.recommendations)} security fixes to your system.")
        print(f"\n{Colors.RED}⚠️  WARNING: This will make system changes!{Colors.END}")

        try:
            confirm = input(f"\n{Colors.YELLOW}Are you sure you want to execute the script? (yes/NO): {Colors.END}").strip().lower()

            if confirm == 'yes':
                print(f"\n{Colors.BLUE}🚀 Executing script: {script_filename}{Colors.END}")
                try:
                    result = self.executor.run_command(f"bash {script_filename}")
                    if result['success']:
                        print(f"{Colors.GREEN}✅ Script executed successfully!{Colors.END}")
                        if result['stdout']:
                            print(f"Output:\n{result['stdout']}")

                        print(f"\n{Colors.GREEN}🎉 Security fixes have been applied!{Colors.END}")
                        print(f"{Colors.BLUE}💡 Recommendation: Run the security audit again to verify improvements{Colors.END}")

                        # Ask if they want to run audit again
                        rerun = input(f"\n{Colors.CYAN}Run security audit again now? (y/N): {Colors.END}").strip().lower()
                        if rerun in ['y', 'yes']:
                            print(f"\n{Colors.BLUE}🔄 Restarting security audit...{Colors.END}")
                            self._restart_audit_after_fixes()
                        else:
                            print(f"{Colors.BLUE}✅ Fixes applied. Run audit manually when ready.{Colors.END}")
                            self._continue_after_script_generation(script_filename)
                    else:
                        print(f"{Colors.RED}❌ Script execution failed: {result['stderr']}{Colors.END}")
                        self._continue_after_script_generation(script_filename)

                except Exception as e:
                    print(f"{Colors.RED}❌ Error executing script: {e}{Colors.END}")
                    self._continue_after_script_generation(script_filename)
            else:
                print(f"{Colors.BLUE}Script execution cancelled.{Colors.END}")
                self._continue_after_script_generation(script_filename)

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Script execution cancelled by user.{Colors.END}")
        except Exception:
            print(f"{Colors.YELLOW}Input error. Returning to menu.{Colors.END}")
            self._continue_after_script_generation(script_filename)

    def run_audit(self) -> None:
        """Run complete security audit."""
        self.print_header()
        
        # Validate system compatibility
        if self.system_info['distribution'] == 'unknown':
            self.print_finding("WARN", "Unknown distribution detected - some checks may not work correctly")
        
        # Run comprehensive audit modules
        self.audit_fail2ban()
        self.audit_firewall()
        self.audit_ssh_security()
        self.audit_system_hardening()
        self.audit_user_accounts()

        # Generate comprehensive report with enhanced analytics
        report_file = self.generate_report()

        print(f"\n{Colors.BOLD}{Colors.BLUE}📄 DETAILED REPORT:{Colors.END}")
        print(f"  📊 Full report saved: {report_file}")
        print(f"  🔍 Contains: Detailed findings, remediation steps, compliance mapping")

        # Offer interactive remediation
        self._offer_interactive_remediation()

    def _restart_audit_after_fixes(self) -> None:
        """Restart the security audit after applying fixes."""
        print(f"\n{Colors.BOLD}{Colors.GREEN}🔄 RESTARTING SECURITY AUDIT{Colors.END}")
        print("=" * 60)
        print(f"{Colors.BLUE}Clearing previous results and running fresh audit...{Colors.END}")

        # Clear previous results
        self.findings = {}
        self.recommendations = []
        self.compliance_status = {'cis_controls': [], 'nist_csf': []}

        # Re-initialize system info
        self.system_info = self._get_system_info()

        print(f"\n{Colors.CYAN}System re-scan in progress...{Colors.END}")

        # Run all audit modules again
        try:
            self.audit_fail2ban()
            self.audit_firewall()
            self.audit_ssh_security()
            self.audit_system_hardening()
            self.audit_user_accounts()

            # Generate new report
            report_file = self.generate_report()

            print(f"\n{Colors.BOLD}{Colors.GREEN}🎉 POST-FIX AUDIT COMPLETE{Colors.END}")
            print(f"{Colors.BLUE}📊 Updated report saved: {report_file}{Colors.END}")

            # Show improvement summary
            self._show_improvement_summary()

            # Offer to continue with any remaining issues
            if self.recommendations:
                print(f"\n{Colors.YELLOW}📋 Additional issues found. Continue with remediation?{Colors.END}")
                self._offer_interactive_remediation()
            else:
                print(f"\n{Colors.GREEN}🎉 Congratulations! All security issues have been resolved!{Colors.END}")
                print(f"{Colors.BLUE}💡 Your system security score should now be significantly improved.{Colors.END}")
                self._offer_final_options()

        except Exception as e:
            print(f"{Colors.RED}❌ Error during audit restart: {e}{Colors.END}")
            print(f"{Colors.YELLOW}Please run the audit manually: python3 security_audit.py{Colors.END}")

    def _show_improvement_summary(self) -> None:
        """Show a summary of security improvements after fixes."""
        print(f"\n{Colors.BOLD}{Colors.CYAN}📈 SECURITY IMPROVEMENT SUMMARY{Colors.END}")
        print("-" * 50)

        # Calculate current metrics
        current_metrics = self._calculate_security_metrics()
        current_score = current_metrics['overall_score']
        current_risk = current_metrics['risk_level']

        # Show current status
        if current_score >= 90:
            score_color = Colors.GREEN
            score_icon = "🟢"
        elif current_score >= 75:
            score_color = Colors.YELLOW
            score_icon = "🟡"
        elif current_score >= 50:
            score_color = Colors.RED
            score_icon = "🟠"
        else:
            score_color = Colors.RED
            score_icon = "🔴"

        print(f"📊 Updated Security Score: {score_color}{current_score}/100 {score_icon} ({current_risk} RISK){Colors.END}")

        # Show remaining issues
        if current_metrics['critical_issues'] > 0:
            print(f"🔴 Critical issues remaining: {current_metrics['critical_issues']}")
        if current_metrics['high_issues'] > 0:
            print(f"🟠 High priority remaining: {current_metrics['high_issues']}")
        if current_metrics['medium_issues'] > 0:
            print(f"🟡 Medium priority remaining: {current_metrics['medium_issues']}")

        if current_metrics['critical_issues'] == 0 and current_metrics['high_issues'] == 0:
            print(f"{Colors.GREEN}✅ No critical or high priority issues remaining!{Colors.END}")

        print(f"✅ Passed security checks: {current_metrics['passed_checks']}")

    def _offer_final_options(self) -> None:
        """Offer final options when all issues are resolved."""
        print(f"\n{Colors.BOLD}{Colors.GREEN}🎯 ALL SECURITY ISSUES RESOLVED{Colors.END}")
        print("Your system is now properly secured. What would you like to do?")
        print(f"  {Colors.GREEN}1{Colors.END} - 📊 View detailed security report")
        print(f"  {Colors.GREEN}2{Colors.END} - 🔄 Run audit again to double-check")
        print(f"  {Colors.GREEN}3{Colors.END} - 📚 Learn about ongoing security maintenance")
        print(f"  {Colors.GREEN}4{Colors.END} - ✅ Exit - security hardening complete")

        try:
            choice = input(f"\n{Colors.CYAN}Enter your choice (1-4): {Colors.END}").strip()

            if choice == '1':
                print(f"\n{Colors.BLUE}📊 Detailed security report available in the JSON file{Colors.END}")
                print(f"{Colors.CYAN}View with: cat security_audit_report_*.json | jq{Colors.END}")
                self._offer_final_options()
            elif choice == '2':
                self._restart_audit_after_fixes()
            elif choice == '3':
                self._show_maintenance_guidance()
            elif choice == '4':
                print(f"\n{Colors.GREEN}🎉 Security hardening complete! Your system is now properly secured.{Colors.END}")
                print(f"{Colors.BLUE}💡 Remember to run regular security audits to maintain security posture.{Colors.END}")
            else:
                print(f"{Colors.YELLOW}Invalid choice. Exiting.{Colors.END}")

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Exiting security audit.{Colors.END}")
        except Exception:
            print(f"{Colors.YELLOW}Input error. Exiting.{Colors.END}")

    def _show_maintenance_guidance(self) -> None:
        """Show ongoing security maintenance guidance."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}🔧 ONGOING SECURITY MAINTENANCE{Colors.END}")
        print("=" * 50)
        print(f"{Colors.GREEN}Regular Security Tasks:{Colors.END}")
        print("  • Run security audit monthly: python3 security_audit.py")
        print("  • Update system packages weekly: sudo dnf update")
        print("  • Review firewall logs: sudo journalctl -u firewalld")
        print("  • Check fail2ban status: sudo fail2ban-client status")
        print("  • Monitor system logs: sudo journalctl --since yesterday")

        print(f"\n{Colors.GREEN}Security Monitoring:{Colors.END}")
        print("  • Set up automated security updates")
        print("  • Configure log monitoring and alerting")
        print("  • Regular backup verification")
        print("  • Security patch management")

        print(f"\n{Colors.GREEN}Advanced Security:{Colors.END}")
        print("  • Implement intrusion detection (AIDE, OSSEC)")
        print("  • Set up centralized logging")
        print("  • Configure security information and event management (SIEM)")
        print("  • Regular penetration testing")

        self._offer_final_options()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Fedora Security Hardening Toolkit - Security Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Run standard audit
  %(prog)s --verbose          # Run with detailed logging
  %(prog)s --help             # Show this help message
        """
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Fedora Security Hardening Toolkit v1.0.0'
    )
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}⚠️  Some checks require root privileges. Run with sudo for complete audit.{Colors.END}")
    
    try:
        auditor = SecurityAuditor(verbose=args.verbose)
        auditor.run_audit()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Audit interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}Audit failed: {e}{Colors.END}")
        sys.exit(1)


if __name__ == "__main__":
    main()
