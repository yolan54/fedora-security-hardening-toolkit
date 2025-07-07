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
        """Audit fail2ban configuration and status."""
        self.print_section("FAIL2BAN INTRUSION PREVENTION AUDIT (CIS 6.2)")
        
        # Check if fail2ban is installed and active
        status_result = self.executor.run_command("systemctl is-active fail2ban")
        
        if status_result['success'] and status_result['stdout'] == 'active':
            self.print_finding("PASS", "Fail2ban service is active")
            
            # Check version
            version_result = self.executor.run_command("fail2ban-client version")
            if version_result['success']:
                version = version_result['stdout'].split('\n')[0] if version_result['stdout'] else 'unknown'
                self.print_finding("INFO", f"Fail2ban version: {version}")
            
            # Check active jails
            jails_result = self.executor.run_command("fail2ban-client status")
            if jails_result['success']:
                self.print_finding("INFO", "Fail2ban jails status retrieved")
                
                # Parse and check specific jails
                jail_lines = jails_result['stdout'].split('\n')
                for line in jail_lines:
                    if 'Jail list:' in line:
                        jails = line.split('Jail list:')[1].strip()
                        if 'sshd' in jails:
                            self.print_finding("PASS", "SSH jail is configured")
                            self.compliance_status['cis_controls'].append("CIS 6.2 - SSH Protection Active")
                        else:
                            self.print_finding("FAIL", "SSH jail not configured")
                            self.recommendations.append("Configure fail2ban SSH jail for brute force protection")
                        
                        if 'recidive' in jails:
                            self.print_finding("PASS", "Recidive jail configured for repeat offenders")
                        else:
                            self.print_finding("WARN", "Recidive jail not configured")
                            self.recommendations.append("Configure recidive jail for persistent attackers")
            
            # Check configuration files
            config_files = ['/etc/fail2ban/jail.local', '/etc/fail2ban/jail.conf']
            for config_file in config_files:
                if os.path.exists(config_file):
                    self.print_finding("PASS", f"Configuration file exists: {config_file}")
                    break
            else:
                self.print_finding("WARN", "No fail2ban configuration files found")
                
        else:
            self.print_finding("FAIL", "Fail2ban is not installed or not running")
            self.recommendations.append("Install and configure fail2ban for intrusion prevention")
            self.compliance_status['cis_controls'].append("CIS 6.2 - MISSING: Host-Based Intrusion Prevention")
        
        self.findings['fail2ban'] = {
            'installed': status_result['success'],
            'active': status_result['success'] and status_result['stdout'] == 'active'
        }
    
    def audit_firewall(self) -> None:
        """Audit firewall configuration."""
        self.print_section("FIREWALL CONFIGURATION AUDIT (CIS 3.5)")
        
        # Check firewalld (preferred for Fedora/RHEL)
        firewalld_status = self.executor.run_command("systemctl is-active firewalld")
        
        if firewalld_status['success'] and firewalld_status['stdout'] == 'active':
            self.print_finding("PASS", "Firewalld is active")
            
            # Check default zone
            default_zone = self.executor.run_command("firewall-cmd --get-default-zone")
            if default_zone['success']:
                zone = default_zone['stdout']
                if zone in ['drop', 'block']:
                    self.print_finding("PASS", f"Secure default zone configured: {zone}")
                elif zone == 'public':
                    self.print_finding("WARN", "Using 'public' zone - consider 'drop' for maximum security")
                    self.recommendations.append("Consider changing default zone to 'drop' for maximum security")
                else:
                    self.print_finding("INFO", f"Default zone: {zone}")
            
            # Check logging
            log_denied = self.executor.run_command("firewall-cmd --get-log-denied")
            if log_denied['success']:
                if log_denied['stdout'] != 'off':
                    self.print_finding("PASS", f"Firewall logging enabled: {log_denied['stdout']}")
                else:
                    self.print_finding("WARN", "Firewall logging disabled")
                    self.recommendations.append("Enable firewall logging for security monitoring")
            
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
                self.print_finding("FAIL", "No active firewall detected")
                self.recommendations.append("Enable and configure firewalld or alternative firewall")
                self.compliance_status['cis_controls'].append("CIS 3.5 - MISSING: Network Firewall")
        
        self.findings['firewall'] = {
            'firewalld_active': firewalld_status['success'] and firewalld_status['stdout'] == 'active'
        }
    
    def generate_report(self) -> str:
        """Generate comprehensive audit report."""
        report = {
            'metadata': {
                'version': '1.0.0',
                'timestamp': self.system_info['timestamp'],
                'audit_type': 'comprehensive_security_assessment'
            },
            'system_info': self.system_info,
            'findings': self.findings,
            'recommendations': self.recommendations,
            'compliance_status': self.compliance_status,
            'summary': {
                'total_checks': len(self.findings),
                'passed_checks': sum(1 for f in self.findings.values() if f.get('active', False)),
                'failed_checks': sum(1 for f in self.findings.values() if not f.get('active', False)),
                'recommendations_count': len(self.recommendations)
            }
        }
        
        # Calculate security score
        if report['summary']['total_checks'] > 0:
            score = (report['summary']['passed_checks'] / report['summary']['total_checks']) * 100
            report['summary']['security_score'] = round(score, 1)
        else:
            report['summary']['security_score'] = 0
        
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
        
        return report_file
    
    def run_audit(self) -> None:
        """Run complete security audit."""
        self.print_header()
        
        # Validate system compatibility
        if self.system_info['distribution'] == 'unknown':
            self.print_finding("WARN", "Unknown distribution detected - some checks may not work correctly")
        
        # Run audit modules
        self.audit_fail2ban()
        self.audit_firewall()
        
        # Generate and display summary
        report_file = self.generate_report()
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}🎯 AUDIT COMPLETED{Colors.END}")
        print(f"📊 Report saved: {report_file}")
        print(f"📈 Security score: {self.findings.get('security_score', 'N/A')}")
        print(f"📋 Recommendations: {len(self.recommendations)}")


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
