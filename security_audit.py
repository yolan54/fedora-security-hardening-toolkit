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
    
    def run_audit(self) -> None:
        """Run complete security audit."""
        self.print_header()
        
        # Validate system compatibility
        if self.system_info['distribution'] == 'unknown':
            self.print_finding("WARN", "Unknown distribution detected - some checks may not work correctly")
        
        # Run audit modules
        self.audit_fail2ban()
        self.audit_firewall()
        
        # Generate comprehensive report with enhanced analytics
        report_file = self.generate_report()

        print(f"\n{Colors.BOLD}{Colors.BLUE}📄 DETAILED REPORT:{Colors.END}")
        print(f"  📊 Full report saved: {report_file}")
        print(f"  🔍 Contains: Detailed findings, remediation steps, compliance mapping")


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
