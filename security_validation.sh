#!/bin/bash
# Security Validation Testing Script for Apple A1286
# Based on CIS Benchmarks, NIST Framework, and official security documentation
# References:
# - CIS Controls v8
# - NIST Cybersecurity Framework
# - https://github.com/imthenachoman/How-To-Secure-A-Linux-Server
# - Official distribution security guides

set -euo pipefail

# Script metadata
readonly SCRIPT_VERSION="2.0.0"
readonly COMPLIANCE_FRAMEWORKS="CIS Controls v8, NIST CSF"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Configuration
LOG_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly LOG_FILE="/tmp/security_validation_${LOG_TIMESTAMP}.log"

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNING_TESTS=0

# Detect distribution
detect_distribution() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/etc/os-release
        source /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distribution)
readonly DISTRO

log_test() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           SECURITY VALIDATION TESTING v${SCRIPT_VERSION}              ║"
    echo "║              Apple A1286 Security Assessment                ║"
    echo "║        Based on Official Documentation & Standards          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${BLUE}Distribution: ${DISTRO}${NC}"
    echo -e "${BLUE}Test log: ${LOG_FILE}${NC}"
    echo -e "${BLUE}Compliance frameworks: ${COMPLIANCE_FRAMEWORKS}${NC}"
}

print_section() {
    echo -e "\n${BOLD}${YELLOW}=== $1 ===${NC}"
    log_test "Testing section: $1"
}

print_pass() {
    echo -e "${GREEN}✅ PASS: $1${NC}"
    log_test "PASS: $1"
    ((PASSED_TESTS++))
    ((TOTAL_TESTS++))
}

print_fail() {
    echo -e "${RED}❌ FAIL: $1${NC}"
    log_test "FAIL: $1"
    ((FAILED_TESTS++))
    ((TOTAL_TESTS++))
}

print_warn() {
    echo -e "${YELLOW}⚠️  WARN: $1${NC}"
    log_test "WARN: $1"
    ((WARNING_TESTS++))
    ((TOTAL_TESTS++))
}

print_info() {
    echo -e "${BLUE}ℹ️  INFO: $1${NC}"
    log_test "INFO: $1"
}

run_test() {
    local command="$1"
    local description="$2"
    local timeout="${3:-10}"
    
    if timeout "$timeout" bash -c "$command" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

test_fail2ban_protection() {
    print_section "FAIL2BAN INTRUSION PREVENTION VALIDATION (CIS 6.2)"
    
    # Test 1: Check if fail2ban service is active
    if systemctl is-active --quiet fail2ban; then
        print_pass "Fail2ban service is active"
        
        # Test 2: Check if SSH jail is configured
        if fail2ban-client status sshd &>/dev/null; then
            print_pass "SSH jail is configured and active"
            
            # Test 3: Check jail configuration
            local jail_info=$(fail2ban-client status sshd 2>/dev/null)
            if echo "$jail_info" | grep -q "Currently failed:"; then
                print_pass "SSH jail is monitoring failed attempts"
            else
                print_warn "SSH jail status unclear"
            fi
            
            # Test 4: Check ban time configuration
            local jail_config=$(fail2ban-client get sshd bantime 2>/dev/null || echo "0")
            if [[ "$jail_config" -ge 3600 ]]; then
                print_pass "SSH jail ban time is appropriately configured (≥1 hour)"
            else
                print_warn "SSH jail ban time may be too short: ${jail_config}s"
            fi
            
        else
            print_fail "SSH jail is not configured or active"
        fi
        
        # Test 5: Check for recidive jail (repeat offender protection)
        if fail2ban-client status recidive &>/dev/null; then
            print_pass "Recidive jail is configured for repeat offenders"
        else
            print_warn "Recidive jail not configured - consider for enhanced protection"
        fi
        
    else
        print_fail "Fail2ban service is not active"
    fi
}

test_firewall_configuration() {
    print_section "FIREWALL CONFIGURATION VALIDATION (CIS 3.5)"
    
    # Test 1: Check if firewalld is active (preferred for Fedora/RHEL)
    if systemctl is-active --quiet firewalld; then
        print_pass "Firewalld service is active"
        
        # Test 2: Check default zone security
        local default_zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
        case "$default_zone" in
            "drop"|"block")
                print_pass "Using secure default zone: $default_zone"
                ;;
            "public")
                print_warn "Using 'public' zone - consider 'drop' for maximum security"
                ;;
            "home"|"work")
                print_info "Using '$default_zone' zone - appropriate for trusted networks"
                ;;
            *)
                print_warn "Using '$default_zone' zone - review security implications"
                ;;
        esac
        
        # Test 3: Check for unnecessary services
        local zone_config=$(firewall-cmd --list-all 2>/dev/null || echo "")
        
        # Check for insecure services
        if echo "$zone_config" | grep -qi "ftp"; then
            print_fail "FTP service is allowed (insecure - use SFTP)"
        fi
        
        if echo "$zone_config" | grep -qi "telnet"; then
            print_fail "Telnet service is allowed (insecure - use SSH)"
        fi
        
        if echo "$zone_config" | grep -qi "ssh"; then
            print_pass "SSH service is properly allowed"
        fi
        
        # Test 4: Check logging configuration
        local log_denied=$(firewall-cmd --get-log-denied 2>/dev/null || echo "off")
        if [[ "$log_denied" != "off" ]]; then
            print_pass "Firewall logging is enabled: $log_denied"
        else
            print_warn "Firewall logging for denied packets is disabled"
        fi
        
    else
        # Check for alternative firewalls
        if systemctl is-active --quiet ufw; then
            print_info "UFW firewall is active (alternative to firewalld)"
            # Basic UFW tests could be added here
        elif command -v iptables &>/dev/null; then
            local iptables_rules=$(iptables -L -n 2>/dev/null | grep -v '^Chain\|^target' | wc -l)
            if [[ "$iptables_rules" -gt 0 ]]; then
                print_info "Custom iptables rules detected ($iptables_rules rules)"
            else
                print_fail "No active firewall detected"
            fi
        else
            print_fail "No firewall system found"
        fi
    fi
}

test_ssh_security() {
    print_section "SSH SECURITY CONFIGURATION VALIDATION (CIS 5.2)"
    
    if [[ -f /etc/ssh/sshd_config ]]; then
        local ssh_config="/etc/ssh/sshd_config"
        
        # Test 1: Root login disabled
        if grep -q "^PermitRootLogin no" "$ssh_config"; then
            print_pass "Root login is disabled"
        elif grep -q "^PermitRootLogin" "$ssh_config"; then
            local root_setting=$(grep "^PermitRootLogin" "$ssh_config" | awk '{print $2}')
            print_fail "Root login setting: $root_setting (should be 'no')"
        else
            print_warn "Root login setting not explicitly configured"
        fi
        
        # Test 2: Password authentication
        if grep -q "^PasswordAuthentication no" "$ssh_config"; then
            print_pass "Password authentication is disabled (key-based auth only)"
        elif grep -q "^PasswordAuthentication yes" "$ssh_config"; then
            print_warn "Password authentication is enabled (consider key-based auth)"
        else
            print_info "Password authentication setting uses default"
        fi
        
        # Test 3: Protocol version
        if grep -q "^Protocol 2" "$ssh_config"; then
            print_pass "SSH Protocol 2 is enforced"
        else
            print_info "SSH protocol version uses default (should be Protocol 2)"
        fi
        
        # Test 4: Max authentication tries
        local max_auth=$(grep "^MaxAuthTries" "$ssh_config" | awk '{print $2}' 2>/dev/null || echo "6")
        if [[ "$max_auth" -le 3 ]]; then
            print_pass "MaxAuthTries is set to secure value: $max_auth"
        else
            print_warn "MaxAuthTries could be lower (current: $max_auth, recommended: ≤3)"
        fi
        
        # Test 5: X11 forwarding
        if grep -q "^X11Forwarding no" "$ssh_config"; then
            print_pass "X11 forwarding is disabled"
        elif grep -q "^X11Forwarding yes" "$ssh_config"; then
            print_warn "X11 forwarding is enabled (security risk if not needed)"
        fi
        
        # Test 6: Empty passwords
        if grep -q "^PermitEmptyPasswords no" "$ssh_config"; then
            print_pass "Empty passwords are not permitted"
        elif grep -q "^PermitEmptyPasswords yes" "$ssh_config"; then
            print_fail "Empty passwords are permitted (security risk)"
        fi
        
    else
        print_fail "SSH configuration file not found"
    fi
}

test_network_security_parameters() {
    print_section "NETWORK SECURITY PARAMETERS VALIDATION (CIS 3.1-3.4)"
    
    # Test 1: IP forwarding disabled
    local ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "1")
    if [[ "$ip_forward" == "0" ]]; then
        print_pass "IPv4 forwarding is disabled"
    else
        print_fail "IPv4 forwarding is enabled (security risk for non-router systems)"
    fi
    
    # Test 2: Source routing disabled
    local source_route=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null || echo "1")
    if [[ "$source_route" == "0" ]]; then
        print_pass "Source routing is disabled"
    else
        print_fail "Source routing is enabled (security risk)"
    fi
    
    # Test 3: ICMP redirects disabled
    local icmp_redirects=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "1")
    if [[ "$icmp_redirects" == "0" ]]; then
        print_pass "ICMP redirects are disabled"
    else
        print_fail "ICMP redirects are enabled (security risk)"
    fi
    
    # Test 4: TCP SYN cookies enabled
    local syn_cookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "0")
    if [[ "$syn_cookies" == "1" ]]; then
        print_pass "TCP SYN cookies are enabled (DDoS protection)"
    else
        print_warn "TCP SYN cookies are disabled (consider enabling for DDoS protection)"
    fi
    
    # Test 5: ICMP echo (ping) response
    local icmp_echo=$(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null || echo "0")
    if [[ "$icmp_echo" == "1" ]]; then
        print_pass "ICMP echo requests are ignored (stealth mode)"
    else
        print_info "ICMP echo requests are allowed (ping works)"
    fi
}

generate_security_report() {
    print_section "SECURITY VALIDATION SUMMARY"
    
    echo -e "\n${BOLD}Security Validation Results:${NC}"
    echo "======================================"
    echo "Total Tests: $TOTAL_TESTS"
    echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "${YELLOW}Warnings: $WARNING_TESTS${NC}"
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
    
    # Calculate security score
    local security_score=0
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        security_score=$(( (PASSED_TESTS * 100) / TOTAL_TESTS ))
    fi
    
    echo -e "\n${BOLD}Security Score: ${security_score}%${NC}"
    
    # Security assessment
    if [[ $security_score -ge 90 ]]; then
        echo -e "${GREEN}🎉 Excellent security posture!${NC}"
    elif [[ $security_score -ge 75 ]]; then
        echo -e "${YELLOW}⚠️  Good security with room for improvement${NC}"
    elif [[ $security_score -ge 50 ]]; then
        echo -e "${YELLOW}⚠️  Moderate security - several issues need attention${NC}"
    else
        echo -e "${RED}❌ Poor security posture - immediate action required${NC}"
    fi
    
    echo -e "\nDetailed log: $LOG_FILE"
    
    # Show failed tests summary
    if [[ $FAILED_TESTS -gt 0 ]]; then
        echo -e "\n${RED}Critical Issues Requiring Attention:${NC}"
        grep "FAIL:" "$LOG_FILE" | sed 's/.*FAIL: /• /' | head -10
    fi
    
    # Show warnings summary
    if [[ $WARNING_TESTS -gt 0 ]]; then
        echo -e "\n${YELLOW}Recommendations for Improvement:${NC}"
        grep "WARN:" "$LOG_FILE" | sed 's/.*WARN: /• /' | head -5
    fi
}

main() {
    print_header
    
    log_test "Starting security validation testing"
    
    # Run all test suites
    test_fail2ban_protection
    test_firewall_configuration
    test_ssh_security
    test_network_security_parameters
    
    # Generate final report
    generate_security_report
    
    echo -e "\n${BOLD}${GREEN}🔒 Security validation completed${NC}"
    echo -e "${BLUE}Review the detailed log: $LOG_FILE${NC}"
    
    # Exit with appropriate code
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# Check if running as root for some tests
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}⚠️  Some tests require root privileges. Run with sudo for complete testing.${NC}"
fi

main "$@"
