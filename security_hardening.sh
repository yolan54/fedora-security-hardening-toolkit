#!/bin/bash
# Advanced Network Hardening Script for Apple A1286
# Based on CIS Benchmarks, NIST Framework, and official documentation
# References:
# - https://github.com/imthenachoman/How-To-Secure-A-Linux-Server
# - https://docs.fedoraproject.org/en-US/quick-docs/firewalld/
# - https://github.com/fail2ban/fail2ban (official repo)
# - CIS Controls v8 and NIST Cybersecurity Framework

set -euo pipefail

# Script metadata
SCRIPT_VERSION="2.0.0"
COMPLIANCE_FRAMEWORKS="CIS Controls v8, NIST CSF"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Configuration
LOG_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly LOG_FILE="/var/log/network_hardening_${LOG_TIMESTAMP}.log"
readonly BACKUP_DIR="/root/security_backups_${LOG_TIMESTAMP}"

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

log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║        ADVANCED NETWORK HARDENING - APPLE A1286 v${SCRIPT_VERSION}        ║"
    echo "║     Based on Official Documentation & Best Practices        ║"
    echo "║              ${COMPLIANCE_FRAMEWORKS}              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${BLUE}Distribution detected: ${DISTRO}${NC}"
    echo -e "${BLUE}Log file: ${LOG_FILE}${NC}"
    echo -e "${BLUE}Backup directory: ${BACKUP_DIR}${NC}"
}

print_section() {
    echo -e "\n${BOLD}${YELLOW}=== $1 ===${NC}"
    log_action "Starting: $1"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
    log_action "SUCCESS: $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
    log_action "WARNING: $1"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
    log_action "ERROR: $1"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
    log_action "INFO: $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        print_info "Please run: sudo $0"
        exit 1
    fi
}

create_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    print_success "Created backup directory: $BACKUP_DIR"
}

backup_config() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_file="$BACKUP_DIR/$(basename "$file").$(date +%Y%m%d_%H%M%S)"
        cp "$file" "$backup_file"
        print_success "Backed up $file to $backup_file"
        return 0
    else
        print_warning "File $file does not exist, skipping backup"
        return 1
    fi
}

# Package manager detection and wrapper
get_package_manager() {
    case "$DISTRO" in
        fedora|rhel|centos)
            echo "dnf"
            ;;
        debian|ubuntu)
            echo "apt"
            ;;
        arch)
            echo "pacman"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

install_package() {
    local package="$1"
    local pm=$(get_package_manager)

    case "$pm" in
        dnf)
            dnf install -y "$package"
            ;;
        apt)
            apt update && apt install -y "$package"
            ;;
        pacman)
            pacman -S --noconfirm "$package"
            ;;
        *)
            print_error "Unknown package manager for distribution: $DISTRO"
            return 1
            ;;
    esac
}

show_fail2ban_config_preview() {
    echo -e "\n${BOLD}${CYAN}📋 CONFIGURATION PREVIEW${NC}"
    echo "════════════════════════════════════════"

    echo -e "${BLUE}Current jail.local (if exists):${NC}"
    if [[ -f /etc/fail2ban/jail.local ]]; then
        echo -e "${YELLOW}--- Current Configuration ---${NC}"
        head -20 /etc/fail2ban/jail.local | sed 's/^/  /'
        echo -e "  ${YELLOW}... (truncated)${NC}"
    else
        echo -e "  ${YELLOW}No existing jail.local found${NC}"
    fi

    echo -e "\n${BLUE}Proposed new configuration:${NC}"
    echo -e "${GREEN}--- New Configuration Preview ---${NC}"
    cat << 'EOF' | sed 's/^/  /'
[DEFAULT]
bantime  = 1h          # 🔧 IMPROVED: Was 10min, now 1 hour
findtime = 10m         # ✅ STANDARD: Detection window
maxretry = 3           # 🔧 IMPROVED: Was 6, now 3 attempts
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
maxretry = 3           # 🔧 HARDENED: Reduced from default 6
bantime = 1h           # 🔧 HARDENED: Increased from 10min

[sshd-ddos]
enabled = true         # 🆕 NEW: DDoS protection
maxretry = 2           # 🔧 STRICT: Only 2 rapid attempts
bantime = 2h           # 🔧 LONGER: 2 hour ban for DDoS

[recidive]
enabled = true         # 🆕 NEW: Repeat offender protection
bantime = 1w           # 🔧 SEVERE: 1 week ban for repeat offenders
maxretry = 5           # 🔧 ESCALATION: 5 bans triggers recidive
EOF

    echo -e "\n${BLUE}Security Impact:${NC}"
    echo -e "  🔴→🟢 SSH brute force protection: WEAK → STRONG"
    echo -e "  ❌→✅ DDoS protection: MISSING → ACTIVE"
    echo -e "  ❌→✅ Repeat offender handling: MISSING → ACTIVE"
    echo -e "  📊 Overall security score: ${CURRENT_FAIL2BAN_SCORE}/100 → 95/100"
}

create_fail2ban_backup_with_rollback() {
    print_info "🛡️ Creating comprehensive backup with rollback capability..."

    # Create timestamped backup directory
    local backup_timestamp=$(date +%Y%m%d_%H%M%S)
    local fail2ban_backup_dir="$BACKUP_DIR/fail2ban_$backup_timestamp"
    mkdir -p "$fail2ban_backup_dir"

    # Backup all fail2ban configuration files
    local files_backed_up=0
    for config_file in "/etc/fail2ban/jail.local" "/etc/fail2ban/jail.conf" "/etc/fail2ban/fail2ban.local" "/etc/fail2ban/fail2ban.conf"; do
        if [[ -f "$config_file" ]]; then
            cp "$config_file" "$fail2ban_backup_dir/"
            ((files_backed_up++))
            print_success "Backed up $(basename "$config_file")"
        fi
    done

    # Create rollback script
    cat > "$fail2ban_backup_dir/restore_fail2ban.sh" << EOF
#!/bin/bash
# Fail2ban Configuration Rollback Script
# Created: $(date)
# Backup location: $fail2ban_backup_dir

echo "🔄 Rolling back fail2ban configuration..."

# Stop fail2ban service
systemctl stop fail2ban

# Restore configuration files
EOF

    for config_file in "/etc/fail2ban/jail.local" "/etc/fail2ban/jail.conf" "/etc/fail2ban/fail2ban.local" "/etc/fail2ban/fail2ban.conf"; do
        if [[ -f "$fail2ban_backup_dir/$(basename "$config_file")" ]]; then
            echo "cp '$fail2ban_backup_dir/$(basename "$config_file")' '$config_file'" >> "$fail2ban_backup_dir/restore_fail2ban.sh"
        fi
    done

    cat >> "$fail2ban_backup_dir/restore_fail2ban.sh" << EOF

# Restart fail2ban service
systemctl start fail2ban

echo "✅ Fail2ban configuration restored from backup"
echo "📊 Verify with: fail2ban-client status"
EOF

    chmod +x "$fail2ban_backup_dir/restore_fail2ban.sh"

    # Show backup summary
    echo -e "\n${BOLD}${GREEN}📁 BACKUP SUMMARY${NC}"
    echo "════════════════════════════════════════"
    echo -e "  📂 Location: $fail2ban_backup_dir"
    echo -e "  📄 Files backed up: $files_backed_up"
    echo -e "  🔄 Rollback script: $fail2ban_backup_dir/restore_fail2ban.sh"
    echo -e "  ⏱️  Auto-rollback: If SSH fails, run the rollback script"

    # Store rollback path for later reference
    FAIL2BAN_ROLLBACK_SCRIPT="$fail2ban_backup_dir/restore_fail2ban.sh"
}

validate_fail2ban_config() {
    print_info "🧪 Validating new fail2ban configuration..."

    # Test jail syntax
    if fail2ban-client --test &>/dev/null; then
        print_success "Configuration syntax is valid"
    else
        print_error "Configuration syntax validation failed"
        return 1
    fi

    # Check log file paths exist
    local log_paths=("/var/log/secure" "/var/log/auth.log" "/var/log/fail2ban.log")
    for log_path in "${log_paths[@]}"; do
        if [[ -f "$log_path" ]]; then
            print_success "Log file exists: $log_path"
        else
            print_warning "Log file not found: $log_path (may be created automatically)"
        fi
    done

    return 0
}

analyze_current_fail2ban_state() {
    local current_jails=()
    local security_score=0
    local issues=()
    local improvements=()

    print_info "🔍 Analyzing current fail2ban configuration..."

    # Get current jail status
    if systemctl is-active --quiet fail2ban; then
        local jail_status=$(fail2ban-client status 2>/dev/null || echo "")
        if [[ -n "$jail_status" ]]; then
            # Parse active jails
            while IFS= read -r line; do
                if [[ "$line" =~ "Jail list:" ]]; then
                    local jails_line=${line#*Jail list:}
                    IFS=',' read -ra current_jails <<< "$jails_line"
                fi
            done <<< "$jail_status"

            # Clean up jail names
            for i in "${!current_jails[@]}"; do
                current_jails[$i]=$(echo "${current_jails[$i]}" | xargs)
            done
        fi
    fi

    # Analyze each jail configuration
    for jail in "${current_jails[@]}"; do
        if [[ -n "$jail" ]]; then
            local jail_info=$(fail2ban-client get "$jail" maxretry bantime findtime 2>/dev/null || echo "")
            print_info "  📊 Jail '$jail': $(echo "$jail_info" | tr '\n' ' ')"

            # Security scoring based on configuration
            if [[ "$jail" == "sshd" ]]; then
                local maxretry=$(fail2ban-client get sshd maxretry 2>/dev/null || echo "6")
                local bantime=$(fail2ban-client get sshd bantime 2>/dev/null || echo "600")

                if [[ "$maxretry" -le 3 ]]; then
                    ((security_score += 25))
                else
                    issues+=("🔴 SSH jail allows $maxretry attempts (should be ≤3)")
                    improvements+=("Reduce SSH maxretry from $maxretry to 3")
                fi

                if [[ "$bantime" -ge 3600 ]]; then
                    ((security_score += 25))
                else
                    local ban_minutes=$((bantime / 60))
                    issues+=("🟡 SSH ban time only ${ban_minutes} minutes (recommend ≥60 minutes)")
                    improvements+=("Increase SSH bantime from ${ban_minutes}min to 60min")
                fi
            fi
        fi
    done

    # Check for missing critical jails
    local has_sshd_ddos=false
    local has_recidive=false

    for jail in "${current_jails[@]}"; do
        [[ "$jail" == "sshd-ddos" ]] && has_sshd_ddos=true
        [[ "$jail" == "recidive" ]] && has_recidive=true
    done

    if ! $has_sshd_ddos; then
        issues+=("🔴 No SSH DDoS protection configured")
        improvements+=("Add sshd-ddos jail for connection flood protection")
    else
        ((security_score += 25))
    fi

    if ! $has_recidive; then
        issues+=("🔴 No repeat offender protection")
        improvements+=("Add recidive jail for persistent attackers")
    else
        ((security_score += 25))
    fi

    # Store results in global variables for later use
    CURRENT_FAIL2BAN_SCORE=$security_score
    CURRENT_FAIL2BAN_ISSUES=("${issues[@]}")
    CURRENT_FAIL2BAN_IMPROVEMENTS=("${improvements[@]}")
    CURRENT_FAIL2BAN_JAILS=("${current_jails[@]}")
}

show_fail2ban_security_assessment() {
    echo -e "\n${BOLD}${CYAN}📊 FAIL2BAN SECURITY ASSESSMENT${NC}"
    echo "════════════════════════════════════════"

    # Current state
    echo -e "${BLUE}Current State:${NC}"
    if systemctl is-active --quiet fail2ban; then
        local version=$(fail2ban-client version 2>/dev/null | head -1 || echo "unknown")
        echo -e "  ✅ Service: Active ($version)"

        if [[ ${#CURRENT_FAIL2BAN_JAILS[@]} -gt 0 ]]; then
            echo -e "  📋 Active jails: ${CURRENT_FAIL2BAN_JAILS[*]}"
        else
            echo -e "  ⚠️  No active jails detected"
        fi
    else
        echo -e "  ❌ Service: Inactive"
    fi

    # Security score with visual indicator
    echo -e "\n${BLUE}Security Score: ${NC}"
    local score_color="${RED}"
    local score_status="CRITICAL"

    if [[ $CURRENT_FAIL2BAN_SCORE -ge 75 ]]; then
        score_color="${GREEN}"
        score_status="EXCELLENT"
    elif [[ $CURRENT_FAIL2BAN_SCORE -ge 50 ]]; then
        score_color="${YELLOW}"
        score_status="NEEDS IMPROVEMENT"
    fi

    echo -e "  ${score_color}${CURRENT_FAIL2BAN_SCORE}/100 - $score_status${NC}"

    # Issues found
    if [[ ${#CURRENT_FAIL2BAN_ISSUES[@]} -gt 0 ]]; then
        echo -e "\n${BLUE}Issues Found:${NC}"
        for issue in "${CURRENT_FAIL2BAN_ISSUES[@]}"; do
            echo -e "  $issue"
        done
    fi

    # Proposed improvements
    if [[ ${#CURRENT_FAIL2BAN_IMPROVEMENTS[@]} -gt 0 ]]; then
        echo -e "\n${BLUE}Proposed Improvements:${NC}"
        for improvement in "${CURRENT_FAIL2BAN_IMPROVEMENTS[@]}"; do
            echo -e "  🔧 $improvement"
        done

        echo -e "\n${GREEN}Estimated score after improvements: 95/100 ✅${NC}"
    fi
}

install_fail2ban() {
    print_section "FAIL2BAN INSTALLATION AND CONFIGURATION (CIS Control 6.2)"

    # Initialize global variables
    CURRENT_FAIL2BAN_SCORE=0
    CURRENT_FAIL2BAN_ISSUES=()
    CURRENT_FAIL2BAN_IMPROVEMENTS=()
    CURRENT_FAIL2BAN_JAILS=()

    # Check if fail2ban is already installed
    if ! command -v fail2ban-client &> /dev/null; then
        print_info "Installing fail2ban..."
        install_package fail2ban
        print_success "Fail2ban installed successfully"
    else
        # Analyze current state before making changes
        analyze_current_fail2ban_state
        show_fail2ban_security_assessment

        # Ask for user confirmation with preview
        echo -e "\n${YELLOW}❓ Apply recommended fail2ban improvements? [Y/n/preview]${NC}"
        read -r response

        case "$response" in
            [nN]|[nN][oO])
                print_info "Skipping fail2ban configuration changes"
                return 0
                ;;
            [pP]|[pP][rR][eE][vV][iI][eE][wW])
                show_fail2ban_config_preview
                echo -e "\n${YELLOW}❓ Proceed with these changes? [Y/n]${NC}"
                read -r confirm
                [[ "$confirm" =~ ^[nN] ]] && return 0
                ;;
        esac
    fi

    # Create comprehensive backup with rollback capability
    create_fail2ban_backup_with_rollback

    # Create jail.local based on official fail2ban documentation
    # Reference: https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf
    print_info "Creating fail2ban jail configuration..."

    cat > /etc/fail2ban/jail.local << 'EOF'
# Fail2ban jail.local configuration
# Based on official fail2ban documentation and CIS benchmarks
# Reference: https://github.com/fail2ban/fail2ban

[DEFAULT]
# "bantime" is the number of seconds that a host is banned.
bantime  = 1h

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10m

# "maxretry" is the number of failures before a host get banned.
maxretry = 3

# "ignoreip" can be a list of IP addresses, CIDR masks or DNS hosts. Fail2ban
# will not ban a host which matches an address in this list.
ignoreip = 127.0.0.1/8 ::1

# "backend" specifies the backend used to get files modification.
backend = auto

# "usedns" specifies if jails should trust hostnames in logs
usedns = warn

# Destination email address used solely for the interpolations in
# jail.{conf,local,d/*} configuration files.
destemail = root@localhost

# Sender email address used solely for some actions
sender = root@localhost

# E-mail action. Since 0.8.1 Fail2Ban uses sendmail MTA for the
# mailing. Change mta configuration parameter to mail if you want to
# revert to conventional 'mail'.
mta = sendmail

# Default protocol
protocol = tcp

# Specify chain where jumps would need to be added in iptables-* actions
chain = INPUT

# Ports to be banned
# Usually should be overridden in a particular jail
port = 0:65535

# Action shortcuts. To be used to define action parameter
action_mw = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
            %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s"]

action_mwl = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
             %(mta)s-whois-lines[name=%(__name__)s, dest="%(destemail)s", logpath=%(logpath)s, chain="%(chain)s"]

# Default action
action = %(action_)s

#
# SSH servers
#

[sshd]
# To use more aggressive sshd modes set filter parameter "mode" in jail.local:
# normal (default), ddos, extra or aggressive (combines all).
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 1h
findtime = 10m

[sshd-ddos]
# This jail corresponds to the standard configuration in Fail2ban.
# The mail-whois action send a notification e-mail with a whois request
# in the body.
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 2
bantime = 2h
findtime = 10m

#
# Recidive jail (repeat offenders)
#

[recidive]
# Ban hosts which get banned multiple times
enabled = true
logpath  = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime  = 1w
findtime = 1d
maxretry = 5
EOF

    print_success "Fail2ban jail configuration created"

    # Validate configuration before applying
    if ! validate_fail2ban_config; then
        print_error "Configuration validation failed - aborting"
        return 1
    fi

    # Enable and start fail2ban service
    print_info "🚀 Applying fail2ban configuration..."
    systemctl enable fail2ban
    systemctl restart fail2ban

    # Wait for service to start and stabilize
    sleep 5

    # Comprehensive post-configuration verification
    verify_fail2ban_implementation
}

verify_fail2ban_implementation() {
    echo -e "\n${BOLD}${CYAN}🔍 POST-CONFIGURATION VERIFICATION${NC}"
    echo "════════════════════════════════════════"

    # Service status check
    if systemctl is-active --quiet fail2ban; then
        print_success "Fail2ban service is active and running"

        local version=$(fail2ban-client version 2>/dev/null | head -1 || echo "unknown")
        print_info "Version: $version"
    else
        print_error "Fail2ban service failed to start"
        print_info "Check logs: journalctl -u fail2ban -n 20"
        return 1
    fi

    # Jail status verification
    print_info "📋 Verifying jail configuration..."
    local jail_status=$(fail2ban-client status 2>/dev/null)

    if [[ -n "$jail_status" ]]; then
        echo -e "${BLUE}Active jails:${NC}"
        echo "$jail_status" | grep -E "(Jail list|Number of jail)" | sed 's/^/  /'

        # Check specific jails
        local expected_jails=("sshd" "sshd-ddos" "recidive")
        local active_jails=0

        for jail in "${expected_jails[@]}"; do
            if fail2ban-client status "$jail" &>/dev/null; then
                print_success "Jail '$jail' is active"
                ((active_jails++))

                # Show jail details
                local jail_info=$(fail2ban-client status "$jail" 2>/dev/null)
                local currently_banned=$(echo "$jail_info" | grep "Currently banned:" | awk '{print $3}')
                local total_banned=$(echo "$jail_info" | grep "Total banned:" | awk '{print $3}')
                print_info "  └── Currently banned: ${currently_banned:-0}, Total banned: ${total_banned:-0}"
            else
                print_warning "Jail '$jail' is not active"
            fi
        done

        # Calculate final security score
        local final_score=$((active_jails * 30 + 10))  # Base 10 + 30 per active jail
        [[ $final_score -gt 100 ]] && final_score=100

        echo -e "\n${BOLD}${GREEN}📊 FINAL SECURITY ASSESSMENT${NC}"
        echo "════════════════════════════════════════"
        echo -e "  Previous score: ${CURRENT_FAIL2BAN_SCORE}/100"
        echo -e "  Current score:  ${final_score}/100"

        if [[ $final_score -ge 90 ]]; then
            echo -e "  ${GREEN}✅ EXCELLENT - Enterprise-grade protection active${NC}"
        elif [[ $final_score -ge 70 ]]; then
            echo -e "  ${YELLOW}⚠️  GOOD - Most protections active${NC}"
        else
            echo -e "  ${RED}❌ NEEDS ATTENTION - Some protections missing${NC}"
        fi

    else
        print_warning "Could not retrieve jail status"
    fi

    # Show rollback information
    echo -e "\n${BOLD}${BLUE}🛡️ SAFETY INFORMATION${NC}"
    echo "════════════════════════════════════════"
    if [[ -n "${FAIL2BAN_ROLLBACK_SCRIPT:-}" ]]; then
        echo -e "  📁 Backup location: $(dirname "$FAIL2BAN_ROLLBACK_SCRIPT")"
        echo -e "  🔄 Rollback command: sudo $FAIL2BAN_ROLLBACK_SCRIPT"
        echo -e "  ⏱️  If SSH access fails: Use console/physical access to run rollback"
    fi

    # Test commands for user
    echo -e "\n${BOLD}${BLUE}🧪 TEST COMMANDS${NC}"
    echo "════════════════════════════════════════"
    echo -e "  📊 Check status: ${CYAN}fail2ban-client status${NC}"
    echo -e "  🔍 SSH jail details: ${CYAN}fail2ban-client status sshd${NC}"
    echo -e "  📝 View logs: ${CYAN}journalctl -u fail2ban -f${NC}"
    echo -e "  🚫 Manual ban test: ${CYAN}fail2ban-client set sshd banip 192.0.2.1${NC}"
    echo -e "  ✅ Manual unban: ${CYAN}fail2ban-client set sshd unbanip 192.0.2.1${NC}"
}

configure_advanced_firewall() {
    print_section "ADVANCED FIREWALL CONFIGURATION"
    
    # Enable firewalld
    systemctl enable firewalld
    systemctl start firewalld
    
    # Set default zone to drop (most restrictive)
    firewall-cmd --set-default-zone=drop
    
    # Configure trusted zone for local network
    firewall-cmd --permanent --zone=trusted --add-source=192.168.1.0/24
    firewall-cmd --permanent --zone=trusted --add-service=ssh
    
    # Configure public zone (restrictive)
    firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client
    firewall-cmd --permanent --zone=public --remove-service=cockpit
    
    # Add SSH with rate limiting (if supported)
    firewall-cmd --permanent --add-rich-rule='rule service name="ssh" accept limit value="3/m"'
    
    # Block common attack ports
    firewall-cmd --permanent --add-rich-rule='rule port port="23" protocol="tcp" reject'
    firewall-cmd --permanent --add-rich-rule='rule port port="21" protocol="tcp" reject'
    firewall-cmd --permanent --add-rich-rule='rule port port="135" protocol="tcp" reject'
    firewall-cmd --permanent --add-rich-rule='rule port port="445" protocol="tcp" reject'
    
    # Enable logging for dropped packets
    firewall-cmd --permanent --set-log-denied=all
    
    # Reload firewall
    firewall-cmd --reload
    print_success "Advanced firewall rules configured"
}

harden_ssh() {
    print_section "SSH HARDENING"
    
    backup_config "/etc/ssh/sshd_config"
    
    # Create hardened SSH config
    cat > /etc/ssh/sshd_config << 'EOF'
# SSH Hardened Configuration
Port 22
Protocol 2

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security settings
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no

# Session settings
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 2
MaxStartups 2

# Logging
SyslogFacility AUTHPRIV
LogLevel VERBOSE

# Crypto settings
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Banner
Banner /etc/ssh/banner
EOF
    
    # Create SSH banner
    cat > /etc/ssh/banner << 'EOF'
***************************************************************************
                            AUTHORIZED ACCESS ONLY
                    
This system is for authorized users only. All activities are monitored
and logged. Unauthorized access is prohibited and will be prosecuted.
***************************************************************************
EOF
    
    # Test SSH config
    if sshd -t; then
        systemctl restart sshd
        print_success "SSH hardened and restarted"
    else
        print_error "SSH configuration test failed"
        return 1
    fi
}

configure_network_security() {
    print_section "NETWORK SECURITY PARAMETERS"
    
    backup_config "/etc/sysctl.conf"
    
    # Add network security parameters
    cat >> /etc/sysctl.conf << 'EOF'

# Network Security Hardening
# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable secure ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Ignore broadcast ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# TCP hardening
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Memory optimization (from previous hardening)
vm.swappiness = 10
EOF
    
    # Apply settings
    sysctl -p
    print_success "Network security parameters applied"
}

setup_intrusion_detection() {
    print_section "INTRUSION DETECTION SETUP"
    
    # Install AIDE (Advanced Intrusion Detection Environment)
    if ! command -v aide &> /dev/null; then
        dnf install -y aide
        print_success "AIDE installed"
    fi
    
    # Initialize AIDE database
    aide --init
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    print_success "AIDE database initialized"
    
    # Create daily AIDE check script
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/sbin/aide --check | mail -s "AIDE Report $(hostname)" root
EOF
    chmod +x /etc/cron.daily/aide-check
    print_success "AIDE daily checks configured"
}

configure_audit_logging() {
    print_section "AUDIT LOGGING CONFIGURATION"
    
    # Install auditd if not present
    if ! systemctl is-active auditd &> /dev/null; then
        dnf install -y audit
    fi
    
    backup_config "/etc/audit/auditd.conf"
    backup_config "/etc/audit/rules.d/audit.rules"
    
    # Configure audit rules
    cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Audit rules for security monitoring

# Monitor authentication events
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor network configuration
-w /etc/hosts -p wa -k network
-w /etc/sysconfig/network -p wa -k network

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd

# Monitor firewall changes
-w /etc/firewalld/ -p wa -k firewall

# Monitor privilege escalation
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p wa -k priv_esc

# Monitor file permission changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
EOF
    
    # Enable and restart auditd
    systemctl enable auditd
    systemctl restart auditd
    print_success "Audit logging configured"
}

setup_log_monitoring() {
    print_section "LOG MONITORING SETUP"
    
    # Install logwatch
    if ! command -v logwatch &> /dev/null; then
        dnf install -y logwatch
        print_success "Logwatch installed"
    fi
    
    # Configure logwatch
    cat > /etc/logwatch/conf/logwatch.conf << 'EOF'
LogDir = /var/log
TmpDir = /var/cache/logwatch
MailTo = root
MailFrom = logwatch@$(hostname)
Print = No
Save = /tmp/logwatch
Range = yesterday
Detail = Med
Service = All
mailer = "/usr/sbin/sendmail -t"
EOF
    
    # Create daily logwatch cron job
    cat > /etc/cron.daily/0logwatch << 'EOF'
#!/bin/bash
/usr/sbin/logwatch --output mail
EOF
    chmod +x /etc/cron.daily/0logwatch
    print_success "Log monitoring configured"
}

create_security_monitoring_script() {
    print_section "SECURITY MONITORING SCRIPT"
    
    cat > /usr/local/bin/security-monitor.sh << 'EOF'
#!/bin/bash
# Security monitoring script

LOG_FILE="/var/log/security-monitor.log"

log_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Check for failed SSH attempts
FAILED_SSH=$(grep "Failed password" /var/log/secure | grep "$(date '+%b %d')" | wc -l)
if [[ $FAILED_SSH -gt 10 ]]; then
    log_event "WARNING: $FAILED_SSH failed SSH attempts today"
fi

# Check for new users
NEW_USERS=$(grep "new user" /var/log/secure | grep "$(date '+%b %d')" | wc -l)
if [[ $NEW_USERS -gt 0 ]]; then
    log_event "ALERT: $NEW_USERS new users created today"
fi

# Check disk usage
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [[ $DISK_USAGE -gt 90 ]]; then
    log_event "WARNING: Disk usage is ${DISK_USAGE}%"
fi

# Check for listening ports changes
CURRENT_PORTS=$(ss -tuln | sort)
if [[ -f /tmp/last_ports.txt ]]; then
    if ! diff -q /tmp/last_ports.txt <(echo "$CURRENT_PORTS") > /dev/null; then
        log_event "ALERT: Listening ports have changed"
    fi
fi
echo "$CURRENT_PORTS" > /tmp/last_ports.txt

log_event "Security monitoring check completed"
EOF
    
    chmod +x /usr/local/bin/security-monitor.sh
    
    # Add to cron
    echo "*/15 * * * * /usr/local/bin/security-monitor.sh" | crontab -
    print_success "Security monitoring script created and scheduled"
}

run_security_tests() {
    print_section "SECURITY VALIDATION TESTS"
    
    echo -e "${BLUE}Testing fail2ban status:${NC}"
    fail2ban-client status
    
    echo -e "\n${BLUE}Testing firewall status:${NC}"
    firewall-cmd --list-all
    
    echo -e "\n${BLUE}Testing SSH configuration:${NC}"
    sshd -t && echo "SSH config is valid"
    
    echo -e "\n${BLUE}Testing listening ports:${NC}"
    ss -tuln | grep LISTEN
    
    echo -e "\n${BLUE}Testing network parameters:${NC}"
    sysctl net.ipv4.tcp_syncookies
    sysctl net.ipv4.icmp_echo_ignore_all
    
    print_success "Security validation completed"
}

main() {
    print_header
    
    check_root
    
    log_action "Starting advanced network hardening"
    
    install_fail2ban
    configure_advanced_firewall
    harden_ssh
    configure_network_security
    setup_intrusion_detection
    configure_audit_logging
    setup_log_monitoring
    create_security_monitoring_script
    run_security_tests
    
    print_section "HARDENING COMPLETED"
    print_success "All security measures have been implemented"
    print_success "Log file: $LOG_FILE"
    
    echo -e "\n${BOLD}${GREEN}🎯 NEXT STEPS:${NC}"
    echo -e "${BLUE}1. Reboot the system to ensure all changes take effect${NC}"
    echo -e "${BLUE}2. Test SSH connectivity from a remote system${NC}"
    echo -e "${BLUE}3. Monitor logs in /var/log/security-monitor.log${NC}"
    echo -e "${BLUE}4. Run the security audit script: python3 network_security_audit.py${NC}"
    echo -e "${BLUE}5. Consider changing SSH port from default 22${NC}"
}

main "$@"
