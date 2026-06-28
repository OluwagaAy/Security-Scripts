#!/bin/bash
###############################################################################
# Linux System Hardening Script
# Based on CIS Benchmarks - Level 1
# 
# WARNING: Review before running on production systems!
# Test in a VM first.
#
# Usage: sudo bash linux_hardening.sh
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="/var/log/security_hardening_$(date +%Y%m%d).log"

log() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[-]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "Please run as root (use sudo)"
    exit 1
fi

log "Starting system hardening..."
echo "=========================================="

###############################################################################
# 1. UPDATE SYSTEM
###############################################################################
log "Section 1: System Updates"

if command -v apt &> /dev/null; then
    apt update && apt upgrade -y
    apt autoremove -y
    apt autoclean
elif command -v yum &> /dev/null; then
    yum update -y
elif command -v dnf &> /dev/null; then
    dnf update -y
fi

log "System updated successfully"

###############################################################################
# 2. PASSWORD POLICY
###############################################################################
log "Section 2: Password Policy Configuration"

# Install libpam-pwquality if not present
if command -v apt &> /dev/null; then
    apt install -y libpam-pwquality cracklib-runtime
fi

# Configure password complexity
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
minclass = 4
maxrepeat = 2
gecoscheck = 1
enforce_for_root
EOF

# Configure password aging
cat > /etc/login.defs << 'EOF'
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_MIN_LEN    14
PASS_WARN_AGE   7
EOF

log "Password policy configured (min 14 chars, 90-day expiry)"

###############################################################################
# 3. SSH HARDENING
###############################################################################
log "Section 3: SSH Hardening"

SSHD_CONFIG="/etc/ssh/sshd_config"

# Backup original
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d)"

cat > "$SSHD_CONFIG" << 'EOF'
# MAPELEAD Security Hardened SSH Configuration
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
MaxAuthTries 3
MaxSessions 2

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Cryptography
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Access Control (customize for your environment)
# AllowUsers user1@10.0.0.* user2@192.168.1.*
EOF

systemctl restart sshd
log "SSH hardened - root login disabled, key auth only, strong ciphers"
warn "Ensure you have SSH key access before disconnecting!"

###############################################################################
# 4. FIREWALL CONFIGURATION
###############################################################################
log "Section 4: Firewall Configuration"

if command -v ufw &> /dev/null; then
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw --force enable
    log "UFW firewall enabled"
elif command -v firewall-cmd &> /dev/null; then
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --set-default-zone=drop
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --reload
    log "Firewalld configured"
fi

###############################################################################
# 5. FILE PERMISSIONS
###############################################################################
log "Section 5: File Permissions"

# Secure /tmp
chmod 1777 /tmp
chmod 1777 /var/tmp

# Remove world-writable files ( informational only)
warn "Checking for world-writable files..."
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null | tee -a "$LOG_FILE" || true

# Secure cron
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.weekly
chmod 700 /etc/cron.monthly

log "File permissions hardened"

###############################################################################
# 6. DISABLE UNUSED SERVICES
###############################################################################
log "Section 6: Disabling Unused Services"

UNUSED_SERVICES=(
    "telnet"
    "ftp"
    "nfs-server"
    "rpcbind"
    "smbd"
    "nmbd"
    "apache2"
    "nginx"
)

for service in "${UNUSED_SERVICES[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        systemctl stop "$service"
        systemctl disable "$service"
        log "Stopped and disabled: $service"
    fi
done

###############################################################################
# 7. KERNEL HARDENING (SYSCTL)
###############################################################################
log "Section 7: Kernel Hardening"

cat >> /etc/sysctl.conf << 'EOF'

# MAPELEAD Security Kernel Parameters
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# Disable IPv6 if not needed (comment out if IPv6 is required)
# net.ipv6.conf.all.disable_ipv6 = 1

# Protect against SYN flood attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable IPv4 forwarding
net.ipv4.ip_forward = 0

# Security
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
EOF

sysctl -p
log "Kernel parameters hardened"

###############################################################################
# 8. AUDIT CONFIGURATION
###############################################################################
log "Section 8: Audit Configuration"

if command -v apt &> /dev/null; then
    apt install -y auditd audispd-plugins
fi

systemctl enable auditd
systemctl start auditd

# Configure audit rules
cat > /etc/audit/rules.d/99-security.rules << 'EOF'
# Monitor password file
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity

# Monitor shadow file
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Monitor SSH config
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Monitor sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation

# Monitor file deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k file_deletion
EOF

augenrules --load
log "Auditd configured with security monitoring rules"

###############################################################################
# 9. AUTOMATIC SECURITY UPDATES
###############################################################################
log "Section 9: Automatic Security Updates"

if command -v apt &> /dev/null; then
    apt install -y unattended-upgrades
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    log "Automatic security updates enabled"
fi

###############################################################################
# SUMMARY
###############################################################################
echo ""
echo "=========================================="
log "HARDENING COMPLETE!"
echo "=========================================="
echo ""
echo "Summary of changes:"
echo "  [✓] System packages updated"
echo "  [✓] Password policy enforced (14+ chars, 90-day expiry)"
echo "  [✓] SSH hardened (no root, key-only, strong ciphers)"
echo "  [✓] Firewall enabled and configured"
echo "  [✓] File permissions secured"
echo "  [✓] Unused services disabled"
echo "  [✓] Kernel parameters hardened"
echo "  [✓] Audit logging configured"
echo "  [✓] Auto-updates enabled"
echo ""
warn "IMPORTANT NEXT STEPS:"
echo "  1. Review SSH key-based authentication is working"
echo "  2. Configure AllowUsers in /etc/ssh/sshd_config"
echo "  3. Review firewall rules for your environment"
echo "  4. Test all services still work as expected"
echo "  5. Monitor /var/log/audit/audit.log for issues"
echo ""
log "Full log available at: $LOG_FILE"
