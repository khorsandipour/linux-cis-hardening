#!/bin/bash
# ================================================
# CIS Benchmark — Ubuntu Hardening Script
# Author: Ahmad Khorsandi Pour
# Tested on: Ubuntu 20.04 LTS / 22.04 LTS (AWS EC2)
# CIS Level: 1 & 2
# ================================================
# WARNING: Test on a non-production instance first
# Some controls will restart services (SSH, UFW)
# ================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_info() { echo -e "[INFO] $1"; }

echo "================================================"
echo "CIS Benchmark Hardening — Ubuntu"
echo "Author: Ahmad Khorsandi Pour"
echo "Started: $(date)"
echo "================================================"

# ------------------------------------------------
# SECTION 1 — SYSTEM UPDATE
# ------------------------------------------------
log_info "Section 1 — System update"

apt-get update -y
apt-get upgrade -y
apt-get autoremove -y
log_ok "System updated"

# ------------------------------------------------
# SECTION 2 — REMOVE UNNECESSARY PACKAGES
# ------------------------------------------------
log_info "Section 2 — Removing unnecessary packages"

PACKAGES_TO_REMOVE=(
  telnet
  rsh-client
  rsh-redone-client
  talk
  talkd
  xinetd
  inetd
)

for pkg in "${PACKAGES_TO_REMOVE[@]}"; do
  if dpkg -l | grep -q "^ii  $pkg"; then
    apt-get remove -y "$pkg"
    log_ok "Removed: $pkg"
  else
    log_info "Not installed: $pkg — skipping"
  fi
done

# ------------------------------------------------
# SECTION 3 — SSH HARDENING
# ------------------------------------------------
log_info "Section 3 — SSH hardening"

SSH_CONFIG="/etc/ssh/sshd_config"

# Backup original
cp "$SSH_CONFIG" "${SSH_CONFIG}.backup.$(date +%Y%m%d)"

# Apply CIS controls
declare -A SSH_SETTINGS=(
  ["PermitRootLogin"]="no"
  ["PasswordAuthentication"]="no"
  ["PubkeyAuthentication"]="yes"
  ["MaxAuthTries"]="3"
  ["LoginGraceTime"]="60"
  ["X11Forwarding"]="no"
  ["AllowTcpForwarding"]="no"
  ["ClientAliveInterval"]="300"
  ["ClientAliveCountMax"]="2"
  ["PermitEmptyPasswords"]="no"
  ["IgnoreRhosts"]="yes"
  ["HostbasedAuthentication"]="no"
  ["Protocol"]="2"
)

for setting in "${!SSH_SETTINGS[@]}"; do
  value="${SSH_SETTINGS[$setting]}"
  if grep -q "^${setting}" "$SSH_CONFIG"; then
    sed -i "s/^${setting}.*/${setting} ${value}/" "$SSH_CONFIG"
  else
    echo "${setting} ${value}" >> "$SSH_CONFIG"
  fi
  log_ok "SSH: ${setting} = ${value}"
done

systemctl restart sshd
log_ok "SSH service restarted"

# ------------------------------------------------
# SECTION 4 — UFW FIREWALL
# ------------------------------------------------
log_info "Section 4 — UFW firewall"

apt-get install -y ufw

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH — change port if using non-default
ufw allow 22/tcp comment 'SSH'

# Allow HTTPS from ALB only
# Replace with your ALB security group CIDR
# ufw allow from [ALB-CIDR] to any port 443

ufw --force enable
log_ok "UFW enabled — default deny incoming"

ufw status verbose

# ------------------------------------------------
# SECTION 5 — FAIL2BAN
# ------------------------------------------------
log_info "Section 5 — Fail2ban"

apt-get install -y fail2ban

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
backend  = %(syslog_backend)s
maxretry = 3
bantime  = 3600
EOF

systemctl enable fail2ban
systemctl restart fail2ban
log_ok "Fail2ban configured — max 3 SSH retries, 1hr ban"

# ------------------------------------------------
# SECTION 6 — FILE PERMISSIONS
# ------------------------------------------------
log_info "Section 6 — File permissions"

chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/ssh/sshd_config
log_ok "Critical file permissions set"

# ------------------------------------------------
# SECTION 7 — DISABLE CORE DUMPS
# ------------------------------------------------
log_info "Section 7 — Disable core dumps"

echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -p
log_ok "Core dumps disabled"

# ------------------------------------------------
# SECTION 8 — KERNEL PARAMETERS
# ------------------------------------------------
log_info "Section 8 — Kernel hardening"

cat >> /etc/sysctl.conf << 'EOF'
# CIS Benchmark — Network hardening
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
EOF

sysctl -p
log_ok "Kernel parameters applied"

# ------------------------------------------------
# SECTION 9 — AUTOMATIC SECURITY UPDATES
# ------------------------------------------------
log_info "Section 9 — Automatic security updates"

apt-get install -y unattended-upgrades

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
  "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

systemctl enable unattended-upgrades
log_ok "Automatic security updates enabled"

# ------------------------------------------------
# SECTION 10 — AUDIT LOGGING (auditd)
# ------------------------------------------------
log_info "Section 10 — Audit logging"

apt-get install -y auditd audispd-plugins

systemctl enable auditd
systemctl start auditd

# Key audit rules
auditctl -w /etc/passwd -p wa -k identity
auditctl -w /etc/shadow -p wa -k identity
auditctl -w /etc/sudoers -p wa -k sudoers
auditctl -w /var/log/auth.log -p wa -k auth_log

log_ok "auditd configured and running"

# ------------------------------------------------
# SUMMARY
# ------------------------------------------------
echo ""
echo "================================================"
echo "HARDENING COMPLETE"
echo "================================================"
echo "Controls applied:"
log_ok "System updated"
log_ok "Unnecessary packages removed"
log_ok "SSH hardened — key-only, root disabled"
log_ok "UFW firewall — default deny"
log_ok "Fail2ban — 3 retry limit"
log_ok "File permissions set"
log_ok "Core dumps disabled"
log_ok "Kernel parameters hardened"
log_ok "Automatic security updates enabled"
log_ok "auditd logging configured"
echo ""
log_warn "Next steps:"
log_warn "1. Verify SSH access still works before closing session"
log_warn "2. Update UFW rules with your ALB CIDR"
log_warn "3. Install CloudWatch agent — see install-cloudwatch-agent.sh"
log_warn "4. Run aws-cis-check.sh for account-level audit"
echo "================================================"
echo "Completed: $(date)"
echo "================================================"
