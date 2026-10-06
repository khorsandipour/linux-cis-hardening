# Linux CIS Hardening — AWS EC2

CIS Benchmark Level 1 & 2 hardening scripts for
Ubuntu and CentOS running on AWS EC2.

Applied to all production servers for a fintech
SaaS platform in Oman — part of a broader AWS
security implementation that included WAF, 
GuardDuty, CloudTrail and Security Hub.

---

## What This Covers

### Linux (CIS Level 1 & 2)
- SSH hardening — key-only, root disabled,
  MaxAuthTries 3
- UFW firewall — default deny, least-open policy
- Fail2ban — brute-force protection
- Unnecessary services disabled
- Automated security patching
- File permission audit
- Cron job audit
- CloudWatch log agent setup
- NTP synchronization

### AWS Account (CIS Foundations)
- MFA enforcement script check
- S3 public access audit
- Security Group audit — flags 0.0.0.0/0
- IAM unused credential check
- CloudTrail status check

---

## Scripts

| Script | OS | CIS Level |
|--------|-----|-----------|
| `harden-ubuntu.sh` | Ubuntu 20.04 / 22.04 | Level 1 & 2 |
| `harden-centos.sh` | CentOS 7 / 8 | Level 1 & 2 |
| `aws-cis-check.sh` | AWS Account audit | Foundations |
| `install-cloudwatch-agent.sh` | Ubuntu / CentOS | — |

---

## Usage

```bash
# Ubuntu
chmod +x harden-ubuntu.sh
sudo ./harden-ubuntu.sh

# CentOS
chmod +x harden-centos.sh
sudo ./harden-centos.sh

# AWS account audit (requires AWS CLI)
chmod +x aws-cis-check.sh
./aws-cis-check.sh
```

> ⚠️ Run on a test instance first.
> Some controls may affect running services.
> Review each section before applying to production.

---

## What Gets Applied

### SSH Hardening
```bash
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
LoginGraceTime 60
X11Forwarding no
AllowTcpForwarding no
```

### UFW Rules (EC2 pattern)
```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow from [ALB-SG-CIDR] to any port 443
ufw allow from [BASTION-IP] to any port [SSH-PORT]
ufw enable
```

### Fail2ban
```bash
[sshd]
enabled  = true
maxretry = 5
bantime  = 3600
findtime = 600
```

---

## Security Controls Checklist

See [docs/cis-checklist.md](docs/cis-checklist.md)
for the full 47-control implementation checklist
with pass/fail status for each control.

---

## Real-World Context

These scripts were applied across all EC2 instances
in a production AWS environment for a fintech SaaS
platform handling 30,000+ transactions per hour
during peak festival events in Oman.

The full security implementation also included:
- AWS WAF with OWASP Top 10 ruleset
- GuardDuty threat detection
- Security Hub centralized findings
- CloudTrail across all regions
- VPC flow logs

See [aws-production-stack](https://github.com/khorsandipour/aws-production-stack)
for the complete infrastructure.

---

## Author

**Ahmad Khorsandi Pour**  
Cloud Infrastructure Engineer · CEH v12 · SANS SEC504  
📍 Muscat, Oman  
🔗 [linkedin.com/in/khorsandipour](https://linkedin.com/in/khorsandipour)
