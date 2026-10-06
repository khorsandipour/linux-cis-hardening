#!/bin/bash
# ================================================
# AWS CIS Foundations Benchmark — Audit Script
# Author: Ahmad Khorsandi Pour
# Requires: AWS CLI configured with read permissions
# ================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }

echo "================================================"
echo "AWS CIS Foundations Benchmark Audit"
echo "Author: Ahmad Khorsandi Pour"
echo "Started: $(date)"
echo "================================================"

# ------------------------------------------------
# SECTION 1 — IAM
# ------------------------------------------------
echo ""
echo "--- Section 1: IAM ---"

# 1.1 Root account MFA
MFA_DEVICES=$(aws iam list-virtual-mfa-devices \
  --assignment-status Assigned \
  --query 'VirtualMFADevices[?SerialNumber!=`null`]' \
  --output text 2>/dev/null | grep -c "root" || true)

if [ "$MFA_DEVICES" -gt 0 ]; then
  pass "1.1 Root account MFA enabled"
else
  fail "1.1 Root account MFA NOT enabled"
fi

# 1.2 Root access keys
ROOT_KEYS=$(aws iam get-account-summary \
  --query 'SummaryMap.AccountAccessKeysPresent' \
  --output text 2>/dev/null)

if [ "$ROOT_KEYS" == "0" ]; then
  pass "1.2 No root access keys exist"
else
  fail "1.2 Root access keys exist — remove immediately"
fi

# 1.3 IAM password policy
PASSWORD_POLICY=$(aws iam get-account-password-policy \
  --query 'PasswordPolicy.MinimumPasswordLength' \
  --output text 2>/dev/null || echo "0")

if [ "$PASSWORD_POLICY" -ge 14 ]; then
  pass "1.3 Password minimum length >= 14"
else
  fail "1.3 Password policy too weak (min length: $PASSWORD_POLICY)"
fi

# 1.4 Access keys rotated within 90 days
echo ""
warn "1.4 Manual check: Verify access keys rotated within 90 days"
echo "     Run: aws iam generate-credential-report"

# ------------------------------------------------
# SECTION 2 — LOGGING
# ------------------------------------------------
echo ""
echo "--- Section 2: Logging ---"

# 2.1 CloudTrail enabled
TRAILS=$(aws cloudtrail describe-trails \
  --query 'trailList[*].Name' \
  --output text 2>/dev/null)

if [ -n "$TRAILS" ]; then
  pass "2.1 CloudTrail trails exist: $TRAILS"
else
  fail "2.1 No CloudTrail trails found"
fi

# 2.2 CloudTrail log validation
VALIDATION=$(aws cloudtrail describe-trails \
  --query 'trailList[*].LogFileValidationEnabled' \
  --output text 2>/dev/null)

if echo "$VALIDATION" | grep -q "True"; then
  pass "2.2 CloudTrail log file validation enabled"
else
  fail "2.2 CloudTrail log file validation NOT enabled"
fi

# 2.3 CloudTrail S3 bucket not public
TRAIL_BUCKET=$(aws cloudtrail describe-trails \
  --query 'trailList[0].S3BucketName' \
  --output text 2>/dev/null)

if [ -n "$TRAIL_BUCKET" ] && [ "$TRAIL_BUCKET" != "None" ]; then
  PUBLIC_ACCESS=$(aws s3api get-bucket-acl \
    --bucket "$TRAIL_BUCKET" \
    --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]' \
    --output text 2>/dev/null)

  if [ -z "$PUBLIC_ACCESS" ]; then
    pass "2.3 CloudTrail S3 bucket is not public: $TRAIL_BUCKET"
  else
    fail "2.3 CloudTrail S3 bucket is PUBLIC: $TRAIL_BUCKET"
  fi
fi

# 2.4 VPC flow logs
VPC_IDS=$(aws ec2 describe-vpcs \
  --query 'Vpcs[*].VpcId' \
  --output text 2>/dev/null)

for VPC_ID in $VPC_IDS; do
  FLOW_LOGS=$(aws ec2 describe-flow-logs \
    --filter "Name=resource-id,Values=$VPC_ID" \
    --query 'FlowLogs[*].FlowLogId' \
    --output text 2>/dev/null)

  if [ -n "$FLOW_LOGS" ]; then
    pass "2.4 VPC flow logs enabled: $VPC_ID"
  else
    fail "2.4 VPC flow logs NOT enabled: $VPC_ID"
  fi
done

# ------------------------------------------------
# SECTION 3 — MONITORING
# ------------------------------------------------
echo ""
echo "--- Section 3: Monitoring ---"

# 3.1 GuardDuty
GUARDDUTY=$(aws guardduty list-detectors \
  --query 'DetectorIds' \
  --output text 2>/dev/null)

if [ -n "$GUARDDUTY" ]; then
  pass "3.1 GuardDuty enabled"
else
  fail "3.1 GuardDuty NOT enabled"
fi

# 3.2 Security Hub
SECURITYHUB=$(aws securityhub describe-hub \
  --query 'HubArn' \
  --output text 2>/dev/null || echo "")

if [ -n "$SECURITYHUB" ]; then
  pass "3.2 Security Hub enabled"
else
  fail "3.2 Security Hub NOT enabled"
fi

# ------------------------------------------------
# SECTION 4 — NETWORKING
# ------------------------------------------------
echo ""
echo "--- Section 4: Networking ---"

# 4.1 Security groups — no 0.0.0.0/0 on SSH
OPEN_SSH=$(aws ec2 describe-security-groups \
  --filters \
    "Name=ip-permission.from-port,Values=22" \
    "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].GroupId' \
  --output text 2>/dev/null)

if [ -z "$OPEN_SSH" ]; then
  pass "4.1 No security groups with SSH open to 0.0.0.0/0"
else
  fail "4.1 SSH open to internet on: $OPEN_SSH"
fi

# 4.2 Security groups — no 0.0.0.0/0 on RDP
OPEN_RDP=$(aws ec2 describe-security-groups \
  --filters \
    "Name=ip-permission.from-port,Values=3389" \
    "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].GroupId' \
  --output text 2>/dev/null)

if [ -z "$OPEN_RDP" ]; then
  pass "4.2 No security groups with RDP open to 0.0.0.0/0"
else
  fail "4.2 RDP open to internet on: $OPEN_RDP"
fi

# 4.3 S3 public access block — account level
S3_PUBLIC=$(aws s3control get-public-access-block \
  --account-id "$(aws sts get-caller-identity \
    --query Account --output text)" \
  --query 'PublicAccessBlockConfiguration' \
  --output json 2>/dev/null)

if echo "$S3_PUBLIC" | grep -q '"true"'; then
  pass "4.3 S3 account-level public access block enabled"
else
  fail "4.3 S3 account-level public access block NOT fully enabled"
fi

# ------------------------------------------------
# SUMMARY
# ------------------------------------------------
echo ""
echo "================================================"
echo "AUDIT COMPLETE"
echo "================================================"
echo -e "${GREEN}PASS: $PASS${NC}"
echo -e "${RED}FAIL: $FAIL${NC}"
echo -e "${YELLOW}WARN: $WARN${NC}"
echo ""
TOTAL=$((PASS + FAIL))
if [ "$TOTAL" -gt 0 ]; then
  SCORE=$(( (PASS * 100) / TOTAL ))
  echo "Score: $SCORE% ($PASS/$TOTAL controls passed)"
fi
echo "================================================"
echo "Completed: $(date)"
echo "================================================"
