#!/usr/bin/env bash
# Creates the two S3 buckets Terraform needs to exist first (run once per account):
#   doublecheck-tfstate-<account>  Terraform state (versioned)
#   doublecheck-reports-<account>  full pentest/SAST reports
# Both: encrypted, public access blocked. The reports bucket is made here
# rather than in Terraform because Learner Lab denies a read
# (s3:GetBucketObjectLockConfiguration) that Terraform's S3 resource needs.
set -euo pipefail
export AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""

ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

for BUCKET in "doublecheck-tfstate-$ACCOUNT" "doublecheck-reports-$ACCOUNT"; do
  if aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
    echo "Bucket already exists: $BUCKET"
  else
    aws s3api create-bucket --bucket "$BUCKET" > /dev/null
    echo "Created bucket: $BUCKET"
  fi
  aws s3api put-bucket-encryption --bucket "$BUCKET" \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
  aws s3api put-public-access-block --bucket "$BUCKET" \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
done

# State bucket only: keep every version of the state file
aws s3api put-bucket-versioning --bucket "doublecheck-tfstate-$ACCOUNT" \
  --versioning-configuration Status=Enabled

echo "Buckets ready: encryption on, public access blocked, state versioning on"
echo "Next:  cd infra/terraform && terraform init -backend-config=\"bucket=doublecheck-tfstate-$ACCOUNT\""
