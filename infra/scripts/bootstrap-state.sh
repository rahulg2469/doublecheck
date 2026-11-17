#!/usr/bin/env bash
# Creates the S3 bucket that stores Terraform state (run once per account).
# Versioned (every state change can be rolled back), encrypted, never public.
set -euo pipefail
export AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""

ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BUCKET="doublecheck-tfstate-$ACCOUNT"

if aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  echo "Bucket already exists: $BUCKET"
else
  aws s3api create-bucket --bucket "$BUCKET" > /dev/null
  echo "Created bucket: $BUCKET"
fi

aws s3api put-bucket-versioning --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

echo "State bucket ready: versioning on, encryption on, public access blocked"
echo "Next:  cd infra/terraform && terraform init -backend-config=\"bucket=$BUCKET\""
