terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.70"
    }
  }

  # Remote state in S3, created once by infra/scripts/bootstrap-state.sh.
  # The bucket name includes the account ID, so it is passed at init time:
  #   terraform init -backend-config="bucket=doublecheck-tfstate-<accountId>"
  # use_lockfile = S3-native state locking (no DynamoDB lock table needed).
  backend "s3" {
    key          = "doublecheck/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "doublecheck"
      ManagedBy = "terraform"
    }
  }
}
