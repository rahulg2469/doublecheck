# Learner Lab does not allow creating IAM roles; every task uses LabRole.
data "aws_caller_identity" "current" {}

locals {
  lab_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/LabRole"
}

module "network" {
  source = "./modules/network"

  name                       = var.name
  region                     = var.region
  app_port                   = var.app_port
  enable_nat                 = var.enable_nat
  enable_interface_endpoints = var.enable_interface_endpoints
  create_outsider_sg         = var.create_outsider_sg
}

module "staging" {
  source = "./modules/staging"

  name               = var.name
  vpc_id             = module.network.vpc_id
  private_subnet_ids = module.network.private_subnet_ids
  alb_sg_id          = module.network.sg_staging_alb_id
  app_sg_id          = module.network.sg_staging_app_id
  image              = var.staging_image
  app_port           = var.app_port
  desired_count      = var.staging_desired_count
  role_arn           = local.lab_role_arn
}

module "pentest" {
  source = "./modules/pentest"

  name     = var.name
  image    = var.pentest_image
  role_arn = local.lab_role_arn
}
