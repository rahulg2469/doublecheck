output "vpc_id" {
  value = module.network.vpc_id
}

output "private_subnet_ids" {
  value = module.network.private_subnet_ids
}

output "cluster_name" {
  value = module.staging.cluster_name
}

output "staging_alb_url" {
  description = "Internal only: resolves and connects only from inside the VPC"
  value       = "http://${module.staging.alb_dns_name}"
}

output "pentest_task_family" {
  value = module.pentest.task_family
}

output "reports_bucket" {
  value = module.pentest.reports_bucket
}

output "security_groups" {
  value = {
    pentest_worker = module.network.sg_pentest_worker_id
    staging_alb    = module.network.sg_staging_alb_id
    staging_app    = module.network.sg_staging_app_id
    sast_scanner   = module.network.sg_sast_scanner_id
    outsider_test  = module.network.sg_outsider_id
  }
}

# Plain values for scripts (terraform output -raw ...)
output "private_subnets_csv" {
  value = join(",", module.network.private_subnet_ids)
}

output "sg_pentest_worker" {
  value = module.network.sg_pentest_worker_id
}

output "sg_outsider_test" {
  value = module.network.sg_outsider_id
}

output "staging_commit" {
  description = "Image tag of the deployed staging app (the commit SHA)"
  value       = try(regex(":([^:/]+)$", var.staging_image)[0], "unknown")
}

output "pentest_trigger_url" {
  description = "Public HTTPS endpoint the deploy job calls (signed requests only)"
  value       = module.trigger.trigger_url
}

output "pentest_trigger_secret" {
  description = "Secrets Manager name of the shared signing secret"
  value       = module.trigger.secret_name
}
