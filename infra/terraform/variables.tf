variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  description = "Prefix for resource names"
  type        = string
  default     = "doublecheck"
}

variable "staging_image" {
  description = "Full ECR URI + tag of the staging app image"
  type        = string
}

variable "pentest_image" {
  description = "Full ECR URI + tag of the pentest worker image"
  type        = string
}

variable "app_port" {
  description = "Port the staging app listens on"
  type        = number
  default     = 4000
}

variable "staging_desired_count" {
  description = "Number of staging tasks (set to 0 to pause without destroying)"
  type        = number
  default     = 1
}

variable "enable_nat" {
  description = "NAT Gateway bills hourly, so it stays off unless a task needs the internet"
  type        = bool
  default     = false
}

variable "enable_interface_endpoints" {
  description = "ECR + CloudWatch Logs endpoints so private tasks can pull images and log without a NAT"
  type        = bool
  default     = true
}

variable "create_outsider_sg" {
  description = "Test-only security group with open egress, used to prove the ALB rule blocks it"
  type        = bool
  default     = true
}

variable "default_endpoints" {
  description = "Paths to attack when a deploy does not list its own"
  type        = list(string)
  default     = ["/api/users", "/api/user?id=1", "/api/login", "/api/data", "/api/process"]
}

variable "alert_email" {
  description = "Where pentest alerts are emailed (empty = no subscription)"
  type        = string
  default     = ""
}
