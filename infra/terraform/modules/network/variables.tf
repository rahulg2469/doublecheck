variable "name" { type = string }
variable "app_port" { type = number }
variable "enable_nat" { type = bool }
variable "enable_interface_endpoints" { type = bool }
variable "create_outsider_sg" { type = bool }

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "region" { type = string }
