# Security groups that reference each other, in the order traffic flows:
#   pentest worker --HTTP 80--> staging ALB --app port--> staging app
# Terraform removes AWS's default "allow all outbound" rule, so the only
# traffic allowed is what is written here.

resource "aws_security_group" "pentest_worker" {
  name        = "doublecheck-pentest-worker"
  description = "Pentest worker: no inbound; HTTP to the staging ALB, HTTPS to AWS"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "sg-pentest-worker" }
}

resource "aws_security_group" "staging_alb" {
  name        = "doublecheck-staging-alb"
  description = "Internal staging ALB: HTTP only from the pentest worker"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "sg-staging-alb" }
}

resource "aws_security_group" "staging_app" {
  name        = "doublecheck-staging-app"
  description = "Staging app: app port only from the staging ALB"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "sg-staging-app" }
}

resource "aws_security_group" "sast_scanner" {
  name        = "doublecheck-sast-scanner"
  description = "SAST scanner: no inbound; HTTPS out (GitHub via NAT, AWS APIs)"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "sg-sast-scanner" }
}

resource "aws_security_group" "endpoints" {
  name        = "doublecheck-vpc-endpoints"
  description = "Interface endpoints: HTTPS from inside the VPC"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "sg-vpc-endpoints" }
}

# ---------- hop 1: pentest worker ----------
resource "aws_vpc_security_group_egress_rule" "worker_to_alb" {
  security_group_id            = aws_security_group.pentest_worker.id
  referenced_security_group_id = aws_security_group.staging_alb.id
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
  description                  = "Attack staging, only through the ALB"
}

resource "aws_vpc_security_group_egress_rule" "worker_https" {
  security_group_id = aws_security_group.pentest_worker.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "ECR, CloudWatch Logs, S3 reports (via VPC endpoints)"
}

# ---------- hop 2: staging ALB (the key rule) ----------
resource "aws_vpc_security_group_ingress_rule" "alb_from_worker" {
  security_group_id            = aws_security_group.staging_alb.id
  referenced_security_group_id = aws_security_group.pentest_worker.id
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
  description                  = "KEY RULE: only the pentest worker can reach staging"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.staging_alb.id
  referenced_security_group_id = aws_security_group.staging_app.id
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  description                  = "Forward requests and health checks to the app"
}

# ---------- hop 3: staging app ----------
resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.staging_app.id
  referenced_security_group_id = aws_security_group.staging_alb.id
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  description                  = "App port only from the ALB"
}

resource "aws_vpc_security_group_egress_rule" "app_https" {
  security_group_id = aws_security_group.staging_app.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "ECR and CloudWatch Logs (via VPC endpoints)"
}

# ---------- SAST scanner (Rahul's service; no path to staging) ----------
resource "aws_vpc_security_group_egress_rule" "sast_https" {
  security_group_id = aws_security_group.sast_scanner.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "GitHub (via NAT) and AWS APIs"
}

# ---------- endpoints ----------
resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  security_group_id = aws_security_group.endpoints.id
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "HTTPS from tasks inside the VPC"
}

# ---------- test only: an "outsider" with wide-open egress ----------
# Its own rules allow everything out, so if it still cannot reach staging,
# the ALB's inbound rule is what stopped it.
resource "aws_security_group" "outsider" {
  count       = var.create_outsider_sg ? 1 : 0
  name        = "doublecheck-outsider-test"
  description = "TEST ONLY: open egress, not allowed by the staging ALB"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "sg-outsider-test" }
}

resource "aws_vpc_security_group_egress_rule" "outsider_all" {
  count             = var.create_outsider_sg ? 1 : 0
  security_group_id = aws_security_group.outsider[0].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Everything out"
}
