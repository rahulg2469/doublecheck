# Staging app on Fargate behind an INTERNAL ALB, all in private subnets.
# The ALB's DNS name only resolves and connects from inside the VPC.

data "aws_region" "current" {}

resource "aws_ecs_cluster" "this" {
  name = var.name
}

resource "aws_cloudwatch_log_group" "staging" {
  name              = "/${var.name}/staging-app"
  retention_in_days = 7
}

resource "aws_lb" "staging" {
  name               = "${var.name}-staging-alb"
  internal           = true
  load_balancer_type = "application"
  subnets            = var.private_subnet_ids
  security_groups    = [var.alb_sg_id]
}

resource "aws_lb_target_group" "staging" {
  name        = "${var.name}-staging-tg"
  vpc_id      = var.vpc_id
  port        = var.app_port
  protocol    = "HTTP"
  target_type = "ip" # Fargate tasks register by IP

  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 10
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.staging.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.staging.arn
  }
}

resource "aws_ecs_task_definition" "staging" {
  family                   = "staging-app"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = var.role_arn
  task_role_arn            = var.role_arn

  container_definitions = jsonencode([{
    name         = "staging-app"
    image        = var.image
    essential    = true
    portMappings = [{ containerPort = var.app_port, protocol = "tcp" }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.staging.name
        awslogs-region        = data.aws_region.current.id
        awslogs-stream-prefix = "staging"
      }
    }
  }])
}

resource "aws_ecs_service" "staging" {
  name            = "staging-app"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.staging.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.app_sg_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.staging.arn
    container_name   = "staging-app"
    container_port   = var.app_port
  }

  # New task healthy before the old one stops
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  depends_on = [aws_lb_listener.http]
}
