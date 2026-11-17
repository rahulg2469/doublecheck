output "cluster_name" { value = aws_ecs_cluster.this.name }
output "cluster_arn" { value = aws_ecs_cluster.this.arn }
output "alb_dns_name" { value = aws_lb.staging.dns_name }
output "service_name" { value = aws_ecs_service.staging.name }
