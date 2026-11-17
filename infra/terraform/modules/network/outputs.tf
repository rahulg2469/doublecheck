output "vpc_id" { value = aws_vpc.this.id }
output "private_subnet_ids" { value = aws_subnet.private[*].id }
output "public_subnet_ids" { value = aws_subnet.public[*].id }
output "sg_pentest_worker_id" { value = aws_security_group.pentest_worker.id }
output "sg_staging_alb_id" { value = aws_security_group.staging_alb.id }
output "sg_staging_app_id" { value = aws_security_group.staging_app.id }
output "sg_sast_scanner_id" { value = aws_security_group.sast_scanner.id }
output "sg_outsider_id" { value = var.create_outsider_sg ? aws_security_group.outsider[0].id : null }
