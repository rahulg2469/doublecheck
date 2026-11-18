output "trigger_url" { value = "${aws_apigatewayv2_api.trigger.api_endpoint}/pentest" }
output "secret_name" { value = aws_secretsmanager_secret.signing.name }
output "queue_url" { value = aws_sqs_queue.jobs.url }
