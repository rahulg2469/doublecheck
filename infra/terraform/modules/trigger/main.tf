# Automatic pentest trigger:
#   deploy job --signed POST /pentest--> API Gateway --> intake Lambda
#     --> SQS pentest queue --> RunTask Lambda --> pentest worker task on Fargate

# ---------- shared signing secret ----------
resource "random_password" "signing" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "signing" {
  name                    = "${var.name}/pentest-trigger-secret"
  description             = "HMAC secret the deploy job uses to sign POST /pentest"
  recovery_window_in_days = 0 # lab project: allow destroy and re-create with the same name
}

resource "aws_secretsmanager_secret_version" "signing" {
  secret_id     = aws_secretsmanager_secret.signing.id
  secret_string = random_password.signing.result
}

# ---------- queue: retries, then a dead-letter queue ----------
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name}-pentest-jobs-dlq"
  message_retention_seconds = 1209600 # 14 days
}

resource "aws_sqs_queue" "jobs" {
  name                       = "${var.name}-pentest-jobs"
  visibility_timeout_seconds = 120 # longer than the RunTask Lambda timeout
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 3
  })
}

# ---------- Lambda code ----------
data "archive_file" "intake" {
  type        = "zip"
  source_file = "${var.lambdas_dir}/pentest-intake/index.mjs"
  output_path = "${path.module}/.build/pentest-intake.zip"
}

data "archive_file" "runtask" {
  type        = "zip"
  source_file = "${var.lambdas_dir}/pentest-runtask/index.mjs"
  output_path = "${path.module}/.build/pentest-runtask.zip"
}

resource "aws_cloudwatch_log_group" "intake" {
  name              = "/aws/lambda/${var.name}-pentest-intake"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "runtask" {
  name              = "/aws/lambda/${var.name}-pentest-runtask"
  retention_in_days = 7
}

# ---------- intake Lambda ----------
resource "aws_lambda_function" "intake" {
  function_name    = "${var.name}-pentest-intake"
  role             = var.role_arn
  runtime          = "nodejs22.x"
  handler          = "index.handler"
  filename         = data.archive_file.intake.output_path
  source_code_hash = data.archive_file.intake.output_base64sha256
  timeout          = 10
  memory_size      = 256

  environment {
    variables = {
      SECRET_ID         = aws_secretsmanager_secret.signing.name
      QUEUE_URL         = aws_sqs_queue.jobs.url
      ALLOWED_TARGET    = var.allowed_target
      DEFAULT_ENDPOINTS = jsonencode(var.default_endpoints)
    }
  }

  depends_on = [aws_cloudwatch_log_group.intake]
}

# ---------- RunTask Lambda ----------
resource "aws_lambda_function" "runtask" {
  function_name    = "${var.name}-pentest-runtask"
  role             = var.role_arn
  runtime          = "nodejs22.x"
  handler          = "index.handler"
  filename         = data.archive_file.runtask.output_path
  source_code_hash = data.archive_file.runtask.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      CLUSTER        = var.cluster_arn
      TASK_FAMILY    = var.task_family
      SUBNETS        = join(",", var.subnet_ids)
      SECURITY_GROUP = var.security_group_id
    }
  }

  depends_on = [aws_cloudwatch_log_group.runtask]
}

resource "aws_lambda_event_source_mapping" "jobs" {
  event_source_arn = aws_sqs_queue.jobs.arn
  function_name    = aws_lambda_function.runtask.arn
  batch_size       = 1 # one job = one container
}

# ---------- public HTTPS entry ----------
resource "aws_apigatewayv2_api" "trigger" {
  name          = "${var.name}-pentest-trigger"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "intake" {
  api_id                 = aws_apigatewayv2_api.trigger.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.intake.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "pentest" {
  api_id    = aws_apigatewayv2_api.trigger.id
  route_key = "POST /pentest"
  target    = "integrations/${aws_apigatewayv2_integration.intake.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.trigger.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 10 # nobody can flood the queue
    throttling_rate_limit  = 5
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.intake.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.trigger.execution_arn}/*/POST/pentest"
}
