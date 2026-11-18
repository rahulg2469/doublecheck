# Email alerts:
#   worker saves report --> S3 event --> alerts Lambda --> decision "alert"? --> SNS --> email

resource "aws_sns_topic" "alerts" {
  name = "${var.name}-pentest-alerts"
}

# AWS emails a confirmation link first; alerts arrive only after it is clicked
resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "archive_file" "alerts" {
  type        = "zip"
  source_file = "${var.lambdas_dir}/pentest-alerts/index.mjs"
  output_path = "${path.module}/.build/pentest-alerts.zip"
}

resource "aws_cloudwatch_log_group" "alerts" {
  name              = "/aws/lambda/${var.name}-pentest-alerts"
  retention_in_days = 7
}

resource "aws_lambda_function" "alerts" {
  function_name    = "${var.name}-pentest-alerts"
  role             = var.role_arn
  runtime          = "nodejs22.x"
  handler          = "index.handler"
  filename         = data.archive_file.alerts.output_path
  source_code_hash = data.archive_file.alerts.output_base64sha256
  timeout          = 15
  memory_size      = 256

  environment {
    variables = {
      TOPIC_ARN = aws_sns_topic.alerts.arn
      ALERT_ON  = "alert"
    }
  }

  depends_on = [aws_cloudwatch_log_group.alerts]
}

resource "aws_lambda_permission" "s3" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alerts.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${var.reports_bucket}"
}

# Only pentest JSON reports trigger it
resource "aws_s3_bucket_notification" "reports" {
  bucket = var.reports_bucket

  lambda_function {
    lambda_function_arn = aws_lambda_function.alerts.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "reports/"
    filter_suffix       = ".json"
  }

  depends_on = [aws_lambda_permission.s3]
}
