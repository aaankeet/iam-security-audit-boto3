terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.73.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~>2.7"
    }
  }
}
provider "aws" {
  region = var.aws_region
}

# Package the Python Script
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/auditor.py"
  output_path = "${path.module}/auditor.zip"
}
# Create SNS Topic for Alerting
resource "aws_sns_topic" "iam_alerts" {
  name = "SecurityAlerts"
}
# Create Subscription for target email
resource "aws_sns_topic_subscription" "email_target" {
  topic_arn = aws_sns_topic.iam_alerts.arn
  endpoint  = var.alert_email
  protocol  = "email"
}

# Least-Privilege IAM Role for Lambda
resource "aws_iam_role" "lambda_execution_role" {
  name = "iam-security-auditor-role"

  # Trust Policy
  assume_role_policy = jsonencode(
    {
      "Version" = "2012-10-17"

      "Statement" = [
        {
          "Effect" = "Allow",
          "Action" = "sts:AssumeRole",
          "Principal" = {
            "Service" = "lambda.amazonaws.com"
          }
      }]
    }
  )
}

# Permission Policy
resource "aws_iam_role_policy" "auditor_policy" {
  name = "iam-auditor-policy"
  role = aws_iam_role.lambda_execution_role.name

  policy = jsonencode({
    "Version" = "2012-10-17"

    "Statement" = [
      {
        "Effect" = "Allow",
        "Action" = [
          "iam:ListUsers",
          "iam:ListMFADevices",
          "iam:GetLoginProfile",
          "iam:ListAccessKeys",
          "iam:ListAttachedUserPolicies",
          "iam:ListGroupsForUser",
          "iam:ListAttachedGroupPolicies"
        ],
        "Resource" = "*"
      },
      {
        "Effect"   = "Allow",
        "Action"   = "sns:Publish",
        "Resource" = aws_sns_topic.iam_alerts.arn
      },
      {
        "Effect" = "Allow",
        "Action" = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource" = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Lambda Function resource
resource "aws_lambda_function" "lambda_iam_auditor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "lambda-security-auditor"
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "auditor.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      SNS_TOPIC_ARN    = aws_sns_topic.iam_alerts.arn
      MAX_KEY_AGE_DAYS = tostring(var.max_key_age_days)
    }
  }
  depends_on = [
    aws_iam_role_policy.auditor_policy
  ]
}

# EventBridge Daily Schedule
resource "aws_cloudwatch_event_rule" "daily_audit" {
  name                = "daily-iam-security-audit"
  description         = "Trigger IAM Security audit once every 24 hours"
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "trigger_lambda" {
  rule      = aws_cloudwatch_event_rule.daily_audit.name
  target_id = "IAMSecurityAuditor"
  arn       = aws_lambda_function.lambda_iam_auditor.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_iam_auditor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_audit.arn
}
