output "live_env" {
  description = "Lines scripts/live-env.mjs writes to live.env in the live directory."
  value = {
    STRONGROOM_LIVE_AWS_KEY_ARN       = aws_kms_key.primary.arn
    STRONGROOM_LIVE_AWS_SECONDARY_ARN = aws_kms_key.secondary.arn
  }
}

output "service_user" {
  value = aws_iam_user.service.name
}
