# Offline: the mock provider needs no AWS credentials. Run with: tofu -chdir=infra/live-test/aws test
mock_provider "aws" {}

override_resource {
  target = aws_kms_key.primary
  values = { arn = "arn:aws:kms:us-east-1:123456789012:key/primary", key_id = "primary" }
}

override_resource {
  target = aws_kms_key.secondary
  values = { arn = "arn:aws:kms:us-east-1:123456789012:key/secondary", key_id = "secondary" }
}

# "Not granted" scenarios depend on the service user reaching the primary key only, as setup aws grants it.
run "service_user_reaches_the_primary_key_only" {
  command = plan
  assert {
    condition     = length(jsondecode(aws_iam_user_policy.service.policy).Statement) == 1 && jsondecode(aws_iam_user_policy.service.policy).Statement[0].Resource == aws_kms_key.primary.arn
    error_message = "The service user must be granted the primary key and nothing else."
  }
  assert {
    condition     = toset(jsondecode(aws_iam_user_policy.service.policy).Statement[0].Action) == toset(["kms:Encrypt", "kms:Decrypt"])
    error_message = "The service user may only Encrypt and Decrypt."
  }
  assert {
    condition     = jsondecode(aws_iam_user_policy.service.policy).Statement[0].Condition.Null["kms:EncryptionContext:strongroom"] == "false"
    error_message = "The grant must require Strongroom's encryption context, like a real deployment's."
  }
  assert {
    condition     = output.live_env.STRONGROOM_LIVE_AWS_KEY_ARN == aws_kms_key.primary.arn && output.live_env.STRONGROOM_LIVE_AWS_SECONDARY_ARN == aws_kms_key.secondary.arn
    error_message = "live.env must point the suite at the primary and secondary keys."
  }
}
