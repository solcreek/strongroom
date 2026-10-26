# The live conformance suite's AWS resources (scripts/test-live.mjs). No credential is created here: the service
# user's access key is issued and revoked by scripts/live-env.mjs, so state holds only names and ARNs.

# Ciphertexts recorded by earlier runs depend on these keys; never destroy them from this stack.
resource "aws_kms_key" "primary" {
  description             = "strongroom live integration test key (dev only)"
  deletion_window_in_days = 7
  lifecycle { prevent_destroy = true }
}

resource "aws_kms_alias" "primary" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.primary.key_id
}

# The service user has no grant here: "not granted" scenarios exercise real IAM denials.
# test-live.mjs --mutate disables it and schedules its deletion, then cancels and re-enables it.
resource "aws_kms_key" "secondary" {
  description             = "strongroom live test secondary key (dev only; toggled disabled by --mutate)"
  deletion_window_in_days = 7
  lifecycle { prevent_destroy = true }
}

resource "aws_kms_alias" "secondary" {
  name          = "alias/${var.name}-secondary"
  target_key_id = aws_kms_key.secondary.key_id
}

resource "aws_iam_user" "service" {
  name = var.service_user
}

# The same grant setup aws writes for a deployment: the primary key only, and only with Strongroom's encryption context.
resource "aws_iam_user_policy" "service" {
  name = "strongroom-kms-primary"
  user = aws_iam_user.service.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "StrongroomEnvelope"
      Effect   = "Allow"
      Action   = ["kms:Encrypt", "kms:Decrypt"]
      Resource = aws_kms_key.primary.arn
      Condition = {
        Null                        = { "kms:EncryptionContext:strongroom" = "false" }
        "ForAllValues:StringEquals" = { "kms:EncryptionContextKeys" = ["strongroom"] }
      }
    }]
  })
}
