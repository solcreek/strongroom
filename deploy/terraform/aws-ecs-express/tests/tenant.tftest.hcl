# Offline: the mock provider needs no AWS credentials. Run with: tofu -chdir=deploy/terraform/aws-ecs-express test
mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
}

variables {
  region    = "us-east-1"
  kms_keys  = { primary = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000" }
  tenant_id = "acme"
  principals = [{
    token_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
    permissions  = ["encrypt", "decrypt"]
    keys         = ["primary"]
  }]
}

run "one_tenant_config" {
  command = plan
  assert {
    condition     = jsondecode(local.config).tenantId == "acme" && !contains(keys(jsondecode(local.config).principals[0]), "tenantId")
    error_message = "The generated configuration must carry the tenant at the top level only."
  }
}

# 256 bytes of 2-byte characters is the service's limit; one more byte must fail at plan time, not at task startup.
run "tenant_id_at_the_byte_limit" {
  command = plan
  variables { tenant_id = join("", [for i in range(128) : "é"]) }
}

run "tenant_id_over_the_byte_limit" {
  command = plan
  variables { tenant_id = join("", [for i in range(128) : "é"], ["x"]) }
  expect_failures = [var.tenant_id]
}

run "empty_tenant_id" {
  command = plan
  variables { tenant_id = "" }
  expect_failures = [var.tenant_id]
}

# A leftover per-principal tenant would otherwise be dropped silently and its token authorized for this tenant.
run "legacy_principal_tenant_is_rejected" {
  command = plan
  variables {
    principals = [{
      token_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
      tenant_id    = "other"
      permissions  = ["encrypt", "decrypt"]
      keys         = ["primary"]
    }]
  }
  expect_failures = [var.principals]
}
