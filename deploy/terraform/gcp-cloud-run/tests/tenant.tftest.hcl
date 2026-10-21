# Offline: the mock provider needs no Google credentials. Run with: tofu -chdir=deploy/terraform/gcp-cloud-run test
mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      email  = "strongroom@demo-project.iam.gserviceaccount.com"
      member = "serviceAccount:strongroom@demo-project.iam.gserviceaccount.com"
    }
  }
}

variables {
  project_id = "demo-project"
  kms_keys   = { primary = "projects/demo-project/locations/global/keyRings/strongroom/cryptoKeys/primary" }
  tenant_id  = "acme"
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

# 256 bytes of 2-byte characters is the service's limit; one more byte must fail at plan time, not at revision startup.
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
