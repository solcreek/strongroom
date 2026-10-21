# Strongroom on Cloud Run. KMS access comes from the runtime service account through the metadata
# server (metadataServer), so STRONGROOM_CONFIG holds no secret: only key names, the tenant ID and token
# digests. It is generated here and passed as a plain environment variable. One deployment serves one
# tenant; apply this module once per tenant.

locals {
  config = jsonencode({
    tenantId   = var.tenant_id
    keys       = { for ref, id in var.kms_keys : ref => { provider = "gcp", keyId = id, metadataServer = true } }
    principals = [for p in var.principals : { tokenSha256 = p.token_sha256, permissions = p.permissions, keys = p.keys }]
  })
}

resource "google_project_service" "this" {
  for_each           = toset(["run.googleapis.com", "artifactregistry.googleapis.com", "cloudkms.googleapis.com", "iam.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "this" {
  repository_id = var.name
  location      = var.region
  format        = "DOCKER"
  depends_on    = [google_project_service.this]
}

resource "google_service_account" "runtime" {
  account_id   = "${var.name}-run"
  display_name = "Strongroom Cloud Run runtime"
  depends_on   = [google_project_service.this]
}

# Encrypt/decrypt on the configured keys only; the keys can be in a central key project.
resource "google_kms_crypto_key_iam_member" "runtime" {
  for_each      = var.kms_keys
  crypto_key_id = each.value
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = google_service_account.runtime.member
}

resource "google_cloud_run_v2_service" "this" {
  count                = var.image == "" ? 0 : 1
  name                 = var.name
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = var.public
  deletion_protection  = var.deletion_protection

  template {
    service_account                  = google_service_account.runtime.email
    max_instance_request_concurrency = 80
    timeout                          = "30s"
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }
    containers {
      image = var.image
      ports { container_port = 8080 }
      env {
        name  = "STRONGROOM_CONFIG"
        value = local.config
      }
      resources {
        limits            = { cpu = "1", memory = "512Mi" }
        cpu_idle          = true
        startup_cpu_boost = true
      }
      startup_probe {
        http_get { path = "/readyz" }
        period_seconds    = 2
        failure_threshold = 15
      }
      liveness_probe {
        http_get { path = "/healthz" }
      }
    }
  }
  depends_on = [google_kms_crypto_key_iam_member.runtime]
}

resource "google_cloud_run_v2_service_iam_member" "invokers" {
  for_each = var.image == "" || var.public ? toset([]) : toset(var.invokers)
  name     = google_cloud_run_v2_service.this[0].name
  location = var.region
  role     = "roles/run.invoker"
  member   = each.value
}
