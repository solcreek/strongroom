# The live conformance suite's Cloud KMS resources (scripts/test-live.mjs). No credential is created here: the service
# account's key is issued and revoked by scripts/live-env.mjs, so state holds only names.

resource "google_project_service" "kms" {
  service            = "cloudkms.googleapis.com"
  disable_on_destroy = false
}

resource "google_kms_key_ring" "this" {
  name       = var.keyring
  location   = var.location
  depends_on = [google_project_service.kms]
}

# Ciphertexts recorded by earlier runs depend on these keys, and a CryptoKey name can never be reused.
resource "google_kms_crypto_key" "primary" {
  name                       = "primary"
  key_ring                   = google_kms_key_ring.this.id
  purpose                    = "ENCRYPT_DECRYPT"
  destroy_scheduled_duration = "2592000s"
  lifecycle { prevent_destroy = true }
}

# The service account has no grant here: "not granted" scenarios exercise real IAM denials.
# test-live.mjs --mutate disables version 1 and re-enables it.
resource "google_kms_crypto_key" "secondary" {
  name                       = "secondary"
  key_ring                   = google_kms_key_ring.this.id
  purpose                    = "ENCRYPT_DECRYPT"
  destroy_scheduled_duration = "2592000s"
  lifecycle { prevent_destroy = true }
}

resource "google_service_account" "service" {
  account_id   = var.service_account
  display_name = "strongroom live KMS tests (dev only)"
  description  = "purpose=integration-test; keys are issued and revoked by scripts/live-env.mjs"
}

# The same grant setup gcp writes for a deployment: the primary key only.
resource "google_kms_crypto_key_iam_member" "service" {
  crypto_key_id = google_kms_crypto_key.primary.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.service.email}"
}
