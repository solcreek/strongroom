# Offline: the mock provider needs no Google credentials. Run with: tofu -chdir=infra/live-test/gcp test
mock_provider "google" {}

override_resource {
  target = google_kms_key_ring.this
  values = { id = "projects/p/locations/global/keyRings/strongroom-dev" }
}

override_resource {
  target = google_kms_crypto_key.primary
  values = { id = "projects/p/locations/global/keyRings/strongroom-dev/cryptoKeys/primary" }
}

override_resource {
  target = google_kms_crypto_key.secondary
  values = { id = "projects/p/locations/global/keyRings/strongroom-dev/cryptoKeys/secondary" }
}

override_resource {
  target = google_service_account.service
  values = { email = "strongroom-dev@p.iam.gserviceaccount.com" }
}

variables {
  project_id = "p"
}

# "Not granted" scenarios depend on the service account reaching the primary key only, as setup gcp grants it.
run "service_account_reaches_the_primary_key_only" {
  command = plan
  assert {
    condition     = google_kms_crypto_key_iam_member.service.crypto_key_id == google_kms_crypto_key.primary.id
    error_message = "The service account must be granted the primary key only."
  }
  assert {
    condition     = google_kms_crypto_key_iam_member.service.role == "roles/cloudkms.cryptoKeyEncrypterDecrypter" && google_kms_crypto_key_iam_member.service.member == "serviceAccount:strongroom-dev@p.iam.gserviceaccount.com"
    error_message = "The grant must be encrypt/decrypt, to the test service account."
  }
  assert {
    condition     = output.live_env.STRONGROOM_LIVE_GCP_KEY == google_kms_crypto_key.primary.id && output.live_env.STRONGROOM_LIVE_GCP_SECONDARY == google_kms_crypto_key.secondary.id
    error_message = "live.env must point the suite at the primary and secondary keys."
  }
}

# A test stack must never land in whatever project gcloud points at.
run "project_is_required" {
  command = plan
  variables { project_id = "" }
  expect_failures = [var.project_id]
}
