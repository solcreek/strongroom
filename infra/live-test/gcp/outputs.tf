output "live_env" {
  description = "Lines scripts/live-env.mjs writes to live.env in the live directory."
  value = {
    STRONGROOM_LIVE_GCP_KEY       = google_kms_crypto_key.primary.id
    STRONGROOM_LIVE_GCP_SECONDARY = google_kms_crypto_key.secondary.id
  }
}

output "service_account" {
  value = google_service_account.service.email
}
