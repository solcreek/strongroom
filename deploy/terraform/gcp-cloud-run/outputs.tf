output "repository" {
  description = "Push target for scripts/image.mjs --repository."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.this.repository_id}/strongroom"
}

output "url" {
  description = "HTTPS origin to use as STRONGROOM_URL."
  value       = try(google_cloud_run_v2_service.this[0].uri, null)
}

output "runtime_service_account" {
  value = google_service_account.runtime.email
}
