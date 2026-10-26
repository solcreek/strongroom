terraform {
  required_version = ">= 1.6"
  # scripts/live-env.mjs passes the path (tofu/gcp/ in the live directory, see scripts/live-dir.mjs). State holds
  # no secret, and the script re-adopts the existing resources when it is missing.
  backend "local" {}
  required_providers {
    google = { source = "hashicorp/google", version = ">= 6.0, < 9.0" }
  }
}

provider "google" {
  project               = var.project_id
  user_project_override = true
  billing_project       = var.project_id
  default_labels        = { project = "strongroom", purpose = "integration-test", managed-by = "opentofu" }
}
