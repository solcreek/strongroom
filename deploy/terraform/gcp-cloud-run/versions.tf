terraform {
  required_version = ">= 1.6"
  required_providers {
    # invoker_iam_disabled on google_cloud_run_v2_service; verified with 8.7.0.
    google = { source = "hashicorp/google", version = ">= 6.0, < 9.0" }
  }
}

provider "google" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
  default_labels        = merge({ app = "strongroom", managed-by = "terraform" }, var.labels)
}
