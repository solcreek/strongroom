variable "project_id" {
  type        = string
  description = "Project holding the test key ring. There is no default: a test stack must never land in whatever project gcloud points at."
  validation {
    condition     = try(length(var.project_id) > 0, false)
    error_message = "Set project_id explicitly (scripts/live-env.mjs --gcp-project P)."
  }
}

variable "location" {
  type    = string
  default = "global"
}

variable "keyring" {
  type        = string
  default     = "strongroom-dev"
  description = "Key ring of the primary and secondary keys. Key rings and CryptoKey names can never be deleted or reused, so keep this stable."
}

variable "service_account" {
  type        = string
  default     = "strongroom-dev"
  description = "Account ID of the least-privilege service account whose key scripts/live-env.mjs issues and revokes. The key never enters state."
}
