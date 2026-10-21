variable "project_id" {
  type        = string
  description = "Project that runs the service. KMS keys may live in another project."
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "name" {
  type        = string
  default     = "strongroom"
  description = "Prefix for every resource name."
}

variable "image" {
  type        = string
  default     = ""
  description = "Image pinned by digest (REPO@sha256:...), as printed by scripts/image.mjs. Leave empty on the first apply to create only the registry and identity."
}

variable "kms_keys" {
  type        = map(string)
  description = "Key reference => CryptoKey (projects/P/locations/L/keyRings/R/cryptoKeys/K). References are stable API names: never remap one to a different key."
  validation {
    condition     = length(var.kms_keys) > 0 && alltrue([for ref, id in var.kms_keys : can(regex("^[A-Za-z0-9_-]{1,64}$", ref)) && can(regex("^projects/[A-Za-z0-9_-]+/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$", id))])
    error_message = "Each key reference must match ^[A-Za-z0-9_-]{1,64}$ and map to a CryptoKey name without a version."
  }
}

variable "tenant_id" {
  type        = string
  description = "The one tenant this deployment serves. Give each tenant its own deployment, KMS key and service account."
  validation {
    condition     = length(var.tenant_id) > 0 && length(var.tenant_id) <= 256
    error_message = "tenant_id must be 1-256 characters."
  }
}

variable "principals" {
  type = list(object({
    token_sha256 = string
    permissions  = list(string)
    keys         = list(string)
  }))
  description = "Callers of this tenant's deployment. Generate token_sha256 with: strongroom token --token-file FILE --keys K. The raw token never enters Terraform."
  validation {
    condition     = length(var.principals) > 0 && alltrue([for p in var.principals : can(regex("^[a-f0-9]{64}$", p.token_sha256))])
    error_message = "token_sha256 must be a lowercase SHA-256 hex digest."
  }
}

variable "public" {
  type        = bool
  default     = false
  description = "true disables the Cloud Run invoker IAM check, leaving Strongroom bearer tokens as the only gate (as on Workers). false requires callers to send a Google ID token in X-Serverless-Authorization."
}

variable "invokers" {
  type        = list(string)
  default     = []
  description = "IAM members granted roles/run.invoker when public = false, e.g. serviceAccount:app@P.iam.gserviceaccount.com."
}

variable "max_instances" {
  type    = number
  default = 10
}

variable "min_instances" {
  type    = number
  default = 0
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "labels" {
  type    = map(string)
  default = {}
}
