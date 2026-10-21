variable "region" {
  type        = string
  description = "AWS region for the service. Each KMS key ARN must be in this region."
}

variable "name" {
  type        = string
  default     = "strongroom"
  description = "Prefix for every resource name."
}

variable "image" {
  type        = string
  default     = ""
  description = "Image pinned by digest (REPO@sha256:...), as printed by scripts/image.mjs. Leave empty on the first apply to create only the registry and roles."
}

variable "kms_keys" {
  type        = map(string)
  description = "Key reference => symmetric KMS key ARN. References are stable API names: never remap one to a different key."
  validation {
    condition     = length(var.kms_keys) > 0 && alltrue([for ref, arn in var.kms_keys : can(regex("^[A-Za-z0-9_-]{1,64}$", ref)) && can(regex("^arn:aws(-us-gov|-cn)?:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$", arn))])
    error_message = "Each key reference must match ^[A-Za-z0-9_-]{1,64}$ and map to a full key ARN (not an alias)."
  }
}

variable "tenant_id" {
  type        = string
  description = "The one tenant this deployment serves. Give each tenant its own deployment, KMS key and task role."
  # The service counts UTF-8 bytes, length() counts characters: derive the byte count from the base64 length.
  validation {
    condition     = length(var.tenant_id) > 0 && length(base64encode(var.tenant_id)) / 4 * 3 - length(regexall("=", base64encode(var.tenant_id))) <= 256
    error_message = "tenant_id must be 1-256 UTF-8 bytes."
  }
}

variable "principals" {
  type = list(object({
    token_sha256 = string
    permissions  = list(string)
    keys         = list(string)
    # Declared only so a leftover per-principal tenant is rejected: an object type silently drops undeclared attributes.
    tenant_id = optional(string)
  }))
  description = "Callers of this tenant's deployment. Generate token_sha256 with: strongroom token --token-file FILE --keys K. The raw token never enters Terraform."
  validation {
    condition     = length(var.principals) > 0 && alltrue([for p in var.principals : can(regex("^[a-f0-9]{64}$", p.token_sha256))])
    error_message = "token_sha256 must be a lowercase SHA-256 hex digest."
  }
  validation {
    condition     = alltrue([for p in var.principals : p.tenant_id == null])
    error_message = "principals no longer carry tenant_id: one deployment serves one tenant (var.tenant_id). Split a mixed-tenant list into one deployment per tenant."
  }
}

variable "cpu" {
  type    = string
  default = "256"
}

variable "memory" {
  type    = string
  default = "512"
}

variable "min_tasks" {
  type    = number
  default = 1
}

variable "max_tasks" {
  type    = number
  default = 2
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "force_delete_registry" {
  type        = bool
  default     = false
  description = "Allow destroy to delete the ECR repository while it still holds images."
}

variable "tags" {
  type    = map(string)
  default = {}
}
