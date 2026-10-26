variable "region" {
  type        = string
  default     = "us-east-1"
  description = "Region of the two test keys."
}

variable "name" {
  type        = string
  default     = "strongroom-dev"
  description = "Alias of the primary key; the secondary is NAME-secondary."
}

variable "service_user" {
  type        = string
  default     = "strongroom-dev-live"
  description = "Least-privilege IAM user whose access key scripts/live-env.mjs issues and revokes. The key never enters state."
}
