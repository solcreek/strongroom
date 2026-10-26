terraform {
  required_version = ">= 1.6"
  # scripts/live-env.mjs passes the path (tofu/aws/ in the live directory, see scripts/live-dir.mjs). State holds
  # no secret, and the script re-adopts the existing resources when it is missing.
  backend "local" {}
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.68, < 7.0" }
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = { project = "strongroom", purpose = "integration-test", managed-by = "opentofu" } }
}
