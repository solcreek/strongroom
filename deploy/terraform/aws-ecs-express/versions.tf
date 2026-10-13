terraform {
  required_version = ">= 1.6"
  required_providers {
    # aws_ecs_express_gateway_service needs a recent 6.x provider; verified with 6.68.0.
    aws = { source = "hashicorp/aws", version = ">= 6.68, < 7.0" }
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = merge({ "app" = "strongroom", "managed-by" = "terraform" }, var.tags) }
}
