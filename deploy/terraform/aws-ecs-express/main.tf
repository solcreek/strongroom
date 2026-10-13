# Strongroom on ECS Express Mode: Fargate tasks behind a managed HTTPS load balancer.
# KMS access comes from the task role (containerCredentials), so STRONGROOM_CONFIG holds no secret:
# only key ARNs, tenant IDs and token digests. It is generated here and passed as a plain environment variable.

locals {
  config = jsonencode({
    keys = { for ref, arn in var.kms_keys : ref => {
      provider             = "aws"
      region               = split(":", arn)[3]
      keyId                = arn
      containerCredentials = true
    } }
    principals = [for p in var.principals : {
      tokenSha256 = p.token_sha256
      tenantId    = p.tenant_id
      permissions = p.permissions
      keys        = p.keys
    }]
  })
}

resource "aws_ecr_repository" "this" {
  name                 = var.name
  image_tag_mutability = "MUTABLE" # deployments pin digests; tags are labels only
  force_delete         = var.force_delete_registry
  image_scanning_configuration { scan_on_push = true }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "tasks" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.tasks.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# The application identity: Encrypt/Decrypt on the configured keys only, and only with Strongroom's
# encryption context, so this role cannot decrypt other data protected by the same key.
resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.tasks.json
}

data "aws_iam_policy_document" "kms" {
  statement {
    actions   = ["kms:Encrypt", "kms:Decrypt"]
    resources = values(var.kms_keys)
    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:strongroom"
      values   = ["false"]
    }
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "kms:EncryptionContextKeys"
      values   = ["strongroom"]
    }
  }
}

resource "aws_iam_role_policy" "kms" {
  name   = "kms"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.kms.json
}

data "aws_iam_policy_document" "infrastructure" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "infrastructure" {
  name               = "${var.name}-infrastructure"
  assume_role_policy = data.aws_iam_policy_document.infrastructure.json
}

resource "aws_iam_role_policy_attachment" "infrastructure" {
  role       = aws_iam_role.infrastructure.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRoleforExpressGatewayServices"
}

resource "aws_ecs_cluster" "this" {
  name = var.name
}

resource "aws_ecs_express_gateway_service" "this" {
  count                   = var.image == "" ? 0 : 1
  service_name            = var.name
  cluster                 = aws_ecs_cluster.this.name
  execution_role_arn      = aws_iam_role.execution.arn
  infrastructure_role_arn = aws_iam_role.infrastructure.arn
  task_role_arn           = aws_iam_role.task.arn
  health_check_path       = "/readyz"
  cpu                     = var.cpu
  memory                  = var.memory
  wait_for_steady_state   = true

  primary_container {
    image          = var.image
    container_port = 8080
    environment {
      name  = "STRONGROOM_CONFIG"
      value = local.config
    }
    aws_logs_configuration = [{
      log_group         = aws_cloudwatch_log_group.this.name
      log_stream_prefix = var.name
    }]
  }

  scaling_target = [{
    auto_scaling_metric       = "AVERAGE_CPU"
    auto_scaling_target_value = 60
    min_task_count            = var.min_tasks
    max_task_count            = var.max_tasks
  }]

  depends_on = [aws_iam_role_policy_attachment.execution, aws_iam_role_policy_attachment.infrastructure, aws_iam_role_policy.kms]
}
