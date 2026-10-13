output "repository_url" {
  description = "Push target for scripts/image.mjs --repository."
  value       = aws_ecr_repository.this.repository_url
}

output "url" {
  description = "HTTPS origin to use as STRONGROOM_URL."
  value       = try(aws_ecs_express_gateway_service.this[0].ingress_paths[0].endpoint, null)
}

output "task_role_arn" {
  value = aws_iam_role.task.arn
}

output "log_group" {
  description = "kms_error operator events land here, keyed by requestId."
  value       = aws_cloudwatch_log_group.this.name
}
