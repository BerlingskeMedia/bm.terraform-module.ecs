output "rds_endpoint" {
  description = "Endpoint url of created RDS"
  value       = module.rds.rds_endpoint
}

output "environments_rds" {
  description = "Environment variables generated due process of creating resources"
  value       = local.rds_envs
}

output "ecs_cluster_arn" {
  value = aws_ecs_cluster.default.arn
}

output "service_internal_security_group" {
  value       = aws_security_group.ecs_sg_internal.id
  description = "Security group used inside services"
}

output "rds_security_group" {
  value       = module.rds.rds_sg_id
  description = "Security group allows to connect with RDS"
}

output "alb_sg" {
  value = module.security.alb_sg_id
}

output "iam_policy_document_json" {
  value = join("", data.aws_iam_policy_document.ecs_exec.*.json)
}


output "aws_cloudwatch_log_group_name" {
  value = aws_cloudwatch_log_group.app.name
}