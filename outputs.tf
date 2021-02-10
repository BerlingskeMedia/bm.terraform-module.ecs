output "label_id" {
  value       = module.label.id
  description = "Whole project id"
}

output "ecs_cluster_arn" {
  value       = aws_ecs_cluster.default.arn
  description = "Project ECS cluster arn"
}

output "service_internal_security_group" {
  value       = aws_security_group.ecs_sg_internal.id
  description = "Security group used for communication between services"
}

output "iam_policy_document_json" {
  value = join("", data.aws_iam_policy_document.ecs_exec.*.json)
}

output "aws_cloudwatch_log_group_name" {
  value = aws_cloudwatch_log_group.app.name
}

output "access_key" {
  value       = module.drone-io.access_key
  description = "Access key used for pushing new ECR images"
}
output "secret_key" {
  value       = module.drone-io.secret_key
  description = "Secret key used for pushing new ECR images"
}

output "ecr_urls" {
  value = module.ecr.name_to_url
}

output "ecs_ec2_role_arn" {
  value       = var.launch_type == "EC2" ? aws_iam_role.ecs_ec2_role[0].arn : ""
  description = "ECS EC2 cluster role arn"
}

output "ecs_ec2_instance_profile_arn" {
  value       = var.launch_type == "EC2" ? aws_iam_instance_profile.ecs_ec2_instance_profile[0].arn : ""
  description = "ECS EC2 cluster instance profile arn"
}

output "ecs_ec2_asg" {
  value       = var.launch_type == "EC2" ? aws_autoscaling_group.ecs_ec2_autoscalling_group[0].arn : ""
  description = "ECS EC2 cluster autoscalling group arn"
}

output "ecs_ec2_launch_configuration" {
  value       = var.launch_type == "EC2" ? aws_launch_configuration.ecs_ec2_launch_configuration[0].arn : ""
  description = "ECS EC2 cluster launch configuration arn"
}

#ALB

output "domain_name" {
  value       = "${var.name}.${var.namespace}.${var.alb_main_domain}"
  description = "Domain name for all projects in the cluster"
}

output "domain_zone_id" {
  value       = data.aws_route53_zone.zone.zone_id
  description = "Domain zone id for all projects in the cluster"
}

output "alb_acm_certificate_arn" {
  value       = var.alb_internal_enabled || var.alb_external_enabled ? aws_acm_certificate.alb_cert[0].arn : ""
  description = "ACM certificate arn for all services in this cluster"
}

output "alb_internal_security_group_id" {
  value       = var.alb_internal_enabled ? module.alb_default_internal.security_group_id : ""
  description = "Internal ALB security group ID"
}

output "alb_internal_dns_endpoint" {
  value       = var.alb_internal_enabled ? module.alb_default_internal.alb_dns_name : ""
  description = "Internal ALB DNS endpoint"
}

output "alb_internal_https_listener_arn" {
  value       = var.alb_internal_enabled ? module.alb_default_internal.https_listener_arn : ""
  description = "Internal ALB https listener arn"
}

output "alb_internal_zone_id" {
  value       = var.alb_internal_enabled ? module.alb_default_internal.alb_zone_id : ""
  description = "Internal ALB DNS zone ID for aliases"
}

output "alb_external_security_group_id" {
  value       = var.alb_external_enabled ? module.alb_default_external.security_group_id : ""
  description = "External ALB security group ID"
}

output "alb_external_dns_endpoint" {
  value       = var.alb_external_enabled ? module.alb_default_external.alb_dns_name : ""
  description = "External ALB DNS endpoint"
}

output "alb_external_https_listener_arn" {
  value       = var.alb_external_enabled ? module.alb_default_external.https_listener_arn : ""
  description = "External ALB https listener arn"
}

output "alb_external_zone_id" {
  value       = var.alb_external_enabled ? module.alb_default_external.alb_zone_id : ""
  description = "External ALB DNS zone ID for aliases"
}

# KMS outputs

output "kms_key_alias_arn" {
  value       = module.kms_key.alias_arn
  description = "Common KMS key alias arn for all services in the cluster"
}

output "kms_key_alias_name" {
  value       = module.kms_key.alias_name
  description = "Common KMS key alias name for all services in the cluster"
}

output "kms_key_arn" {
  value       = module.kms_key.key_arn
  description = "Common KMS key arn for all services in the cluster"
}

output "kms_key_id" {
  value       = module.kms_key.key_id
  description = "Common KMS key ID for all services in the cluster"
}

output "kms_key_access_policy_arn" {
  value       = aws_iam_policy.kms_key_access_policy.arn
  description = "Common KMS IAM access policy arn"
}

# Service discovery outputs

output "service_discovery_namespace_id" {
  value       = join("", aws_service_discovery_private_dns_namespace.default.*.id)
  description = "Service discovery namespace ID"
}

output "service_discovery_name" {
  value       = join("", aws_service_discovery_private_dns_namespace.default.*.name)
  description = "Service discovery namespace name"
}

# ECS Module map outputs
output "internal_alb_output_map" {
  value       = local.internal_alb_output_map
  description = "Internal ALB Output map with variables `listener_arn`, `dns_name`, `dns_zone_id` and `allowed_security_group_id` inside"
}

output "external_alb_output_map" {
  value       = local.external_alb_output_map
  description = "External ALB Output map with variables `listener_arn`, `dns_name`, `dns_zone_id` and `allowed_security_group_id` inside"
}

output "output_map" {
  value       = local.output_map
  description = "Output map with most of the variables used for https://github.com/BerlingskeMedia/bm.terraform-module.ecs-service module"
}

output "context" {
  value = module.this.context
}

output "normalized_context" {
  value = module.this.normalized_context
}