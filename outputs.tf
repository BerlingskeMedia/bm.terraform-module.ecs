output "ecs_cluster_arn" {
  value = aws_ecs_cluster.default.arn
}

output "service_internal_security_group" {
  value       = aws_security_group.ecs_sg_internal.id
  description = "Security group used inside services"
}

output "iam_policy_document_json" {
  value = join("", data.aws_iam_policy_document.ecs_exec.*.json)
}

output "aws_cloudwatch_log_group_name" {
  value = aws_cloudwatch_log_group.app.name
}

output "access_key" {
  value = module.drone-io.access_key
}
output "secret_key" {
  value = module.drone-io.secret_key
}

output "ecr_urls" {
  value = module.ecr.name_to_url
}

output "ecs_ec2_role_arn" {
  value = var.launch_type == "EC2" ? aws_iam_role.ecs_ec2_role[0].arn : ""
}

output "ecs_ec2_instance_profile_arn" {
  value = var.launch_type == "EC2" ? aws_iam_instance_profile.ecs_ec2_instance_profile[0].arn : ""
}

output "ecs_ec2_asg" {
  value = var.launch_type == "EC2" ? aws_autoscaling_group.ecs_ec2_autoscalling_group[0].arn : ""
}

output "ecs_ec2_launch_configuration" {
  value = var.launch_type == "EC2" ? aws_launch_configuration.ecs_ec2_launch_configuration[0].arn : ""
}

#ALB

output "domain_name" {
  value = "${var.name}.${var.namespace}.${var.alb_main_domain}"
}

output "domain_zone_id" {
  value = data.aws_route53_zone.zone.zone_id
}

output "alb_acm_certificate_arn" {
  value = var.alb_internal_enabled || var.alb_external_enabled ? aws_acm_certificate.alb_cert[0].arn : ""
}

output "alb_internal_security_group_id" {
  value = var.alb_internal_enabled ? module.alb_default_internal.security_group_id : ""
}

output "alb_internal_dns_endpoint" {
  value = var.alb_internal_enabled ? module.alb_default_internal.alb_dns_name : ""
}

output "alb_internal_https_listener_arn" {
  value = var.alb_internal_enabled ? module.alb_default_internal.https_listener_arn : ""
}

output "alb_internal_zone_id" {
  value = var.alb_internal_enabled ? module.alb_default_internal.alb_zone_id : ""
}

output "alb_external_dns_endpoint" {
  value = var.alb_external_enabled ? module.alb_default_external.alb_dns_name : ""
}

output "alb_external_https_listener_arn" {
  value = var.alb_external_enabled ? module.alb_default_external.https_listener_arn : ""
}

output "alb_external_security_group_id" {
  value = var.alb_external_enabled ? module.alb_default_external.security_group_id : ""
}

output "alb_external_zone_id" {
  value = var.alb_external_enabled ? module.alb_default_external.alb_zone_id : ""
}

# KMS outputs

output "kms_key_alias_arn" {
  value = module.kms_key.alias_arn
}

output "kms_key_alias_name" {
  value = module.kms_key.alias_name
}

output "kms_key_arn" {
  value = module.kms_key.key_arn
}

output "kms_key_name" {
  value = module.kms_key.key_id
}

output "kms_key_access_policy_arn" {
  value = aws_iam_policy.kms_key_access_policy.arn
}

# ECS Module map outputs
output "internal_alb_output_map" {
  value = local.output_map
}

output "external_alb_output_map" {
  value = local.output_map
}

output "output_map" {
  value = local.output_map
}