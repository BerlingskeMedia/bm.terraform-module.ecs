output "ecs_cluster_arn" {
  value = aws_ecs_cluster.default.arn
}

output "service_internal_security_group" {
  value       = aws_security_group.ecs_sg_internal.id
  description = "Security group used inside services"
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

output "alb_acm_certificate_arn" {
  value = var.alb_internal_enabled || var.alb_external_enabled ? aws_acm_certificate.alb_cert[0].arn : ""
}

output "alb_common_security_group_id" {
  value = var.alb_internal_enabled || var.alb_external_enabled ? module.security.alb_sg_id : ""
}

output "alb_internal_dns_endpoint" {
  value = var.alb_internal_enabled ? module.alb_default_internal.alb_dns_name : ""
}

output "alb_internal_https_listener_arn" {
  value = var.alb_internal_enabled ? module.alb_default_internal.https_listener_arn : ""
}

output "alb_external_dns_endpoint" {
  value = var.alb_external_enabled ? module.alb_default_external.alb_dns_name : ""
}

output "alb_external_https_listener_arn" {
  value = var.alb_external_enabled ? module.alb_default_external.https_listener_arn : ""
}