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
  value = join("", data.aws_ssm_parameter.access_key.*.value)
}
output "secret_key" {
  value = join("", data.aws_ssm_parameter.secret_key.*.value)
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