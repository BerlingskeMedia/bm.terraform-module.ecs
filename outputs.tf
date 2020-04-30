output "rds_endpoint" {
  description = "Endpoint url of created RDS"
  value       = module.rds.rds_endpoint
}

output "custom_container_definition_1" {
  value = var.custom_container_definition_1
}

output "container_definition" {
  value = module.container_definition.object
}
