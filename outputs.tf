output "rds_endpoint" {
  description = "Endpoint url of created RDS"
  value       = module.rds.rds_endpoint
}