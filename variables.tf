variable "region" {
  type        = string
  description = "AWS Region for S3 bucket"
  #sane default
}

variable "enabled" {
  type        = bool
  default     = true
  description = "Defines whether create resources for this module and it's submodules"
}

variable "vpc_id" {
  type        = string
  description = "ID of vpc for this infrastructure"
}

variable "igw_id" {
  type        = string
  description = "Internet Gateway ID"
}

variable "nat_id" {
  type        = string
  description = "NAT Gateway ID"
}

variable "private_subnets" {
  type        = list(string)
  default     = []
  description = "List of private subnet's ID" //. Will be ignored if parameter application_cidr==true"
}

variable "namespace" {
  type        = string
  description = "Namespace (e.g. `eg` or `cp`)"
  #no default.
}

variable "stage" {
  type        = string
  description = "Stage (e.g. `prod`, `testing`, `staging`)"
  #no default.
}

variable "name" {
  type        = string
  description = "Name of the application"
  #no default
}

variable "delimiter" {
  type        = string
  default     = "-"
  description = "Delimiter between `namespace`, `stage`, `name` and `attributes`"
  #sane default
}

variable "attributes" {
  type        = list(string)
  description = "Additional attributes (_e.g._ \"1\")"
  default     = []
  #sane default
}

variable "tags" {
  type        = map(string)
  description = "Additional tags (_e.g._ { BusinessUnit : ABC })"
  #no default
}

#### RDS section
variable "run_rds" {
  type        = bool
  description = "Should run RDS cluster?"
  default     = false
}
variable "rds_port" {
  type        = string
  description = "RDS port"
  default     = "3306"
  #sane default
}

variable "rds_admin" {
  type        = string
  description = "RDS root username"
  default     = ""
}
variable "rds_db_engine" {
  type        = string
  default     = "aurora-mysql"
  description = "The name of the database engine to be used for this DB cluster. Valid values: `aurora`, `aurora-mysql`, `aurora-postgresql`"
}

variable "rds_db_cluster_family" {
  type        = string
  default     = "aurora-mysql5.7"
  description = "The family of the DB cluster parameter group"
}

variable "rds_instaces_count" {
  type        = string
  description = "How many instances should run in cluster"
  default     = "1"
}

variable "rds_instance_type" {
  type        = string
  description = "Instance type"
  default     = "db.t3.small"
}

variable "rds_dbname" {
  type        = string
  description = "RDS database name"
  default     = "dbname"
}


#### ECS section

variable "log_retention_in_days" {
  type        = string
  description = "Log retention measured in days"
  default     = "14"
}
variable "drone-io_enabled" {
  type        = bool
  description = "Determines if should use Drone.io"
  default     = false
}

variable "ecr_namespaces" {
  type        = list(string)
  description = "If provided, will create namespaces for ECR"
  default     = []
}

variable "ecr_enabled" {
  type        = bool
  description = "Determine if ECR should be created (codepipeline_enabled=true also will result creating ECR)"
  default     = false
}

variable "ecs_ports" {
  type        = list(string)
  description = "Ports on which SG will operate"
  default     = []
}

variable "launch_type" {
  type        = string
  description = "ECS default cluster laynch type"
  default     = "FARGATE"
}

# ECS EC2 cluster section
variable "instance_type" {
  type        = string
  description = "Instances type for ECS EC2 cluster"
  default     = "t3.medium"
}

variable "launch_configuration_desired_capacity" {
  type        = string
  default     = 3
  description = "Launch configuration desired capacity for ecs ec2 cluster"
}

variable "launch_configuration_desired_capacity" {
  type        = string
  default     = 3
  description = "Launch configuration desired capacity for ecs ec2 cluster"
}

variable "launch_configuration_desired_capacity" {
  type        = string
  default     = 3
  description = "Launch configuration desired capacity for ecs ec2 cluster"
}