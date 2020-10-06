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

variable "public_subnets" {
  type        = list(string)
  default     = []
  description = "List of public subnet's ID"
}

variable "private_subnets" {
  type        = list(string)
  default     = []
  description = "List of private subnet's ID"
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
variable "instance_ami_name_regex" {
  type        = string
  description = "Instance ami name regex"
  default     = "amzn2-ami-ecs-hvm-2.0*"
}

variable "instance_type" {
  type        = string
  description = "Instances type for ECS EC2 cluster"
  default     = "t3a.medium"
}

variable "aws_key_pair" {
  type        = string
  description = "AWS instances key pair"
  default     = ""
}

variable "asg_instances_desired_capacity" {
  type        = string
  default     = 3
  description = "Launch configuration desired capacity for ecs ec2 cluster"
}

variable "asg_instances_max_size" {
  type        = string
  default     = 3
  description = "Launch configuration desired capacity for ecs ec2 cluster"
}

variable "asg_instances_min_size" {
  type        = string
  default     = 3
  description = "Launch configuration desired capacity for ecs ec2 cluster"
}

variable "asg_max_instance_lifetime" {
  type        = string
  default     = 604800 # 1 week in seconds
  description = "Time of life for instances in Autoscalling group"
}

variable "asg_termination_policies" {
  type        = list
  default     = ["OldestLaunchConfiguration","OldestInstance"]
  description = "Default policies for vm termination in ASG"
}

# ALB variables

variable "alb_main_domain" {
  type        = string
  description = "Domain name for all services and acm certificate"
  default     = "berlingskemedia-testing.net"
}

variable "alb_internal_create" {
  type        = bool
  description = "Determine if module will create internal ALB"
  default     = false
}

variable "alb_external_create" {
  type        = bool
  description = "Determine if module will create external ALB"
  default     = false
}