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

#### Network Variables

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

variable "ecr_enabled" {
  type        = bool
  description = "Determine if ECR should be created (codepipeline_enabled=true also will result creating ECR)"
  default     = true
}

variable "ecr_namespaces" {
  type        = list(string)
  description = "If provided, will create namespaces for ECR"
  default     = []
}

variable "ecr_image_tag_mutability" {
  type        = string
  description = "The tag mutability setting for the repository. Must be one of: MUTABLE or IMMUTABLE"
  default     = "MUTABLE"
}

variable "ecr_protected_tag_prefixes" {
  type        = list(string)
  description = "If provided, will create Lifecycle rules for specified ecr image tag prefixes"
  default     = []
}

variable "ecr_max_image_count" {
  type        = number
  description = "How many Docker Image versions AWS ECR will store"
  default     = 500
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
  type        = list(string)
  default     = ["OldestLaunchConfiguration", "OldestInstance"]
  description = "Default policies for vm termination in ASG"
}

variable "efs_mounts_hosts_entries" {
  type        = map(list(string))
  default     = {}
  description = "Map of EFS volumes hosts entries. Each entry should contain key-value where key is `mount target dns name` and value is a list of `mount target ip address`"
}

# ALB variables

variable "alb_main_domain" {
  type        = string
  description = "Main domain name for all services and acm certificate"
  default     = "berlingskemedia-testing.net"
}

variable "alb_https_policy" {
  type        = string
  default     = "ELBSecurityPolicy-TLS-1-2-2017-01"
  description = "Set ALB https listener TLS policy"
}

variable "alb_internal_enabled" {
  type        = bool
  description = "Determine if module will create internal ALB"
  default     = false
}

variable "alb_internal_http_enable" {
  type        = bool
  default     = false
  description = "Determine if you want to enable http listener"
}

variable "alb_internal_http_redirect" {
  type        = bool
  default     = false
  description = "Determine if you want to enable http to https redirects"
}

variable "alb_internal_https_enable" {
  type        = bool
  default     = true
  description = "Determine if you want to enable https listener"
}

variable "alb_internal_http2_enable" {
  type        = bool
  default     = true
  description = "Determine if you want to enable http2 listener"
}

variable "alb_internal_default_security_group_enabled" {
  type        = bool
  default     = true
  description = "Determine if you want to create default security group - If set to `false` you need to provide list of security group to `alb_internal_additional_security_groups_list`"
}

variable "alb_internal_default_security_group_ingress_cidrs_blocks" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "Determine what CIDR blocks will be allowed to access internal ALB"
}

variable "alb_internal_additional_security_groups_list" {
  type        = list(string)
  default     = []
  description = "List of internal ALB security groups - If empty you need to enable variable `alb_internal_default_security_group_enabled`"
}

variable "alb_external_enabled" {
  type        = bool
  description = "Determine if module will create external ALB"
  default     = false
}

variable "alb_external_http_enable" {
  type        = bool
  default     = false
  description = "Determine if you want to enable http listener"
}

variable "alb_external_http_redirect" {
  type        = bool
  default     = false
  description = "Determine if you want to enable http to https redirects"
}

variable "alb_external_https_enable" {
  type        = bool
  default     = true
  description = "Determine if you want to enable https listener"
}

variable "alb_external_http2_enable" {
  type        = bool
  default     = true
  description = "Determine if you want to enable http2 listener"
}

variable "alb_external_default_security_group_enabled" {
  type        = bool
  default     = true
  description = "Determine if you want to create default security group - If set to `false` you need to provide list of security group to `alb_external_security_groups_list`"
}

variable "alb_external_default_security_group_ingress_cidrs_blocks" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "Determine what CIDR blocks will be allowed to access external ALB"
}

variable "alb_external_additional_security_groups_list" {
  type        = list(string)
  default     = []
  description = "List of external ALB security groups - If empty you need to enable variable `alb_external_default_security_group_enabled`"
}

# Service Discovery variables

variable "service_discovery_enabled" {
  type        = bool
  default     = false
  description = "Determine, wheter servicediscovery should be enabled for this service."
}