# bm.terraform-module.ecs

## Description

Terraform module for creating ECS cluster with common resources used in manifests. We are using this module to:
* Create ECS cluster (EC2 or FARGATE)
* Create internal and external ALBs
* Create wildcard ACM certificate
* (Optional) Create ECR repositories
* (Optional) Create drone.io related resources
* Create Cloudwatch group
* Create common KMS key
* Create IAM access policy for common KMS key
* Prepare output maps for [ecs-service module](https://github.com/BerlingskeMedia/bm.terraform-module.ecs-service)

## Example Usage
```yaml
module "ecs" {
  source          = "git@github.com:BerlingskeMedia/bm.terraform-module.ecs?ref=tags/1.0.0"
  igw_id          = local.igw_id
  name            = local.name
  namespace       = local.namespace
  nat_id          = local.nat_id
  region          = local.region
  stage           = local.stage
  tags            = local.tags
  vpc_id          = local.vpc_id
  private_subnets = local.private_subnets
  public_subnets  = local.public_subnets
  attributes      = local.global_attributes

  enabled         = true
  ecr_enabled     = false

  # New ALB part
  alb_main_domain = local.domain
  alb_internal_enabled = local.alb_internal
  alb_external_enabled = local.alb_external   
}
```
## Variables

### General Variables

| Variable    | Type           | Required | Default Value | Description |
| ----------- |:--------------:|:--------:|:-------------:|:-----------:|
| enabled     | `bool`         | **no**   | `true`        | Enable module flag |
| namespace   | `string`       | **yes**  | `empty`       | Namespace (e.g. `eg` or `cp`) |
| stage       | `string`       | **yes**  | `empty`       | Stage (e.g. `prod`, `testing`, `staging`) |
| name        | `string`       | **yes**  | `empty`       | Name of the application |
| delimeter   | `string`       | **no**   | `-`           | Delimiter between `namespace`, `stage`, `name`, `application` and `attributes` |
| attributes  | `list(string)` | **no**   | `[]`          | Additional attributes (_e.g._ \"1\") |
| tags        | `map(string)`  | **no**   | `{}`          | Additional tags (_e.g._ { BusinessUnit : ABC }) |
| region      | `string`       | **yes**  | `empty`       | AWS Region for project |

### Network Variables

| Variable        | Type           | Required | Default Value  | Description |
| --------------- |:--------------:|:--------:|:--------------:|:-----------:|
| vpc_id          | `string`       | **yes**  | `empty`        | ID of vpc for this infrastructure |
| igw_id          | `string`       | **yes**  | `empty`        | Internet Gateway ID|
| nat_id          | `string`       | **yes**  | `empty`        | NAT Gateway ID |
| public_subnets  | `list(string)` | **yes**  | `[]`           | List of public subnet's ID |
| private_subnets | `list(string)` | **yes**  | `[]`           | List of public subnet's ID |

### ECS settings

#### Common settings variables

| Variable                   | Type           | Required | Default Value  | Description |
| -------------------------- |:--------------:|:--------:|:--------------:|:-----------:|
| log_retention_in_days      | `string`       | **no**   | `14`           | Log retention measured in days |
| drone-io_enabled           | `bool`         | **no**   | `false`        | Determines if should use Drone.io |
| ecr_enabled                | `bool`         | **no**   | `false`        | Determine if ECR should be created (codepipeline_enabled=true also will result creating ECR) |
| ecr_namespaces             | `list(string)` | **no**   | `[]`           | List of public subnet's ID |
| ecr_image_tag_mutability   | `string`       | **no**   | `MUTABLE`      | The tag mutability setting for the repository. Must be one of: MUTABLE or IMMUTABLE |
| ecr_protected_tag_prefixes | `list(string)` | **no**   | `[]`           | If provided, will create Lifecycle rules for specified ecr image tag prefixes |
| ecr_max_image_count        | `number`       | **no**   | `500`          | How many Docker Image versions AWS ECR will store |
| launch_type                | `string`       | **no**   | `FARGATE`      | ECS default cluster laynch type |

#### ECS EC2 cluster variables

| Variable                       | Type                | Required                                 | Default Value                                    | Description |
| ------------------------------ |:-------------------:|:----------------------------------------:|:------------------------------------------------:|:-----------:|
| instance_ami_name_regex        | `string`            | **no**                                   | `amzn2-ami-ecs-hvm-2.0*`                         | Instance ami name regex |
| instance_type                  | `string`            | **no**                                   | `t3a.medium`                                     | Instances type for ECS EC2 cluster |
| aws_key_pair                   | `string`            | **only if `launch_type` is set to`EC2`** | `empty`                                          | AWS instances key pair |
| asg_instances_desired_capacity | `string`            | **no**                                   | `3`                                              | Launch configuration desired capacity for ecs ec2 cluster |
| asg_instances_max_size         | `string`            | **no**                                   | `3`                                              | Launch configuration maximum capacity for ecs ec2 cluster |
| asg_instances_min_size         | `string`            | **no**                                   | `3`                                              | Launch configuration minimum capacity for ecs ec2 cluster |
| asg_max_instance_lifetime      | `string`            | **no**                                   | `604800`                                         | Time of life for instances in Autoscalling group |
| asg_termination_policies       | `list(string)`      | **no**                                   | `["OldestLaunchConfiguration","OldestInstance"]` | Default policies for vm termination in ASG |
| efs_mounts_hosts_entries       | `map(list(string))` | **no**                                   | `{}`                                             | Map of EFS volumes hosts entries. Each entry should contain key-value where key is `mount target dns name` and value is a list of `mount target ip address` |

### ALB variables

| Variable                                                 | Type           | Required | Default Value                       | Description |
| -------------------------------------------------------- |:--------------:|:--------:|:-----------------------------------:|:-----------:|
| alb_main_domain                                          | `string`       | **no**   | `berlingskemedia-testing.net`       | Main domain name for all services and acm certificate |
| alb_https_policy                                         | `string`       | **no**   | `ELBSecurityPolicy-TLS-1-2-2017-01` | Set ALB https listener TLS policy |
| alb_internal_enabled                                     | `bool`         | **no**   | `false`                             | Determine if module will create internal ALB |
| alb_internal_http_enable                                 | `bool`         | **no**   | `false`                             | Determine if you want to enable http listener |
| alb_internal_http_redirect                               | `bool`         | **no**   | `false`                             | Determine if you want to enable http to https redirects |
| alb_internal_https_enable                                | `bool`         | **no**   | `true`                              | Determine if you want to enable https listener |
| alb_internal_http2_enable                                | `bool`         | **no**   | `true`                              | Determine if you want to enable http2 listener |
| alb_internal_default_security_group_enabled              | `bool`         | **no**   | `true`                              | Determine if you want to create default security group - If set to `false` you need to provide list of security group to `alb_internal_additional_security_groups_list` |
| alb_internal_default_security_group_ingress_cidrs_blocks | `list(string)` | **no**   | `["0.0.0.0/0"]`                     | Determine what CIDR blocks will be allowed to access internal ALB |
| alb_internal_additional_security_groups_list             | `list(string)` | **no**   | `[]`                                | List of internal ALB security groups - If empty you need to enable variable `alb_internal_default_security_group_enabled` |
| alb_external_enabled                                     | `bool`         | **no**   | `false`                             | Determine if module will create external ALB |
| alb_external_http_enable                                 | `bool`         | **no**   | `false`                             | Determine if you want to enable http listener |
| alb_external_http_redirect                               | `bool`         | **no**   | `false`                             | Determine if you want to enable http to https redirects |
| alb_external_https_enable                                | `bool`         | **no**   | `true`                              | Determine if you want to enable https listener |
| alb_external_http2_enable                                | `bool`         | **no**   | `true`                              | Determine if you want to enable http2 listener |
| alb_external_default_security_group_enabled              | `bool`         | **no**   | `true`                              | Determine if you want to create default security group - If set to `false` you need to provide list of security group to `alb_external_additional_security_groups_list` |
| alb_external_default_security_group_ingress_cidrs_blocks | `list(string)` | **no**   | `["0.0.0.0/0"]`                     | Determine what CIDR blocks will be allowed to access external ALB |
| alb_external_additional_security_groups_list             | `list(string)` | **no**   | `[]`                                | List of external ALB security groups - If empty you need to enable variable `alb_external_default_security_group_enabled` |

### Service Discovery settings
| Variable                       | Type   | Required | Default Value | Description |
| ------------------------------ |:------:|:--------:|:-------------:|:-----------:|
| service_discovery_enabled      | `bool` | **no**   | `false`       | Determine, wheter servicediscovery should be enabled for this service. |

## Outputs

### ECS cluster outputs

| Variable                        | Description |
| -------------------------------:|:-----------:|
| label_id                        | Whole project id |
| ecs_cluster_arn                 | Project ECS cluster arn |
| service_internal_security_group | Security group used for communication between services |
| iam_policy_document_json        | |
| aws_cloudwatch_log_group_name   | |
| drone_builder_username          | Username of the user used for tasks in drone |
| access_key                      | Access key used for pushing new ECR images |
| secret_key                      | Secret key used for pushing new ECR images |
| ecr_urls                        | Map of created ecr registries urls|
| ecs_ec2_role_arn                | ECS EC2 cluster role arn |
| ecs_ec2_instance_profile_arn    | ECS EC2 cluster instance profile arn |
| ecs_ec2_asg                     | ECS EC2 cluster autoscalling group arn |
| ecs_ec2_launch_configuration    | ECS EC2 cluster launch configuration arn |

### Context output
Refer to https://github.com/BerlingskeMedia/bm.terraform-module.context
Returns two objects: `context` and `normalized_context`.
`context` has raw structure, ready for reuse in dependent modules.
`normalized_context` has defaulted values (depending on types) instead of nulls.
E.g. null strings are empty strings `""`, null booleans have defined true/false state, etc.

Keys' names corresponding to the values of the same name, just passes the values.

| Key                        | Description |
| -------------------------------:|:-----------:|
| enabled | see var.enabled |
| namespace | see var.namespace |
| stage | see var.stage |
| name | see var.name |
| delimiter | see var.delimiter |
| attributes | see var.attributes |
| tags | see var.tags |
| region | see var.region |
| vpc_id | see var.vpc_id |
| launch_type | see var.launch_type |
| ecs_cluster_arn | Project ECS cluster arn |
| aws_logs_region | CloudWatch log group region |
| aws_cloudwatch_log_group_name | CloudWatch log group name |
| deploy_iam_access_key | Access key used for pushing new ECR images |
| deploy_iam_secret_key | Secret key used for pushing new ECR images |
| domain_name | Domain name for all projects in the cluster |
| domain_zone_id | Domain zone id for all projects in the cluster |
| alb_acm_certificate_arn | ACM certificate arn for all services in this cluster |
| kms_key_alias_arn | Common KMS key alias arn for all services in the cluster |
| kms_key_alias_name | Common KMS key alias name for all services in the cluster |
| kms_key_arn | Common KMS key arn for all services in the cluster |
| kms_key_id | Common KMS key ID for all services in the cluster |
| kms_key_access_policy_arn | Common KMS IAM access policy arn |
| service_discovery_namespace_id | Service discovery namespace ID |
| service_discovery_name | Service discovery namespace name |
| service_internal_security_group | Security group used for communication between services |
| private_subnets | see var.private_subnets |
| alb_external_enabled | see var.alb_external_enabled |
| alb_external_listener_arn | External ALB https listener arn |
| alb_external_dns_name | External ALB DNS endpoint |
| alb_external_dns_zone_id | External ALB DNS zone ID for aliases |
| alb_external_allowed_security_group  | External ALB security group ID |
| alb_internal_enabled | see var.alb_internal_enabled |
| alb_internal_listener_arn | Internal ALB https listener arn |
| alb_internal_dns_name | Internal ALB DNS endpoint |
| alb_internal_dns_zone_id | Internal ALB DNS zone ID for aliases |
| alb_internal_allowed_security_group  | Internal ALB security group ID |


### ALB outputs (deprecated on favor of the context)

| Variable                        | Description |
| -------------------------------:|:-----------:|
| domain_name                     | Domain name for all projects in the cluster |
| domain_zone_id                  | Domain zone id for all projects in the cluster |
| alb_acm_certificate_arn         | ACM certificate arn for all services in this cluster |
| alb_internal_security_group_id  | Internal ALB security group ID |
| alb_internal_dns_endpoint       | Internal ALB DNS endpoint |
| alb_internal_https_listener_arn | Internal ALB https listener arn |
| alb_internal_zone_id            | Internal ALB DNS zone ID for aliases |
| alb_external_security_group_id  | External ALB security group ID |
| alb_external_dns_endpoint       | External ALB DNS endpoint |
| alb_external_https_listener_arn | External ALB https listener arn |
| alb_external_zone_id            | External ALB DNS zone ID for aliases |

### KMS outputs

| Variable                  | Description |
| -------------------------:|:-----------:|
| kms_key_alias_arn         | Common KMS key alias arn for all services in the cluster |
| kms_key_alias_name        | Common KMS key alias name for all services in the cluster |
| kms_key_arn               | Common KMS key arn for all services in the cluster |
| kms_key_id                | Common KMS key ID for all services in the cluster |
| kms_key_access_policy_arn | Common KMS IAM access policy arn |

### Service discovery outputs

| Variable                       | Description |
| ------------------------------:|:-----------:|
| service_discovery_namespace_id | Service discovery namespace ID |
| service_discovery_name         | Service discovery namespace name |

### ECS module output maps (deprecated on favor of the context)

| Variable                | Description |
| -----------------------:|:-----------:|
| internal_alb_output_map | Internal ALB Output map with variables `listener_arn`, `dns_name`, `dns_zone_id` and `allowed_security_group_id` inside. Replaces variables with the same names in [bm.terraform-module.ecs-service](https://github.com/BerlingskeMedia/bm.terraform-module.ecs-service) module |
| external_alb_output_map | External ALB Output map with variables `listener_arn`, `dns_name`, `dns_zone_id` and `allowed_security_group_id` inside. Replaces variables with the same names in [bm.terraform-module.ecs-service](https://github.com/BerlingskeMedia/bm.terraform-module.ecs-service) module |
| output_map              | Output map with most of the variables used for [bm.terraform-module.ecs-service](https://github.com/BerlingskeMedia/bm.terraform-module.ecs-service) module |