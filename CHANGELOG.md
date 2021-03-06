---
# 1.12.0
## Main Changes
    - Add permissions to fetch any ECR from within a drone build.

# 1.11.2
## Main Changes
    - Add tags where it was possible to add them

# 1.11.1
## Main Changes
    - Add tags to Service discovery resource

# 1.11.0
## Main Changes
    - Fix tags management in few resources

# 1.10.0
## Main Changes
    - Output builder username to have it when we need to apply policy outside of the module to it (ex. with `aws_iam_user_policy_attachment`).

# 1.9.0
## Main Changes
    - upgrade module cloudposse/terraform-aws-alb to 0.33.1
    - upgrade module cloudposse/terraform-aws-kms-key to 0.10.0
    - upgrade module BerlingskeMedia/bm.terraform-module.context to v1.1.0
    - providers no longer stick to fixed major version
    - added required provider hashicorp/aws in v3.38

# 1.8.0
## Main Changes
    - Add possibility to mount EFS volumes from different VPC if cluster is in EC2 mode (Fargate not avaliable)
    - Add possibility to connect with Session manager to ECS instances

# 1.7.0
## Main Changes
    - support for drone-io module 0.5.0, which fixes drone policies security concerns

# 1.6.0
## Main Changes
    - Revoke all unnecessary IAM permissions from EC2 instances - it was massive security issue

# 1.5.0
## Main Changes
    - Remove datadog agent settings from ecs
    - Upgrade all submodules
    - Change AWS provider version to 3.0 by default
    - Remove setting for pushing logs from cloudwatch into elasticsearch
    - Replace resources based certificate request to cloudposse module

## Warning
<b>Please update to `1.4.2` before running this update</b>
1. <b><u>(Only when updating existing projects)</u></b> This change require removing acm
certificate states and importing to new module. You can do this with below commands
    ```bash
    # ACM certificate import
    terraform state rm 'module.ecs.aws_acm_certificate.alb_cert[0]'
    terraform import 'module.ecs.module.acm_certificate.aws_acm_certificate.default[0]' EXISTING_CERTIFICATE_ARN
    ```
    Also remember that DNS validation records and validation resource will be recreated on terraform run. This is normal and will not break anything if certificate was imported into new state.
2. <b>Cloudposse ACM</b> will create duplicate DNS records, but because of the `overwrite` option set to `true` everything is fine. <u>There is no need to import existing DNS record</u>
3. <b>Cloudposse ACM</b> certificate module will add tags to certificate
4. <b>Cloudposse ECR</b> module is setting by default `scan_on_push` variable to `true`

# 1.4.2
## Main Changes
    - Add option for lifecycle rules for ECR repositories
    - Move away from our ECR module fork to cloudposse mainstream

## Warning
<b><u>(Only when updating existing projects)</u></b> This change require removing ecr states and importing to new module. You can do this with below commands
```bash
# ECR repository Lifecycle policy
terraform state rm 'module.ecs.module.ecr.aws_ecr_lifecycle_policy.default[REPOSITORY_ID]'
terraform import 'module.ecs.module.ecr.aws_ecr_lifecycle_policy.name["REPOSITORY_NAME"]' REPOSITORY_NAME

# ECR repository
terraform state rm 'module.ecs.module.ecr.aws_ecr_repository.default[REPOSITORY_ID]'
terraform import 'module.ecs.module.ecr.aws_ecr_repository.name["REPOSITORY_NAME"]' REPOSITORY_NAME
```
Where:
- <b>REPOSITORY_NAME</b> - full name of existing repository name
- <b>REPOSITORY_ID</b> - terraform repository id

Run `terraform plan` to get both variables from changes output. After successfull importing existing resources there will be only change for tags, but resources will be intact.

# 1.4.1
## Main Changes
    - Add option for enabling/disabling default ALB security group - default set to true because of backward compatibility
    - Add option for managing default ALB security group allowed CIDR blocks - default set to allow CIDR ["0.0.0.0/0"] because of backward compatibility
    - Add option for adding additional ALB security groups - they are not passed in context module

# 1.4.0
## Main Changes
    - Support for bm.terraform-module.context - now parameters are being handed over by context module. We still have backward compatibility for old ecs-service modules

# 1.3.2
## Main Changes
    - Output label id in both outputs and output map
    - Update ALB module and add enabled flag to internal and external alb

# 1.3.1
## Main Changes
    - Add Datadog agent to each EC2 ECS cluster with right permissions

# 1.3.0
## Main Changes
    - Terraform v0.13.x support (Terraform 0.12 not supported anymore)

# 1.2.1
## Main changes
    - Change variables names from`cwl2es_lambda_*` to `cwl2es_*`
    - Fix defaults for `cwl2es_*` variables
    - Add `cwl2es_subnets` variables if Lambda VPC is different than the project VPC
    - Move Cloudwatch to lambda subscription from ecs-service module to ecs module
    - Fix kms_key_id variable name

# 1.2.0
## Main changes
    - Add Cloudwatch to Elasticsearch Lambda support

# 1.1.0
## Main changes
    - Add service discovery support

# 1.0.0
## Main changes
    - Add external and internal ALB by default
    - Add wildcard certificate for every project

# 0.1.7
## Main changes
    - Remove all code related to rds - use separated module if you need database

# 0.1.6
## Main changes
    - Add option for creating ECS EC2 clusters

# 0.1.5
## Main changes
    - rds module in v0.1.2 (kms bugfix)

# 0.1.4
## Main changes
    - use bm.terraform-module.rds-cluster version 0.1.1
    - added output rds_kms_arn
    - added output rds_kms_key_id

# 0.1.3
## Main changes
    - Outputs ECR URLs

# 0.1.2
## Main changes
    - drone-io module in v0.1.1
    - Added versions.tf
    - Added dependencies to data.aws_ssm_parameter

# 0.1.1
## Main changes
    - return drone's IAM user keys

# 0.0.0

## Main changes
* Start
