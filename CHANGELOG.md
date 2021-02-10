---
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
