module "label" {
  source     = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.16.0"
  namespace  = var.namespace
  name       = var.name
  stage      = var.stage
  delimiter  = var.delimiter
  attributes = var.attributes
  tags       = var.tags
}

# Main cluster's Security Groups
module "security" {
  source = "git@github.com:BerlingskeMedia/bm.terraform-module.security?ref=production"
  //source      = "../bm.terraform-module.security"
  label       = module.label.id
  namespace   = var.namespace
  stage       = var.stage
  tags        = var.tags
  vpc_id      = var.vpc_id
  name        = var.name
  ecs_ports   = var.ecs_ports
  enabled     = var.enabled
  ecs_enabled = true
  alb_enabled = true
}

module "rds" {
  source  = "git@github.com:BerlingskeMedia/bm.terraform-module.rds-cluster?ref=production"
  enabled = var.enabled && var.run_rds

  name              = var.name
  namespace         = var.namespace
  attributes        = compact(concat(var.attributes, ["rds"]))
  rds_port          = var.rds_port
  stage             = var.stage
  subnets           = var.private_subnets
  vpc_id            = var.vpc_id
  tags              = var.tags
  db_engine         = var.rds_db_engine
  db_cluster_family = var.rds_db_cluster_family
  db_cluster_size   = var.rds_instaces_count
  db_instance_type  = var.rds_instance_type
  db_root_user      = var.rds_admin
  dbname            = var.rds_dbname
}

resource "aws_ecs_cluster" "default" {
  name = module.label.id
  tags = module.label.tags
}

module "ecr" {
  source = "git::https://github.com/BerlingskeMedia/bm.terraform-module.ecr"
  //source = "../bm.terraform-module.ecr"
  enabled    = var.enabled && var.ecr_enabled
  name       = var.name
  namespace  = var.namespace
  stage      = var.stage
  attributes = compact(concat(var.attributes, ["ecr"]))
  namespaces = var.ecr_namespaces
}

resource "aws_security_group" "ecs_sg_internal" {
  name        = "${module.label.id}-ecs-internal"
  description = "Security group giving access between ECS instances ${module.label.id} on containers ports"
  vpc_id      = var.vpc_id
  ingress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    self        = true
    description = "All resources using this SG have unlimited access to each other"
  }
  tags = merge(var.tags, { "Name" = "${module.label.id}-ecs-internal" })
}
locals {
  // if RDS enabled - provide credentials
  rds_envs = var.run_rds ? [{
    name  = "MYSQL_DATABASE"
    value = module.rds.db_name
    }, {
    name  = "MYSQL_USER"
    value = module.rds.root_username
    }, {
    name  = "MYSQL_HOST"
    value = join("", module.rds.endpoind_ssm_arn)
    }, {
    name  = "MYSQL_PASSWORD"
    value = join("", module.rds.password_ssm_arn)
  }] : []

}
# Create user

module "drone-io" {
  source     = "git::https://github.com/BerlingskeMedia/bm.terraform-module.drone-io"
  enabled    = var.drone-io_enabled
  name       = var.name
  namespace  = var.namespace
  stage      = var.stage
  attributes = compact(concat(var.attributes, ["drone"]))
}

locals {
  repository_name = length(module.ecr.repository_name) > 0 ? element(module.ecr.repository_name, 0) : ""
  ssm_arns        = concat(module.rds.ssm_arns)
  kms_arns        = concat(module.rds.kms_arns)
}

data "aws_iam_policy_document" "ecs_exec" {
  count = var.enabled ? 1 : 0

  # ECR
  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ssm:GetParameters",
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
  }

  # Service discovery
  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "servicediscovery:Get*",
      "servicediscovery:List*",
      "servicediscovery:DiscoverInstances"
    ]
  }
  # If RDS enabled - access to RDS
  dynamic "statement" {
    for_each = var.run_rds ? ["true"] : []
    content {
      effect    = "Allow"
      resources = module.rds.dbuser_arns

      actions = [
        "rds-db:connect"
      ]
    }
  }
  # If any SSM parameters created in this manifest - allow access to them
  dynamic "statement" {
    for_each = length(local.ssm_arns) > 0 ? ["true"] : []
    content {
      effect    = "Allow"
      resources = local.ssm_arns

      actions = [
        "ssm:GetParameters"
      ]
    }
  }
  # If any KMS created in this manifest - allow access to them
  dynamic "statement" {
    for_each = length(local.kms_arns) > 0 ? ["true"] : []
    content {
      effect    = "Allow"
      resources = local.kms_arns

      actions = [
        "kms:DescribeKey",
        "kms:GenerateDataKey",
        "kms:Decrypt"
      ]
    }
  }
}

resource "aws_cloudwatch_log_group" "app" {
  name              = module.label.id
  tags              = module.label.tags
  retention_in_days = var.log_retention_in_days
}





