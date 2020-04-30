locals {
  availability_zones = length(var.availability_zones) > 0 ? var.availability_zones : ["${var.region}a", "${var.region}b"]
  github_token       = var.ssm_github_oauth_token != "" ? data.aws_ssm_parameter.github_oauth_token[0].value : ""
}


# TODO: Ensure VPC has  [DNS hostnames  = Enabled]

module "label" {
  source     = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.16.0"
  namespace  = var.namespace
  name       = var.name
  stage      = var.stage
  delimiter  = var.delimiter
  attributes = var.attributes
  tags       = var.tags
}

# Networking stuff, will be replaced with cloudposse VPC creation
module "network" {
  source = "git@github.com:BerlingskeMedia/bm.terraform-module.network?ref=mx_tools"
  //source = "../bm.terraform-module.network"
  namespace          = var.namespace
  stage              = var.stage
  name               = var.name
  tags               = var.tags
  region             = var.region
  availability_zones = local.availability_zones
  igw_id             = var.igw_id
  nat_id             = var.nat_id
  vpc_id             = var.vpc_id
  app_cidr           = var.application_cidr
}

# Main cluster's Security Groups
module "security" {
  source = "git@github.com:BerlingskeMedia/bm.terraform-module.security?ref=mx_tools"
  //source    = "../bm.terraform-module.security"
  label     = module.label.id
  namespace = var.namespace
  stage     = var.stage
  tags      = var.tags
  vpc_id    = module.network.vpc_id
  name      = var.name
  ecs_ports = var.ecs_ports
}

module "alb" {
  source                                  = "git::https://github.com/cloudposse/terraform-aws-alb.git?ref=tags/0.7.0"
  namespace                               = var.namespace
  stage                                   = var.stage
  name                                    = var.name
  attributes                              = var.attributes
  delimiter                               = var.delimiter
  vpc_id                                  = module.network.vpc_id
  security_group_ids                      = [module.security.alb_sg_id]
  subnet_ids                              = module.network.public_subnets
  internal                                = false
  http_enabled                            = true
  access_logs_enabled                     = false
  alb_access_logs_s3_bucket_force_destroy = true
  access_logs_region                      = var.region
  cross_zone_load_balancing_enabled       = true
  http2_enabled                           = true
  deletion_protection_enabled             = false
  tags                                    = var.tags
  health_check_path                       = var.alb_ingress_healthcheck_path
}



module "rds" {
  source = "git@github.com:BerlingskeMedia/bm.terraform-module.rds-cluster?ref=mx_tools"
  //source  = "../bm.terraform-module.rds-cluster"
  enabled = var.enabled && var.run_rds

  //master_password = module.rds_secret.value
  name       = var.name
  namespace  = var.namespace
  attributes = compact(concat(var.attributes, ["rds"]))
  rds_port   = var.rds_port
  //security_groups = [module.security.rds_sg_id]
  stage             = var.stage
  subnets           = module.network.private_subnets
  vpc_id            = module.network.vpc_id
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

data "aws_ssm_parameter" "github_oauth_token" {
  count = var.ssm_github_oauth_token != "" ? 1 : 0
  name  = var.ssm_github_oauth_token
}


############## default webapp

module "ecr" {
  //source     = "git::https://github.com/BerlingskeMedia/bm.terraform-module.ecr/git/commits/3e03498ecff1a87407dffa5c59db9852a1ac3cdd"
  source = "git::https://github.com/BerlingskeMedia/bm.terraform-module.ecr"
  //source = "../bm.terraform-module.ecr"
  enabled    = var.enabled && var.ecr_enabled
  name       = var.name
  namespace  = var.namespace
  stage      = var.stage
  attributes = compact(concat(var.attributes, ["ecr"]))
  namespaces = var.ecr_namespaces
}


resource "aws_cloudwatch_log_group" "app" {
  name              = module.label.id
  tags              = module.label.tags
  retention_in_days = var.log_retention_in_days
}

# duplicates module.alb but leave for now, because module.cloudwatch uses this part
# TODO: for further investigation to find out if needed
/*module "alb_ingress" {
  source                       = "git::https://github.com/cloudposse/terraform-aws-alb-ingress.git?ref=tags/0.9.0"
  name                         = var.name
  namespace                    = var.namespace
  stage                        = var.stage
  attributes                   = var.attributes
  vpc_id                       = var.vpc_id
  port                         = var.container_port
  health_check_path            = var.alb_ingress_healthcheck_path
  //default_target_group_enabled = true
  default_target_group_enabled = var.enabled

  authenticated_paths   = var.alb_ingress_authenticated_paths
  unauthenticated_paths = var.alb_ingress_unauthenticated_paths
  authenticated_hosts   = var.alb_ingress_authenticated_hosts
  unauthenticated_hosts = var.alb_ingress_unauthenticated_hosts

  authenticated_priority   = var.alb_ingress_listener_authenticated_priority
  unauthenticated_priority = var.alb_ingress_listener_unauthenticated_priority

  unauthenticated_listener_arns       = module.alb.listener_arns
  unauthenticated_listener_arns_count = 1
  authenticated_listener_arns         = var.alb_ingress_authenticated_listener_arns
  authenticated_listener_arns_count   = var.alb_ingress_authenticated_listener_arns_count

  authentication_type                        = var.authentication_type
  authentication_cognito_user_pool_arn       = var.authentication_cognito_user_pool_arn
  authentication_cognito_user_pool_client_id = var.authentication_cognito_user_pool_client_id
  authentication_cognito_user_pool_domain    = var.authentication_cognito_user_pool_domain
  authentication_oidc_client_id              = var.authentication_oidc_client_id
  authentication_oidc_client_secret          = var.authentication_oidc_client_secret
  authentication_oidc_issuer                 = var.authentication_oidc_issuer
  authentication_oidc_authorization_endpoint = var.authentication_oidc_authorization_endpoint
  authentication_oidc_token_endpoint         = var.authentication_oidc_token_endpoint
  authentication_oidc_user_info_endpoint     = var.authentication_oidc_user_info_endpoint
}*/

// TODO: change tagging from latest to other
locals {
  // hard tag latest on every image
  container_image = var.ecr_enabled ? length(module.ecr.registry_url) > 0 ? element(formatlist("%s:latest", module.ecr.registry_url), 0) : "" : var.container_image

  port_mappings = var.container_port_mappings == null ? [
    {
      containerPort = var.container_port
      hostPort      = var.container_port
      protocol      = "tcp"
    }
  ] : var.container_port_mappings
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

# Used only on one-container deployments
# TODO: compare this definition with master branch, most likely master version is better
module "container_definition" {
  //source                       = "git::https://github.com/cloudposse/terraform-aws-ecs-container-definition.git?ref=tags/0.22.0"
  //source                       = "git::https://github.com/cloudposse/terraform-aws-ecs-container-definition.git"
  //source = "../bm.terraform-module.container_definition"
  source         = "git@github.com:BerlingskeMedia/bm.terraform-module.container_definition?ref=mx_tools"
  containers_map = module.ecr.name_to_url
  container_name = module.label.id
  //container_image              = local.container_images
  container_image              = ""
  container_memory             = var.container_memory
  container_memory_reservation = var.container_memory_reservation
  container_cpu                = var.container_cpu
  healthcheck                  = var.healthcheck
  environment                  = concat(var.environment, local.rds_envs)
  //port_mappings                = var.container_port_mappings
  secrets              = var.secrets
  ulimits              = var.ulimits
  entrypoint           = var.entrypoint
  command              = var.command
  mount_points         = var.mount_points
  container_depends_on = local.container_depends_on
  port_mappings        = local.port_mappings

  log_configuration = {
    logDriver = var.log_driver
    options = {
      "awslogs-region"        = var.aws_logs_region
      "awslogs-group"         = aws_cloudwatch_log_group.app.name
      "awslogs-stream-prefix" = var.name
    }
    secretOptions = null
  }
}


locals {
  init_container_definitions = [
    for init_container in var.init_containers : lookup(init_container, "container_definition")
  ]

  container_depends_on = [
    for init_container in var.init_containers :
    {
      containerName = lookup(jsondecode(init_container.container_definition), "name"),
      condition     = init_container.condition
    }
  ]
  # Tuple incompability
  //primary_container_definition = var.disable_primary_container_definition ? var.custom_container_definition_1 : module.container_definition.json_map
  //secondary_container_definition = var.disable_secondary_container_definition ? var.custom_container_definition_2 : []


  alb1 = {
    container_name = module.secondary_container_definition.container_name
    container_port = "8080"
    elb_name       = null
    //target_group_arn = module.alb_ingress.target_group_arn
    target_group_arn = module.alb.default_target_group_arn
  }
}

# gives ability to override every container_definition attribute
module "primary_container_definition" {
  source = "git@github.com:BerlingskeMedia/bm.terraform-module.container_definition_override.git?ref=mx_tools"
  //source = "../bm.terraform-module.container_definition_override"
  container_definition = var.disable_primary_container_definition ? var.custom_container_definition_1 : []
  environment          = concat(var.environment, local.rds_envs)
}

module "secondary_container_definition" {
  source = "git@github.com:BerlingskeMedia/bm.terraform-module.container_definition_override.git?ref=mx_tools"
  container_definition = var.disable_secondary_container_definition ? var.custom_container_definition_2 : []
  environment          = var.environment
}


##########################################################################
######### terraform-aws-ecs-alb-service-task START #######################
##########################################################################

// TODO: export this section to separate module, remove module/resources repetition

module "default_label" {
  source     = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.15.0"
  enabled    = var.enabled
  attributes = var.attributes
  delimiter  = var.delimiter
  name       = var.name
  namespace  = var.namespace
  stage      = var.stage
  tags       = var.tags
}

module "task_label" {
  source     = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.15.0"
  enabled    = var.enabled
  context    = module.default_label.context
  attributes = compact(concat(var.attributes, ["task"]))
}

module "service_label" {
  source     = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.15.0"
  enabled    = var.enabled
  context    = module.default_label.context
  attributes = compact(concat(var.attributes, ["service"]))
}

module "exec_label" {
  source     = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.15.0"
  enabled    = var.enabled
  context    = module.default_label.context
  attributes = compact(concat(var.attributes, ["exec"]))
}



# IAM

locals {
  ssm_arns = concat(module.rds.ssm_arns)
  kms_arns = concat(module.rds.kms_arns)
}

data "aws_iam_policy_document" "ecs_task" {
  count = var.enabled ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_task" {
  count              = var.enabled ? 1 : 0
  name               = "${module.task_label.id}-1"
  assume_role_policy = join("", data.aws_iam_policy_document.ecs_task.*.json)
  tags               = module.task_label.tags
}

data "aws_iam_policy_document" "ecs_service" {
  count = var.enabled ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_service" {
  count              = var.enabled ? 1 : 0
  name               = "${module.service_label.id}-1"
  assume_role_policy = join("", data.aws_iam_policy_document.ecs_service.*.json)
  tags               = module.service_label.tags
}

data "aws_iam_policy_document" "ecs_service_policy" {
  count = var.enabled ? 1 : 0

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "elasticloadbalancing:Describe*",
      "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
      "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
      "ec2:Describe*",
      "ec2:AuthorizeSecurityGroupIngress"
    ]
  }
}

resource "aws_iam_role_policy" "ecs_service" {
  count  = var.enabled ? 1 : 0
  name   = module.service_label.id
  policy = join("", data.aws_iam_policy_document.ecs_service_policy.*.json)
  role   = join("", aws_iam_role.ecs_service.*.id)
}

# IAM role that the Amazon ECS container agent and the Docker daemon can assume
data "aws_iam_policy_document" "ecs_task_exec" {
  count = var.enabled ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_exec" {
  count              = var.enabled ? 1 : 0
  name               = "${module.exec_label.id}-1"
  assume_role_policy = join("", data.aws_iam_policy_document.ecs_task_exec.*.json)
  tags               = module.exec_label.tags
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

resource "aws_iam_role_policy" "ecs_exec" {
  count  = var.enabled ? 1 : 0
  name   = module.exec_label.id
  policy = join("", data.aws_iam_policy_document.ecs_exec.*.json)
  role   = join("", aws_iam_role.ecs_exec.*.id)
}

# TODO: rename this resource, mxtools -> app
resource "aws_ecs_task_definition" "mxtools" {
  count                    = var.enabled ? 1 : 0
  family                   = "${module.default_label.id}-mxtools"
  container_definitions    = "[${join(",", concat(local.init_container_definitions, var.disable_primary_container_definition ? module.primary_container_definition.json_map : module.container_definition.json_map))}]"
  requires_compatibilities = [var.launch_type]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = join("", aws_iam_role.ecs_exec.*.arn)
  task_role_arn            = join("", aws_iam_role.ecs_task.*.arn)
  tags                     = module.default_label.tags

  # disabled for now
  dynamic "proxy_configuration" {
    for_each = [] //var.proxy_configuration == null ? [] : [var.proxy_configuration]
    content {
      type           = lookup(proxy_configuration.value, "type", "APPMESH")
      container_name = proxy_configuration.value.container_name
      properties     = proxy_configuration.value.properties
    }
  }

  # disabled for now
  dynamic "placement_constraints" {
    for_each = [] //var.task_placement_constraints
    content {
      type       = placement_constraints.value.type
      expression = lookup(placement_constraints.value, "expression", null)
    }
  }

  dynamic "volume" {
    for_each = var.volumes
    content {
      host_path = lookup(volume.value, "host_path", null)
      name      = volume.value.name

      dynamic "docker_volume_configuration" {
        for_each = lookup(volume.value, "docker_volume_configuration", [])
        content {
          autoprovision = lookup(docker_volume_configuration.value, "autoprovision", null)
          driver        = lookup(docker_volume_configuration.value, "driver", null)
          driver_opts   = lookup(docker_volume_configuration.value, "driver_opts", null)
          labels        = lookup(docker_volume_configuration.value, "labels", null)
          scope         = lookup(docker_volume_configuration.value, "scope", null)
        }
      }
    }
  }
}



# This section should be initiated after app service creation - this way we'll ensure service discovery fqdn is resolvable

# TODO: add env vars with:
#    + resolver (VPC network addr + 2)
#    + app's service discovery fqdn
# TODO: provide logic to ignore this resource in one-container deployments
resource "aws_ecs_task_definition" "nginx" {
  count                    = var.enabled ? 1 : 0
  family                   = "${module.default_label.id}-nginx"
  container_definitions    = "[${join(",", concat(local.init_container_definitions, var.disable_secondary_container_definition ? module.secondary_container_definition.json_map : module.container_definition.json_map))}]"
  requires_compatibilities = [var.launch_type]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = join("", aws_iam_role.ecs_exec.*.arn)
  task_role_arn            = join("", aws_iam_role.ecs_task.*.arn)
  tags                     = module.default_label.tags

  # disabled for now
  dynamic "proxy_configuration" {
    for_each = [] //var.proxy_configuration == null ? [] : [var.proxy_configuration]
    content {
      type           = lookup(proxy_configuration.value, "type", "APPMESH")
      container_name = proxy_configuration.value.container_name
      properties     = proxy_configuration.value.properties
    }
  }

  # disabled for now
  dynamic "placement_constraints" {
    for_each = [] //var.task_placement_constraints
    content {
      type       = placement_constraints.value.type
      expression = lookup(placement_constraints.value, "expression", null)
    }
  }

  dynamic "volume" {
    for_each = var.volumes
    content {
      host_path = lookup(volume.value, "host_path", null)
      name      = volume.value.name

      dynamic "docker_volume_configuration" {
        for_each = lookup(volume.value, "docker_volume_configuration", [])
        content {
          autoprovision = lookup(docker_volume_configuration.value, "autoprovision", null)
          driver        = lookup(docker_volume_configuration.value, "driver", null)
          driver_opts   = lookup(docker_volume_configuration.value, "driver_opts", null)
          labels        = lookup(docker_volume_configuration.value, "labels", null)
          scope         = lookup(docker_volume_configuration.value, "scope", null)
        }
      }
    }
  }
}



####################

# Service
## Security Groups
resource "aws_security_group" "ecs_service" {
  count       = var.enabled ? 1 : 0
  vpc_id      = var.vpc_id
  name        = "${module.service_label.id}-1"
  description = "Allow ALL egress from ECS service"
  tags        = module.service_label.tags
}

resource "aws_security_group_rule" "allow_all_egress" {
  count             = var.enabled ? 1 : 0
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = join("", aws_security_group.ecs_service.*.id)
}

resource "aws_security_group_rule" "allow_icmp_ingress" {
  count             = var.enabled ? 1 : 0
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "icmp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = join("", aws_security_group.ecs_service.*.id)
}

resource "aws_security_group_rule" "alb" {
  count                    = var.enabled /*&& var.use_alb_security_group*/ ? 1 : 0
  type                     = "ingress"
  from_port                = var.container_port
  to_port                  = var.container_port
  protocol                 = "tcp"
  source_security_group_id = module.security.alb_sg_id // var.alb_security_group
  security_group_id        = join("", aws_security_group.ecs_service.*.id)
}

# TODO: modify count definition to gain flexibility
# TODO: parametrize
resource "aws_ecs_service" "ignore_changes_task_definition_app" {
  count                              = 1 //var.enabled && var.ignore_changes_task_definition ? 1 : 0
  name                               = "${module.default_label.id}-app"
  task_definition                    = "${join("", aws_ecs_task_definition.mxtools.*.family)}:${join("", aws_ecs_task_definition.mxtools.*.revision)}"
  desired_count                      = var.desired_count
  deployment_maximum_percent         = 200 //var.deployment_maximum_percent
  deployment_minimum_healthy_percent = 50  //var.deployment_minimum_healthy_percent
  health_check_grace_period_seconds  = var.health_check_grace_period_seconds
  launch_type                        = var.launch_type //length(var.capacity_provider_strategies) > 0 ? null : var.launch_type
  platform_version                   = "LATEST"        // var.launch_type == "FARGATE" ? var.platform_version : null
  scheduling_strategy                = "REPLICA"       //var.launch_type == "FARGATE" ? "REPLICA" : var.scheduling_strategy
  enable_ecs_managed_tags            = false           //var.enable_ecs_managed_tags

  # disabled for now
  dynamic "capacity_provider_strategy" {
    for_each = [] //var.capacity_provider_strategies
    content {
      capacity_provider = capacity_provider_strategy.value.capacity_provider
      weight            = capacity_provider_strategy.value.weight
      base              = lookup(capacity_provider_strategy.value, "base", null)
    }
  }

  service_registries {
    registry_arn = aws_service_discovery_service.mxtools.arn
  }

  # disabled for now
  dynamic "ordered_placement_strategy" {
    for_each = [] //var.ordered_placement_strategy
    content {
      type  = ordered_placement_strategy.value.type
      field = lookup(ordered_placement_strategy.value, "field", null)
    }
  }

  # disabled for now
  dynamic "placement_constraints" {
    for_each = [] //var.service_placement_constraints
    content {
      type       = placement_constraints.value.type
      expression = lookup(placement_constraints.value, "expression", null)
    }
  }

  # TODO: no LB in app, however we need to add this section for single-container deployments
  /*dynamic "load_balancer" {
    for_each = [local.alb2]
    content {
      container_name   = load_balancer.value.container_name
      container_port   = load_balancer.value.container_port
      elb_name         = lookup(load_balancer.value, "elb_name", null)
      target_group_arn = lookup(load_balancer.value, "target_group_arn", null)
    }
  }*/

  cluster        = aws_ecs_cluster.default.arn
  propagate_tags = null //var.propagate_tags
  tags           = module.default_label.tags

  # TODO: parametrize
  deployment_controller {
    type = "ECS" //var.deployment_controller_type
  }

  # https://www.terraform.io/docs/providers/aws/r/ecs_service.html#network_configuration
  # TODO: make conditional back again
  dynamic "network_configuration" {
    for_each = ["true"] //var.network_mode == "awsvpc" ? ["true"] : []
    content {
      security_groups  = compact(concat(var.ecs_security_group_ids, aws_security_group.ecs_service.*.id, [aws_security_group.ecs_sg_internal.id, aws_security_group.ecs_sg_mxtools.id])) //compact(concat(var.security_group_ids, aws_security_group.ecs_service.*.id))
      subnets          = module.network.private_subnets                                                                                                                                  //var.subnet_ids
      assign_public_ip = false                                                                                                                                                           //var.assign_public_ip
    }
  }

  lifecycle {
    ignore_changes = [task_definition]
  }
}


# TODO: provide logic to ignore this resource in one-container deployments
resource "aws_ecs_service" "ignore_changes_task_definition_nginx" {
  count                              = 1 //var.enabled && var.ignore_changes_task_definition ? 1 : 0
  name                               = "${module.default_label.id}-nginx"
  task_definition                    = "${join("", aws_ecs_task_definition.nginx.*.family)}:${join("", aws_ecs_task_definition.nginx.*.revision)}"
  desired_count                      = var.desired_count
  deployment_maximum_percent         = 200 //var.deployment_maximum_percent
  deployment_minimum_healthy_percent = 50  //var.deployment_minimum_healthy_percent
  health_check_grace_period_seconds  = var.health_check_grace_period_seconds
  launch_type                        = var.launch_type //length(var.capacity_provider_strategies) > 0 ? null : var.launch_type
  platform_version                   = "LATEST"        // var.launch_type == "FARGATE" ? var.platform_version : null
  scheduling_strategy                = "REPLICA"       //var.launch_type == "FARGATE" ? "REPLICA" : var.scheduling_strategy
  enable_ecs_managed_tags            = false           //var.enable_ecs_managed_tags

  dynamic "capacity_provider_strategy" {
    for_each = [] //var.capacity_provider_strategies
    content {
      capacity_provider = capacity_provider_strategy.value.capacity_provider
      weight            = capacity_provider_strategy.value.weight
      base              = lookup(capacity_provider_strategy.value, "base", null)
    }
  }

  # TODO: provide logic to make conditional service discovery
  /*service_registries {
    registry_arn = aws_service_discovery_service.nginx.arn
    //port = 80
  }*/

  # disabled for now
  dynamic "ordered_placement_strategy" {
    for_each = [] //var.ordered_placement_strategy
    content {
      type  = ordered_placement_strategy.value.type
      field = lookup(ordered_placement_strategy.value, "field", null)
    }
  }

  # disabled for now
  dynamic "placement_constraints" {
    for_each = [] //var.service_placement_constraints
    content {
      type       = placement_constraints.value.type
      expression = lookup(placement_constraints.value, "expression", null)
    }
  }

  # TODO: provide logic to make this LB definition conditional
  dynamic "load_balancer" {
    for_each = [local.alb1]
    content {
      container_name   = load_balancer.value.container_name
      container_port   = load_balancer.value.container_port
      elb_name         = lookup(load_balancer.value, "elb_name", null)
      target_group_arn = lookup(load_balancer.value, "target_group_arn", null)
    }
  }

  cluster        = aws_ecs_cluster.default.arn
  propagate_tags = null //var.propagate_tags
  tags           = module.default_label.tags

  # TODO: parametrize
  deployment_controller {
    type = "ECS" //var.deployment_controller_type
  }

  # https://www.terraform.io/docs/providers/aws/r/ecs_service.html#network_configuration
  # TODO: make conditional back again
  dynamic "network_configuration" {
    for_each = ["true"] //var.network_mode == "awsvpc" ? ["true"] : []
    content {
      security_groups  = compact(concat(var.ecs_security_group_ids, aws_security_group.ecs_service.*.id, [aws_security_group.ecs_sg_internal.id, aws_security_group.ecs_sg_nginx.id])) //compact(concat(var.security_group_ids, aws_security_group.ecs_service.*.id))
      subnets          = module.network.private_subnets                                                                                                                                //var.subnet_ids
      assign_public_ip = false                                                                                                                                                         //var.assign_public_ip
    }
  }

  lifecycle {
    ignore_changes = [task_definition]
  }
}





####################################################################
######### terraform-aws-ecs-alb-service-task STOP ##################
####################################################################






# TODO: Multi codepipeline
locals {
  repository_name = length(module.ecr.repository_name) > 0 ? element(module.ecr.repository_name, 0) : ""
}

module "ecs_cloudwatch_autoscaling" {
  enabled               = var.autoscaling_enabled
  source                = "git::https://github.com/cloudposse/terraform-aws-ecs-cloudwatch-autoscaling.git?ref=tags/0.2.0"
  name                  = var.name
  namespace             = var.namespace
  stage                 = var.stage
  attributes            = var.attributes
  service_name          = join("", aws_security_group.ecs_service.*.id)
  cluster_name          = aws_ecs_cluster.default.name
  min_capacity          = var.autoscaling_min_capacity
  max_capacity          = var.autoscaling_max_capacity
  scale_down_adjustment = var.autoscaling_scale_down_adjustment
  scale_down_cooldown   = var.autoscaling_scale_down_cooldown
  scale_up_adjustment   = var.autoscaling_scale_up_adjustment
  scale_up_cooldown     = var.autoscaling_scale_up_cooldown
}
# TODO: make conditional for one-container deployments
module "ecs_cloudwatch_autoscaling_2" {
  enabled               = var.autoscaling_enabled
  source                = "git::https://github.com/cloudposse/terraform-aws-ecs-cloudwatch-autoscaling.git?ref=tags/0.2.0"
  name                  = var.name
  namespace             = var.namespace
  stage                 = var.stage
  attributes            = var.attributes
  service_name          = join("", aws_security_group.ecs_service.*.id)
  cluster_name          = aws_ecs_cluster.default.name
  min_capacity          = var.autoscaling_min_capacity
  max_capacity          = var.autoscaling_max_capacity
  scale_down_adjustment = var.autoscaling_scale_down_adjustment
  scale_down_cooldown   = var.autoscaling_scale_down_cooldown
  scale_up_adjustment   = var.autoscaling_scale_up_adjustment
  scale_up_cooldown     = var.autoscaling_scale_up_cooldown
}

# TODO: make conditional for one-container deployments
locals {
  cpu_utilization_high_alarm_actions      = var.autoscaling_enabled && var.autoscaling_dimension == "cpu" ? module.ecs_cloudwatch_autoscaling.scale_up_policy_arn : ""
  cpu_utilization_low_alarm_actions       = var.autoscaling_enabled && var.autoscaling_dimension == "cpu" ? module.ecs_cloudwatch_autoscaling.scale_down_policy_arn : ""
  memory_utilization_high_alarm_actions   = var.autoscaling_enabled && var.autoscaling_dimension == "memory" ? module.ecs_cloudwatch_autoscaling.scale_up_policy_arn : ""
  memory_utilization_low_alarm_actions    = var.autoscaling_enabled && var.autoscaling_dimension == "memory" ? module.ecs_cloudwatch_autoscaling.scale_down_policy_arn : ""
  cpu_utilization_high_alarm_actions_2    = var.autoscaling_enabled && var.autoscaling_dimension == "cpu" ? module.ecs_cloudwatch_autoscaling_2.scale_up_policy_arn : ""
  cpu_utilization_low_alarm_actions_2     = var.autoscaling_enabled && var.autoscaling_dimension == "cpu" ? module.ecs_cloudwatch_autoscaling_2.scale_down_policy_arn : ""
  memory_utilization_high_alarm_actions_2 = var.autoscaling_enabled && var.autoscaling_dimension == "memory" ? module.ecs_cloudwatch_autoscaling_2.scale_up_policy_arn : ""
  memory_utilization_low_alarm_actions_2  = var.autoscaling_enabled && var.autoscaling_dimension == "memory" ? module.ecs_cloudwatch_autoscaling_2.scale_down_policy_arn : ""

}

module "ecs_cloudwatch_sns_alarms" {
  source  = "git::https://github.com/cloudposse/terraform-aws-ecs-cloudwatch-sns-alarms.git?ref=tags/0.5.0"
  enabled = var.ecs_alarms_enabled

  name       = var.name
  namespace  = var.namespace
  stage      = var.stage
  attributes = var.attributes
  tags       = var.tags

  cluster_name = aws_ecs_cluster.default.name
  service_name = join("", aws_security_group.ecs_service.*.id)

  cpu_utilization_high_threshold          = var.ecs_alarms_cpu_utilization_high_threshold
  cpu_utilization_high_evaluation_periods = var.ecs_alarms_cpu_utilization_high_evaluation_periods
  cpu_utilization_high_period             = var.ecs_alarms_cpu_utilization_high_period

  cpu_utilization_high_alarm_actions = compact(
    concat(
      var.ecs_alarms_cpu_utilization_high_alarm_actions,
      [local.cpu_utilization_high_alarm_actions],
    )
  )

  cpu_utilization_high_ok_actions = var.ecs_alarms_cpu_utilization_high_ok_actions

  cpu_utilization_low_threshold          = var.ecs_alarms_cpu_utilization_low_threshold
  cpu_utilization_low_evaluation_periods = var.ecs_alarms_cpu_utilization_low_evaluation_periods
  cpu_utilization_low_period             = var.ecs_alarms_cpu_utilization_low_period

  cpu_utilization_low_alarm_actions = compact(
    concat(
      var.ecs_alarms_cpu_utilization_low_alarm_actions,
      [local.cpu_utilization_low_alarm_actions],
    )
  )

  cpu_utilization_low_ok_actions = var.ecs_alarms_cpu_utilization_low_ok_actions

  memory_utilization_high_threshold          = var.ecs_alarms_memory_utilization_high_threshold
  memory_utilization_high_evaluation_periods = var.ecs_alarms_memory_utilization_high_evaluation_periods
  memory_utilization_high_period             = var.ecs_alarms_memory_utilization_high_period

  memory_utilization_high_alarm_actions = compact(
    concat(
      var.ecs_alarms_memory_utilization_high_alarm_actions,
      [local.memory_utilization_high_alarm_actions],
    )
  )

  memory_utilization_high_ok_actions = var.ecs_alarms_memory_utilization_high_ok_actions

  memory_utilization_low_threshold          = var.ecs_alarms_memory_utilization_low_threshold
  memory_utilization_low_evaluation_periods = var.ecs_alarms_memory_utilization_low_evaluation_periods
  memory_utilization_low_period             = var.ecs_alarms_memory_utilization_low_period

  memory_utilization_low_alarm_actions = compact(
    concat(
      var.ecs_alarms_memory_utilization_low_alarm_actions,
      [local.memory_utilization_low_alarm_actions],
    )
  )

  memory_utilization_low_ok_actions = var.ecs_alarms_memory_utilization_low_ok_actions
}

# Right now uses module.alb_ingress whitch is disabled
# TODO: adopt to be compatibile with module.alb
/*module "alb_target_group_cloudwatch_sns_alarms" {
  source                         = "git::https://github.com/cloudposse/terraform-aws-alb-target-group-cloudwatch-sns-alarms.git?ref=tags/0.8.0"
  enabled                        = var.alb_target_group_alarms_enabled
  name                           = var.name
  namespace                      = var.namespace
  stage                          = var.stage
  attributes                     = var.attributes
  alarm_actions                  = var.alb_target_group_alarms_alarm_actions
  ok_actions                     = var.alb_target_group_alarms_ok_actions
  insufficient_data_actions      = var.alb_target_group_alarms_insufficient_data_actions
  alb_arn_suffix                 = var.alb_arn_suffix
  target_group_arn_suffix        = module.alb_ingress.target_group_arn_suffix
  target_3xx_count_threshold     = var.alb_target_group_alarms_3xx_threshold
  target_4xx_count_threshold     = var.alb_target_group_alarms_4xx_threshold
  target_5xx_count_threshold     = var.alb_target_group_alarms_5xx_threshold
  target_response_time_threshold = var.alb_target_group_alarms_response_time_threshold
  period                         = var.alb_target_group_alarms_period
  evaluation_periods             = var.alb_target_group_alarms_evaluation_periods
}*/




# Create user

module "drone-io" {
  source     = "git::https://github.com/BerlingskeMedia/bm.terraform-module.drone-io"
  enabled    = var.drone-io_enabled
  name       = var.name
  namespace  = var.namespace
  stage      = var.stage
  attributes = compact(concat(var.attributes, ["drone"]))
}



############### Service discovery

# TODO: make conditional on second service for multiple-container deployments
/*resource "aws_service_discovery_private_dns_namespace" "nginx" {
  name        = "${module.label.id}.nginx.local"
  description = "Service discovery for ${module.label.id}"
  vpc         = var.vpc_id
}

resource "aws_service_discovery_service" "nginx" {
  name = module.label.id

  dns_config {
    namespace_id = "${aws_service_discovery_private_dns_namespace.nginx.id}"

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}*/

# TODO: make conditional
# TODO: namespace more specific to distinguish from other services in multi-container deployments
resource "aws_service_discovery_private_dns_namespace" "app" {
  name        = "${module.label.id}.local"
  description = "Service discovery for ${module.label.id}"
  vpc         = var.vpc_id
}

# TODO: make conditional
resource "aws_service_discovery_service" "mxtools" {
  name = module.label.id

  dns_config {
    namespace_id = "${aws_service_discovery_private_dns_namespace.app.id}"

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  //  health_check_custom_config {
  //    failure_threshold = 1
  //  }
}






############ Security groups
resource "aws_security_group" "ecs_sg_nginx" {
  name        = "${module.label.id}-nginx-ecs"
  description = "Security group for ECS ${var.name}"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Connections from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [module.security.alb_sg_id]
  }
  ingress {
    description     = "Connections from ALB"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [module.security.alb_sg_id]
  }
  tags = var.tags
}
resource "aws_security_group" "ecs_sg_mxtools" {
  name        = "${module.label.id}-mxtools-ecs"
  description = "Security group for ECS ${var.name}"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Connections from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [module.security.alb_sg_id]
  }
  ingress {
    description     = "Connections from ALB"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [module.security.alb_sg_id]
  }
  tags = var.tags
}


resource "aws_security_group" "ecs_sg_other" {
  name        = "${module.label.id}-ecs-other"
  description = "Security group giving access to ECS instances ${module.label.id} on containers ports"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { "Name" = "${module.label.id}-ecs-other" })
}

resource "aws_security_group" "ecs_sg_internal" {
  name        = "${module.label.id}-ecs-internal"
  description = "Security group giving access between ECS instances ${module.label.id} on containers ports"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = toset(var.ecs_ports)
    content {
      description = "Connections to exposed ports"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      security_groups = [
      aws_security_group.ecs_sg_other.id]
    }
  }
  ingress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    self        = true
    description = "All resources using this SG have unlimited access to each other"
  }
  tags = merge(var.tags, { "Name" = "${module.label.id}-ecs-internal" })
}

