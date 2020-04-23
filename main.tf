locals {
  availability_zones = length(var.availability_zones) > 0 ? var.availability_zones : ["${var.region}a", "${var.region}b"]
  github_token       = var.ssm_github_oauth_token != "" ? data.aws_ssm_parameter.github_oauth_token[0].value : ""

}

module "label" {
  source     = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.16.0"
  namespace  = var.namespace
  name       = var.name
  stage      = var.stage
  delimiter  = var.delimiter
  attributes = var.attributes
  tags       = var.tags
}


module "network" {
  source             = "git@github.com:BerlingskeMedia/bm.terraform-module.network"
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

module "secrets" {
  source    = "git@github.com:BerlingskeMedia/bm.terraform-module.secrets"
  namespace = var.namespace
  stage     = var.stage
  name      = var.name
  tags      = var.tags
}

module "security" {
  source    = "git@github.com:BerlingskeMedia/bm.terraform-module.security"
  label     = module.label.id
  namespace = var.namespace
  rds_port  = var.rds_port
  stage     = var.stage
  tags      = var.tags
  vpc_id    = module.network.vpc_id
  name      = var.name
}

module "alb" {
  source     = "git::https://github.com/cloudposse/terraform-aws-alb.git?ref=tags/0.7.0"
  namespace  = var.namespace
  stage      = var.stage
  name       = var.name
  attributes = var.attributes
  delimiter  = var.delimiter
  vpc_id     = module.network.vpc_id
  //  security_group_ids                      = [data.aws_vpc.selected.vpc_default_security_group_id] aws_security_group.default.id
  security_group_ids = [module.security.alb_sg_id]
  //  subnet_ids                              = module.subnets.public_subnet_ids
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
}



module "rds" {
  source  = "git@github.com:BerlingskeMedia/bm.terraform-module.rds-cluster"
  enabled = var.run_rds

  master_password = module.secrets.rsd_master_password
  name            = "${var.name}-rds"
  namespace       = var.namespace
  rds_port        = var.rds_port
  security_groups = [module.security.rds_sg_id]
  stage           = var.stage
  subnets         = module.network.private_subnets
  vpc_id          = module.network.vpc_id
  tags            = var.tags
}

resource "aws_ecs_cluster" "default" {
  name = module.label.id
  tags = module.label.tags
}

data "aws_ssm_parameter" "github_oauth_token" {
  count = var.ssm_github_oauth_token != "" ? 1 : 0
  name  = var.ssm_github_oauth_token
}





/*module "default_backend_web_app" {
  #source	= "../temp/default_backend_web_app"
  source          = "git::https://github.com/BerlingskeMedia/terraform-aws-ecs-web-app?ref=temp_ecs-webapp_ref" #?ref=tags/0.28.2"
  namespace       = var.namespace
  stage           = var.stage
  name            = var.name
  region          = var.region
  vpc_id          = module.network.vpc_id
  aws_logs_region = var.region

  # Load balancer
  alb_ingress_unauthenticated_listener_arns       = module.alb.listener_arns
  alb_ingress_unauthenticated_listener_arns_count = 1
  alb_security_group                              = module.security.alb_sg_id
  alb_ingress_healthcheck_path                    = "/healthcheck"
  alb_ingress_unauthenticated_paths               = ["*/ /*"]

  # ECS cluster
  ecs_cluster_arn        = aws_ecs_cluster.default.arn
  ecs_cluster_name       = aws_ecs_cluster.default.name
  ecs_security_group_ids = [module.security.ecs_sg_id]
  ecs_private_subnet_ids = module.network.private_subnets

  # Code pipeline
  codepipeline_enabled  = true
  repo_owner            = var.github_repo_owner
  github_oauth_token    = local.github_token
  github_webhooks_token = var.github_webhooks_token
  build_image           = var.codepipeline_build_image
  repo_name             = var.github_repo_name
  branch                = var.github_branch_name
  webhook_enabled       = var.webhook_enabled


  environment = [
    {
      name  = "COOKIE"
      value = "cookiemonster"
    },
    {
      name  = "PORT"
      value = "80"
    }
  ]
}*/





############## default webapp

module "ecr" {
  source = "git::https://github.com/BerlingskeMedia/bm.terraform-module.ecr"
  //source     = "git::https://github.com/BerlingskeMedia/bm.terraform-module.ecr?ref=3e03498ecff1a87407dffa5c59db9852a1ac3cdd"
  //source = "../bm.terraform-module.ecr"
  enabled    = var.ecr_enabled
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

module "alb_ingress" {
  source            = "git::https://github.com/cloudposse/terraform-aws-alb-ingress.git?ref=tags/0.9.0"
  name              = var.name
  namespace         = var.namespace
  stage             = var.stage
  attributes        = var.attributes
  vpc_id            = var.vpc_id
  port              = var.container_port
  health_check_path = var.alb_ingress_healthcheck_path
  //default_target_group_enabled = true
  default_target_group_enabled = true

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
}

/*module "container_definition" {
  source                       = "git::https://github.com/cloudposse/terraform-aws-ecs-container-definition.git?ref=tags/0.22.0"
  container_name               = module.label.id
  container_image              = var.container_image
  container_memory             = var.container_memory
  container_memory_reservation = var.container_memory_reservation
  container_cpu                = var.container_cpu
  healthcheck                  = var.healthcheck
  environment                  = var.environment
  port_mappings                = var.container_port_mappings
  secrets                      = var.secrets
  ulimits                      = var.ulimits
  entrypoint                   = var.entrypoint
  command                      = var.command
  mount_points                 = var.mount_points
  container_depends_on         = local.container_depends_on

  log_configuration = {
    logDriver = var.log_driver
    options = {
      "awslogs-region"        = var.aws_logs_region
      "awslogs-group"         = aws_cloudwatch_log_group.app.name
      "awslogs-stream-prefix" = var.name
    }
    secretOptions = null
  }
}*/
// TODO: change tagging from latest to other
locals {
  // hard tag latest on every image
  //container_images = formatlist("%s:latest", module.ecr.registry_url)
  container_images = [var.container_image]
}

module "container_definition" {
  //source                       = "git::https://github.com/cloudposse/terraform-aws-ecs-container-definition.git?ref=tags/0.22.0"
  source = "git::https://github.com/BerlingskeMedia/bm.terraform-module.container_definition"
  //source = "../container_definition"
  containers_map = module.ecr.name_to_url
  container_name = module.label.id
  container_image              = local.container_images
  //container_image              = ""
  container_memory             = var.container_memory
  container_memory_reservation = var.container_memory_reservation
  container_cpu                = var.container_cpu
  healthcheck                  = var.healthcheck
  environment                  = var.environment
  port_mappings                = var.container_port_mappings
  secrets                      = var.secrets
  ulimits                      = var.ulimits
  entrypoint                   = var.entrypoint
  command                      = var.command
  mount_points                 = var.mount_points
  container_depends_on         = local.container_depends_on

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

  alb = {
    container_name = module.label.id
    container_port = var.container_port
    elb_name       = null
    //target_group_arn = module.alb_ingress.target_group_arn
    target_group_arn = module.alb.default_target_group_arn
  }
  /*nlb = {
    container_name   = module.label.id
    container_port   = var.nlb_container_port
    elb_name         = null
    target_group_arn = var.nlb_ingress_target_group_arn
  }*/
  //load_balancers = var.nlb_ingress_target_group_arn != "" ? [local.alb, local.nlb] : [local.alb]
  load_balancers = [local.alb]
  /*load_balancers_2 = [local.alb2]*/
  init_container_definitions = [
    for init_container in var.init_containers : lookup(init_container, "container_definition")
  ]
  //file_container_definitions = lookup(jsondecode(var.file), "containerDefinitions")

  container_depends_on = [
    for init_container in var.init_containers :
    {
      containerName = lookup(jsondecode(init_container.container_definition), "name"),
      condition     = init_container.condition
    }
  ]
  primary_container_definition   = var.disable_primary_container_definition ? var.custom_container_definition_1 : module.container_definition.json_map
  secondary_container_definition = var.disable_secondary_container_definition ? var.custom_container_definition_2 : []
}

/*
# Push init images
data "aws_ecr_image" "service_image" {
  repository_name = "my/service"
  image_tag       = "latest"
}
*/



module "ecs_alb_service_task" {
  source = "git::https://github.com/cloudposse/terraform-aws-ecs-alb-service-task.git?ref=tags/0.21.0"
  //source = "../terraform-aws-ecs-alb-service-task"
  name                   = var.name
  namespace              = var.namespace
  stage                  = var.stage
  attributes             = var.attributes
  alb_security_group     = module.security.alb_sg_id
  use_alb_security_group = true
  //nlb_cidr_blocks                   = var.nlb_cidr_blocks
  //use_nlb_cidr_blocks               = var.use_nlb_cidr_blocks
  container_definition_json         = "[${join(",", concat(local.init_container_definitions, local.primary_container_definition))}]"
  desired_count                     = var.desired_count
  health_check_grace_period_seconds = var.health_check_grace_period_seconds
  task_cpu                          = coalesce(var.task_cpu, var.container_cpu)
  task_memory                       = coalesce(var.task_memory, var.container_memory)
  ecs_cluster_arn                   = aws_ecs_cluster.default.arn
  launch_type                       = var.launch_type
  vpc_id                            = var.vpc_id
  security_group_ids                = var.ecs_security_group_ids
  subnet_ids                        = module.network.private_subnets
  container_port                    = var.container_port
  //nlb_container_port                = var.nlb_container_port
  tags               = var.tags
  volumes            = var.volumes
  ecs_load_balancers = local.load_balancers
}

/*module "ecs_alb_service_task_2" {
  source                            = "git::https://github.com/cloudposse/terraform-aws-ecs-alb-service-task.git?ref=tags/0.21.0"
  //source = "../terraform-aws-ecs-alb-service-task"
  name                              = var.name
  namespace                         = var.namespace
  stage                             = var.stage
  attributes                        = var.attributes
  alb_security_group                = module.security.alb_sg_id
  use_alb_security_group            = true
  //nlb_cidr_blocks                   = var.nlb_cidr_blocks
  //use_nlb_cidr_blocks               = var.use_nlb_cidr_blocks
  container_definition_json         = "[${join(",", concat(local.init_container_definitions, local.secondary_container_definition))}]"
  desired_count                     = var.desired_count
  health_check_grace_period_seconds = var.health_check_grace_period_seconds
  task_cpu                          = coalesce(var.task_cpu, var.container_cpu)
  task_memory                       = coalesce(var.task_memory, var.container_memory)
  ecs_cluster_arn                   = aws_ecs_cluster.default.arn
  launch_type                       = var.launch_type
  vpc_id                            = var.vpc_id
  security_group_ids                = var.ecs_security_group_ids
  subnet_ids                        = module.network.private_subnets
  container_port                    = var.container_port
  //nlb_container_port                = var.nlb_container_port
  tags                              = var.tags
  volumes                           = var.volumes
  ecs_load_balancers                = local.load_balancers_2
}*/


# TODO: Multi codepipeline
locals {
  repository_name = length(module.ecr.repository_name) > 0 ? element(module.ecr.repository_name, 0) : ""
}
module "ecs_codepipeline" {
  enabled               = var.codepipeline_enabled
  source                = "git::https://github.com/BerlingskeMedia/terraform-aws-ecs-codepipeline?ref=temp_github_ref"
  name                  = var.name
  namespace             = var.namespace
  stage                 = var.stage
  attributes            = var.attributes
  region                = var.region
  github_oauth_token    = local.github_token
  github_webhooks_token = var.github_webhooks_token
  //  github_webhook_events = var.github_webhook_events
  repo_owner = var.github_repo_owner
  repo_name  = var.github_repo_name
  branch     = var.github_branch_name
  //badge_enabled         = var.badge_enabled
  build_image   = var.codepipeline_build_image
  build_timeout = var.build_timeout
  buildspec     = var.codepipeline_buildspec
  //image_repo_name       = module.ecr.repository_name
  image_repo_name     = local.repository_name
  service_name        = module.ecs_alb_service_task.service_name
  ecs_cluster_name    = aws_ecs_cluster.default.name
  privileged_mode     = true
  poll_source_changes = var.poll_source_changes

  webhook_enabled             = var.webhook_enabled
  webhook_target_action       = var.webhook_target_action
  webhook_authentication      = var.webhook_authentication
  webhook_filter_json_path    = var.webhook_filter_json_path
  webhook_filter_match_equals = var.webhook_filter_match_equals

  s3_bucket_force_destroy = var.codepipeline_s3_bucket_force_destroy

  environment_variables = [
    {
      name  = "CONTAINER_NAME"
      value = module.label.id
    }
  ]
}

module "ecs_cloudwatch_autoscaling" {
  enabled               = var.autoscaling_enabled
  source                = "git::https://github.com/cloudposse/terraform-aws-ecs-cloudwatch-autoscaling.git?ref=tags/0.2.0"
  name                  = var.name
  namespace             = var.namespace
  stage                 = var.stage
  attributes            = var.attributes
  service_name          = module.ecs_alb_service_task.service_name
  cluster_name          = aws_ecs_cluster.default.name
  min_capacity          = var.autoscaling_min_capacity
  max_capacity          = var.autoscaling_max_capacity
  scale_down_adjustment = var.autoscaling_scale_down_adjustment
  scale_down_cooldown   = var.autoscaling_scale_down_cooldown
  scale_up_adjustment   = var.autoscaling_scale_up_adjustment
  scale_up_cooldown     = var.autoscaling_scale_up_cooldown
}

/*module "ecs_cloudwatch_autoscaling_2" {
  enabled               = var.autoscaling_enabled
  source                = "git::https://github.com/cloudposse/terraform-aws-ecs-cloudwatch-autoscaling.git?ref=tags/0.2.0"
  name                  = var.name
  namespace             = var.namespace
  stage                 = var.stage
  attributes            = var.attributes
  service_name          = module.ecs_alb_service_task_2.service_name
  cluster_name          = aws_ecs_cluster.default.name
  min_capacity          = var.autoscaling_min_capacity
  max_capacity          = var.autoscaling_max_capacity
  scale_down_adjustment = var.autoscaling_scale_down_adjustment
  scale_down_cooldown   = var.autoscaling_scale_down_cooldown
  scale_up_adjustment   = var.autoscaling_scale_up_adjustment
  scale_up_cooldown     = var.autoscaling_scale_up_cooldown
}*/

locals {
  cpu_utilization_high_alarm_actions    = var.autoscaling_enabled && var.autoscaling_dimension == "cpu" ? module.ecs_cloudwatch_autoscaling.scale_up_policy_arn : ""
  cpu_utilization_low_alarm_actions     = var.autoscaling_enabled && var.autoscaling_dimension == "cpu" ? module.ecs_cloudwatch_autoscaling.scale_down_policy_arn : ""
  memory_utilization_high_alarm_actions = var.autoscaling_enabled && var.autoscaling_dimension == "memory" ? module.ecs_cloudwatch_autoscaling.scale_up_policy_arn : ""
  memory_utilization_low_alarm_actions  = var.autoscaling_enabled && var.autoscaling_dimension == "memory" ? module.ecs_cloudwatch_autoscaling.scale_down_policy_arn : ""
  /*cpu_utilization_high_alarm_actions_2    = var.autoscaling_enabled && var.autoscaling_dimension == "cpu" ? module.ecs_cloudwatch_autoscaling_2.scale_up_policy_arn : ""
  cpu_utilization_low_alarm_actions_2     = var.autoscaling_enabled && var.autoscaling_dimension == "cpu" ? module.ecs_cloudwatch_autoscaling_2.scale_down_policy_arn : ""
  memory_utilization_high_alarm_actions_2 = var.autoscaling_enabled && var.autoscaling_dimension == "memory" ? module.ecs_cloudwatch_autoscaling_2.scale_up_policy_arn : ""
  memory_utilization_low_alarm_actions_2  = var.autoscaling_enabled && var.autoscaling_dimension == "memory" ? module.ecs_cloudwatch_autoscaling_2.scale_down_policy_arn : ""*/
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
  service_name = module.ecs_alb_service_task.service_name

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

/*
module "ecs_cloudwatch_sns_alarms_2" {
  source  = "git::https://github.com/cloudposse/terraform-aws-ecs-cloudwatch-sns-alarms.git?ref=tags/0.5.0"
  enabled = var.ecs_alarms_enabled

  name       = var.name
  namespace  = var.namespace
  stage      = var.stage
  attributes = var.attributes
  tags       = var.tags

  cluster_name = aws_ecs_cluster.default.name
  service_name = module.ecs_alb_service_task_2.service_name

  cpu_utilization_high_threshold          = var.ecs_alarms_cpu_utilization_high_threshold
  cpu_utilization_high_evaluation_periods = var.ecs_alarms_cpu_utilization_high_evaluation_periods
  cpu_utilization_high_period             = var.ecs_alarms_cpu_utilization_high_period

  cpu_utilization_high_alarm_actions = compact(
    concat(
      var.ecs_alarms_cpu_utilization_high_alarm_actions,
      [local.cpu_utilization_high_alarm_actions_2],
    )
  )

  cpu_utilization_high_ok_actions = var.ecs_alarms_cpu_utilization_high_ok_actions

  cpu_utilization_low_threshold          = var.ecs_alarms_cpu_utilization_low_threshold
  cpu_utilization_low_evaluation_periods = var.ecs_alarms_cpu_utilization_low_evaluation_periods
  cpu_utilization_low_period             = var.ecs_alarms_cpu_utilization_low_period

  cpu_utilization_low_alarm_actions = compact(
    concat(
      var.ecs_alarms_cpu_utilization_low_alarm_actions,
      [local.cpu_utilization_low_alarm_actions_2],
    )
  )

  cpu_utilization_low_ok_actions = var.ecs_alarms_cpu_utilization_low_ok_actions

  memory_utilization_high_threshold          = var.ecs_alarms_memory_utilization_high_threshold
  memory_utilization_high_evaluation_periods = var.ecs_alarms_memory_utilization_high_evaluation_periods
  memory_utilization_high_period             = var.ecs_alarms_memory_utilization_high_period

  memory_utilization_high_alarm_actions = compact(
    concat(
      var.ecs_alarms_memory_utilization_high_alarm_actions,
      [local.memory_utilization_high_alarm_actions_2],
    )
  )

  memory_utilization_high_ok_actions = var.ecs_alarms_memory_utilization_high_ok_actions

  memory_utilization_low_threshold          = var.ecs_alarms_memory_utilization_low_threshold
  memory_utilization_low_evaluation_periods = var.ecs_alarms_memory_utilization_low_evaluation_periods
  memory_utilization_low_period             = var.ecs_alarms_memory_utilization_low_period

  memory_utilization_low_alarm_actions = compact(
    concat(
      var.ecs_alarms_memory_utilization_low_alarm_actions,
      [local.memory_utilization_low_alarm_actions_2],
    )
  )

  memory_utilization_low_ok_actions = var.ecs_alarms_memory_utilization_low_ok_actions
}
*/

module "alb_target_group_cloudwatch_sns_alarms" {
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
}

/*resource "aws_ecs_task_definition" "service" {
  for_each = module.ecr.repository_name
  family                = each.value
  container_definitions = file("task-definitions/service.json")

  volume {
    name      = "service-storage"
    host_path = "/ecs/service-storage"
  }

  placement_constraints {
    type       = "memberOf"
    expression = "attribute:ecs.availability-zone in [us-west-2a, us-west-2b]"
  }
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






