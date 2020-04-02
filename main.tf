locals {
  availability_zones = length(var.availability_zones) > 0 ? var.availability_zones : ["${var.region}a", "${var.region}b"]

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

module "default_backend_web_app" {
  #source	= "../temp/default_backend_web_app"
  source                                          = "git::https://github.com/BerlingskeMedia/terraform-aws-ecs-web-app?ref=temp_ecs-webapp_ref" #?ref=tags/0.28.2"
  namespace                                       = var.namespace
  stage                                           = var.stage
  name                                            = var.name
  region                                          = var.region
  vpc_id                                          = module.network.vpc_id
  alb_ingress_unauthenticated_listener_arns       = module.alb.listener_arns
  alb_ingress_unauthenticated_listener_arns_count = 1
  alb_security_group                              = module.security.alb_sg_id
  aws_logs_region                                 = var.region
  ecs_cluster_arn                                 = aws_ecs_cluster.default.arn
  ecs_cluster_name                                = aws_ecs_cluster.default.name
  ecs_security_group_ids                          = [module.security.ecs_sg_id]
  ecs_private_subnet_ids                          = module.network.private_subnets
  alb_ingress_healthcheck_path                    = "/healthcheck"
  alb_ingress_unauthenticated_paths               = ["/*"]
  codepipeline_enabled                            = true
  repo_owner                                      = var.codepipeline_repo_owner
  codepipeline_branch                             = var.codepipeline_branch
  codepipeline_github_oauth_token                 = var.codepipeline_github_oauth_token
  codepipeline_github_webhooks_token              = var.codepipeline_github_webhooks_token
  codepipeline_repo_name                          = var.codepipeline_repo_name
  codepipeline_build_image                        = var.codepipeline_build_image



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
}
