module "label" {
  source     = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.24.1"
  namespace  = var.namespace
  name       = var.name
  stage      = var.stage
  delimiter  = var.delimiter
  attributes = var.attributes
  tags       = var.tags
}

# ECS cluster basic configuration
resource "aws_ecs_cluster" "default" {
  name = module.label.id
  tags = module.label.tags
}

# ECS cluster configuration when "EC2" launch type is set

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "ecs_instance_policy" {
  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:DescribeTags",
    ]
  }

  statement {
    effect = "Allow"
    resources = [
      "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.id}:container-instance/${module.label.id}/*"
    ]

    actions = [
      "ecs:Poll",
      "ecs:StartTelemetrySession",
      "ecs:UpdateContainerInstancesState",
    ]
  }

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ecs:DiscoverPollEndpoint",
    ]
  }

  statement {
    effect = "Allow"
    resources = [
      aws_ecs_cluster.default.arn
    ]

    actions = [
      "ecs:DeregisterContainerInstance",
      "ecs:RegisterContainerInstance",
      "ecs:Submit*",
    ]
  }

  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
  }

  statement {
    effect = "Allow"
    resources = [
      aws_cloudwatch_log_group.app.arn
    ]

    actions = [
      "logs:CreateLogStream"
    ]
  }

  statement {
    effect = "Allow"
    resources = [
      "${aws_cloudwatch_log_group.app.arn}:log-stream:*"
    ]

    actions = [
      "logs:PutLogEvents"
    ]
  }
}

resource "aws_iam_policy" "ecs_instance_policy" {
  count       = var.launch_type == "EC2" ? 1 : 0
  name        = "${module.label.id}-ecs-ec2-policy"
  path        = "/"
  description = "${module.label.id} ECS cluster policy used for EC2 instances"
  policy      = data.aws_iam_policy_document.ecs_instance_policy.json
}

data "aws_iam_policy_document" "ec2_role_document" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_ec2_role" {
  count              = var.launch_type == "EC2" ? 1 : 0
  name               = "${module.label.id}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_role_document.json
  tags               = module.label.tags
}

resource "aws_iam_instance_profile" "ecs_ec2_instance_profile" {
  count = var.launch_type == "EC2" ? 1 : 0
  name  = "${module.label.id}-ec2-instance-profile"
  role  = join("", aws_iam_role.ecs_ec2_role.*.name)
}

resource "aws_iam_role_policy_attachment" "ecs_ec2_role_attachement" {
  count      = var.launch_type == "EC2" ? 1 : 0
  role       = join("", aws_iam_role.ecs_ec2_role.*.name)
  policy_arn = join("", aws_iam_policy.ecs_instance_policy.*.arn)
}

data "aws_iam_policy" "AmazonSSMManagedInstanceCore" {
  name = "AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "AmazonSSMManagedInstanceCore" {
  count      = var.launch_type == "EC2" ? 1 : 0
  role       = join("", aws_iam_role.ecs_ec2_role.*.name)
  policy_arn = data.aws_iam_policy.AmazonSSMManagedInstanceCore.arn
}

data "aws_iam_policy" "EC2InstanceConnect" {
  name = "EC2InstanceConnect"
}

resource "aws_iam_role_policy_attachment" "EC2InstanceConnect" {
  count      = var.launch_type == "EC2" ? 1 : 0
  role       = join("", aws_iam_role.ecs_ec2_role.*.name)
  policy_arn = data.aws_iam_policy.EC2InstanceConnect.arn
}

data "aws_ami" "vm_ami" {
  most_recent = true
  filter {
    name   = "name"
    values = [var.instance_ami_name_regex]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  owners = ["amazon"] # We want to use only Amazon optimized ecs image
}

resource "aws_security_group" "ecs_ec2_security_group" {
  count  = var.launch_type == "EC2" ? 1 : 0
  name   = "${module.label.id}-ec2-instances-security-group"
  vpc_id = var.vpc_id

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = module.label.tags
}

locals {
  user_data_file = var.launch_type != "EC2" ? "" : templatefile(
    "${path.module}/additional_config_files/cloud-config.yml",
    {
      ecs_cluster_name         = aws_ecs_cluster.default.name
      efs_mounts_hosts_entries = var.efs_mounts_hosts_entries
    }
  )
}

resource "aws_launch_configuration" "ecs_ec2_launch_configuration" {
  count                       = var.launch_type == "EC2" && var.aws_key_pair != "" ? 1 : 0
  name_prefix                 = "${module.label.id}-launch-configuration-"
  key_name                    = var.aws_key_pair
  image_id                    = data.aws_ami.vm_ami.id
  instance_type               = var.instance_type
  iam_instance_profile        = join("", aws_iam_instance_profile.ecs_ec2_instance_profile.*.arn)
  user_data                   = local.user_data_file
  associate_public_ip_address = false
  security_groups             = [join("", aws_security_group.ecs_ec2_security_group.*.id)]
  root_block_device {
    volume_size = "30"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "ecs_ec2_autoscalling_group" {
  count                 = var.launch_type == "EC2" ? 1 : 0
  name                  = "${module.label.id}-ec2-autoscalling-group"
  vpc_zone_identifier   = var.private_subnets
  desired_capacity      = var.asg_instances_desired_capacity
  max_size              = var.asg_instances_max_size
  min_size              = var.asg_instances_min_size
  launch_configuration  = join("", aws_launch_configuration.ecs_ec2_launch_configuration.*.id)
  termination_policies  = var.asg_termination_policies
  max_instance_lifetime = var.asg_max_instance_lifetime

  dynamic "tag" {
    for_each = module.label.tags

    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

locals {
  full_ecr_namespaces = var.enabled && var.ecr_enabled && length(var.ecr_namespaces) > 0 ? formatlist("${module.label.id}-ecr/%s", var.ecr_namespaces) : []
}

module "ecr" {
  source               = "git::https://github.com/cloudposse/terraform-aws-ecr.git?ref=tags/0.32.2"
  enabled              = var.enabled && var.ecr_enabled
  name                 = var.name
  namespace            = var.namespace
  stage                = var.stage
  tags                 = module.label.tags
  protected_tags       = var.ecr_protected_tag_prefixes
  max_image_count      = var.ecr_max_image_count
  image_tag_mutability = var.ecr_image_tag_mutability
  image_names          = local.full_ecr_namespaces
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

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { "Name" = "${module.label.id}-ecs-internal" })
}

# Create user for drone.io

module "drone-io" {
  source     = "git::https://github.com/BerlingskeMedia/bm.terraform-module.drone-io?ref=tags/0.6.0"
  enabled    = var.drone-io_enabled
  name       = var.name
  namespace  = var.namespace
  stage      = var.stage
  attributes = compact(concat(var.attributes, ["drone"]))
  ecr_arns   = values(module.ecr.repository_arn_map)
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
}

resource "aws_cloudwatch_log_group" "app" {
  name              = module.label.id
  tags              = module.label.tags
  retention_in_days = var.log_retention_in_days
}

# ACM

data "aws_route53_zone" "zone" {
  name         = "${var.alb_main_domain}."
  private_zone = false
}

module "acm_certificate" {
  source                      = "git::https://github.com/cloudposse/terraform-aws-acm-request-certificate.git?ref=tags/0.13.1"
  enabled                     = (var.alb_internal_enabled || var.alb_external_enabled) && var.alb_main_domain != "" ? true : false
  domain_name                 = "${var.name}.${var.namespace}.${var.alb_main_domain}"
  subject_alternative_names   = ["*.${var.name}.${var.namespace}.${var.alb_main_domain}"]
  ttl                         = "60"
  wait_for_certificate_issued = true
  zone_name                   = "${var.alb_main_domain}."
  context                     = module.label.context
}

# ALB

# ALB short names and ALBs target groups names
locals {
  alb_namespace_short          = substr(var.namespace, 0, 4)
  alb_stage_short              = substr(var.stage, 0, 1)
  alb_internal_name_short      = "${substr(var.name, 0, min(length(var.name), 18))}-i"
  alb_external_name_short      = "${substr(var.name, 0, min(length(var.name), 18))}-e"
  alb_internal_default_tg_name = "${local.alb_namespace_short}-${local.alb_stage_short}-${local.alb_internal_name_short}dtg"
  alb_external_default_tg_name = "${local.alb_namespace_short}-${local.alb_stage_short}-${local.alb_external_name_short}dtg"
}

module "alb_default_internal" {
  source                                  = "git::https://github.com/cloudposse/terraform-aws-alb.git?ref=tags/0.33.1"
  enabled                                 = var.alb_internal_enabled
  namespace                               = local.alb_namespace_short
  name                                    = local.alb_internal_name_short
  stage                                   = local.alb_stage_short
  attributes                              = var.attributes
  vpc_id                                  = var.vpc_id
  security_group_enabled                  = var.alb_internal_default_security_group_enabled
  security_group_ids                      = var.alb_internal_additional_security_groups_list
  http_ingress_cidr_blocks                = var.alb_internal_default_security_group_ingress_cidrs_blocks
  https_ingress_cidr_blocks               = var.alb_internal_default_security_group_ingress_cidrs_blocks
  subnet_ids                              = var.private_subnets
  internal                                = true
  target_group_name                       = local.alb_internal_default_tg_name
  http_enabled                            = var.alb_internal_http_enable && var.alb_internal_enabled ? true : false
  http_redirect                           = var.alb_internal_http_redirect && var.alb_internal_http_enable && var.alb_internal_enabled ? true : false
  https_enabled                           = var.alb_internal_https_enable && var.alb_internal_enabled ? true : false
  https_ssl_policy                        = var.alb_internal_https_enable && var.alb_internal_enabled ? var.alb_https_policy : null
  certificate_arn                         = var.alb_internal_enabled ? module.acm_certificate.arn : ""
  access_logs_enabled                     = false
  alb_access_logs_s3_bucket_force_destroy = true
  cross_zone_load_balancing_enabled       = true
  http2_enabled                           = var.alb_internal_http2_enable && var.alb_internal_enabled ? true : false
  deletion_protection_enabled             = false
  tags                                    = module.label.tags
  health_check_path                       = "/"
}

module "alb_default_external" {
  source                                  = "git::https://github.com/cloudposse/terraform-aws-alb.git?ref=tags/0.33.1"
  enabled                                 = var.alb_external_enabled
  namespace                               = local.alb_namespace_short
  name                                    = local.alb_external_name_short
  stage                                   = local.alb_stage_short
  attributes                              = var.attributes
  vpc_id                                  = var.vpc_id
  security_group_enabled                  = var.alb_external_default_security_group_enabled
  security_group_ids                      = var.alb_external_additional_security_groups_list
  http_ingress_cidr_blocks                = var.alb_external_default_security_group_ingress_cidrs_blocks
  https_ingress_cidr_blocks               = var.alb_external_default_security_group_ingress_cidrs_blocks
  subnet_ids                              = var.public_subnets
  internal                                = false
  target_group_name                       = local.alb_external_default_tg_name
  http_enabled                            = var.alb_external_http_enable && var.alb_external_enabled ? true : false
  http_redirect                           = var.alb_external_http_redirect && var.alb_external_http_enable && var.alb_external_enabled ? true : false
  https_enabled                           = var.alb_external_https_enable && var.alb_external_enabled ? true : false
  https_ssl_policy                        = var.alb_external_https_enable && var.alb_external_enabled ? var.alb_https_policy : null
  certificate_arn                         = var.alb_external_enabled ? module.acm_certificate.arn : ""
  access_logs_enabled                     = false
  alb_access_logs_s3_bucket_force_destroy = true
  cross_zone_load_balancing_enabled       = true
  http2_enabled                           = var.alb_external_http2_enable && var.alb_external_enabled ? true : false
  deletion_protection_enabled             = false
  tags                                    = module.label.tags
  health_check_path                       = "/"
}

# KMS key for all services

module "kms_key" {
  source                  = "git::https://github.com/cloudposse/terraform-aws-kms-key.git?ref=tags/0.10.0"
  namespace               = var.namespace
  stage                   = var.stage
  name                    = var.name
  tags                    = var.tags
  description             = "KMS key for all ${module.label.id} projects"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

data "aws_iam_policy_document" "kms_key_policy_document" {
  statement {
    effect = "Allow"
    resources = [
      module.kms_key.key_arn
    ]
    actions = [
      "kms:GenerateDataKey",
      "kms:DescribeKey",
      "kms:Decrypt"
    ]
  }
}

resource "aws_iam_policy" "kms_key_access_policy" {
  name   = "${module.label.id}-kms_access_policy"
  policy = data.aws_iam_policy_document.kms_key_policy_document.json
}

# create service discovery
resource "aws_service_discovery_private_dns_namespace" "default" {
  count       = var.service_discovery_enabled ? 1 : 0
  name        = "${module.label.id}.local"
  description = "Service discovery for ${module.label.id}"
  vpc         = var.vpc_id
}

locals {
  # External ALB output map
  external_alb_output_map = {
    "listener_arn"              = var.alb_external_enabled ? module.alb_default_external.https_listener_arn : ""
    "dns_name"                  = var.alb_external_enabled ? module.alb_default_external.alb_dns_name : ""
    "dns_zone_id"               = var.alb_external_enabled ? module.alb_default_external.alb_zone_id : ""
    "allowed_security_group_id" = var.alb_external_enabled ? module.alb_default_external.security_group_id : ""
  }
  # Internal ALB output map
  internal_alb_output_map = {
    "listener_arn"              = var.alb_internal_enabled ? module.alb_default_internal.https_listener_arn : ""
    "dns_name"                  = var.alb_internal_enabled ? module.alb_default_internal.alb_dns_name : ""
    "dns_zone_id"               = var.alb_internal_enabled ? module.alb_default_internal.alb_zone_id : ""
    "allowed_security_group_id" = var.alb_internal_enabled ? module.alb_default_internal.security_group_id : ""
  }
  # Map passed to ecs-service module to simplify manifests
  output_map = {
    #General variables
    "label_id"   = module.label.id
    "name"       = var.name
    "stage"      = var.stage
    "namespace"  = var.namespace
    "attributes" = var.attributes
    "tags"       = var.tags
    "region"     = var.region
    "delimiter"  = var.delimiter
    #Network variables
    "vpc_id"                          = var.vpc_id
    "service_internal_security_group" = aws_security_group.ecs_sg_internal.id
    #ECS Cluster variables
    "ecs_cluster_arn"               = aws_ecs_cluster.default.arn
    "launch_type"                   = var.launch_type
    "aws_logs_region"               = var.region
    "aws_cloudwatch_log_group_name" = aws_cloudwatch_log_group.app.name
    "deploy_iam_access_key"         = var.drone-io_enabled ? module.drone-io.access_key : ""
    "deploy_iam_secret_key"         = var.drone-io_enabled ? module.drone-io.secret_key : ""
    #"ecr_urls"                        = var.ecr_enabled ? module.ecr.name_to_url : ""
    # ALB variables
    "domain_name"             = "${var.name}.${var.namespace}.${var.alb_main_domain}"
    "domain_zone_id"          = (var.alb_internal_enabled || var.alb_external_enabled) && var.alb_main_domain != "" ? data.aws_route53_zone.zone.zone_id : ""
    "alb_acm_certificate_arn" = (var.alb_internal_enabled || var.alb_external_enabled) && var.alb_main_domain != "" ? module.acm_certificate.arn : ""
    # KMS outputs
    "kms_key_alias_arn"         = module.kms_key.alias_arn
    "kms_key_alias_name"        = module.kms_key.alias_name
    "kms_key_arn"               = module.kms_key.key_arn
    "kms_key_id"                = module.kms_key.key_id
    "kms_key_access_policy_arn" = aws_iam_policy.kms_key_access_policy.arn
    # Service discovery outputs
    "service_discovery_namespace_id" = join("", aws_service_discovery_private_dns_namespace.default.*.id)
    "service_discovery_name"         = join("", aws_service_discovery_private_dns_namespace.default.*.name)
  }
}