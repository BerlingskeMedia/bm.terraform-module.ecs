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

# ECS cluster basic configuration
resource "aws_ecs_cluster" "default" {
  name = module.label.id
  tags = module.label.tags
}

# ECS cluster configuration when "EC2" launch type is set
locals {
  ecs_ec2_role_policies_list = [
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess",
    "arn:aws:iam::aws:policy/AmazonECS_FullAccess",
    "arn:aws:iam::aws:policy/AWSApplicationDiscoveryServiceFullAccess",
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
    "arn:aws:iam::aws:policy/AmazonRoute53FullAccess"
  ]
}

data "aws_iam_policy_document" "ec2_role_document" {
  statement {
    actions         = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_ec2_role" {
  count               = var.launch_type == "EC2" ? 1 : 0
  name                = "${module.label.id}-ec2-role"
  assume_role_policy  = data.aws_iam_policy_document.ec2_role_document.json
  tags                = module.label.tags
}

resource "aws_iam_instance_profile" "ecs_ec2_instance_profile" {
  count = var.launch_type == "EC2" ? 1 : 0
  name  = "${module.label.id}-ec2-instance-profile"
  role  = join("",aws_iam_role.ecs_ec2_role.*.name)
}

resource "aws_iam_role_policy_attachment" "ecs_ec2_role_attachement" {
  role          = join("",aws_iam_role.ecs_ec2_role.*.name)
  for_each      = var.launch_type == "EC2" ? toset(local.ecs_ec2_role_policies_list) : toset([])
  policy_arn    = each.value
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
  count     = var.launch_type == "EC2" ? 1 : 0
  name      = "${module.label.id}-ec2-instances-security-group"
  vpc_id    = var.vpc_id

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
  tags      = module.label.tags
}

resource "aws_launch_configuration" "ecs_ec2_launch_configuration" {
  count                         = var.launch_type == "EC2" && var.aws_key_pair != "" ? 1 : 0
  name_prefix                   = "${module.label.id}-launch-configuration-"
  key_name                      = var.aws_key_pair
  image_id                      = data.aws_ami.vm_ami.id
  instance_type                 = var.instance_type
  iam_instance_profile          = join("",aws_iam_instance_profile.ecs_ec2_instance_profile.*.arn)
  user_data                     = templatefile(
    "${path.module}/cloud-config.yml",
    {
      ecs_cluster_name = "${aws_ecs_cluster.default.name}"
    }
  )
  associate_public_ip_address   = false
  security_groups               = [join("",aws_security_group.ecs_ec2_security_group.*.id)]
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
  launch_configuration  = join("",aws_launch_configuration.ecs_ec2_launch_configuration.*.id)
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

module "ecr" {
  source      = "git::https://github.com/BerlingskeMedia/bm.terraform-module.ecr?ref=tags/0.1.0"
  enabled     = var.enabled && var.ecr_enabled
  name        = var.name
  namespace   = var.namespace
  stage       = var.stage
  attributes  = compact(concat(var.attributes, ["ecr"]))
  namespaces  = var.ecr_namespaces
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
  source     = "git::https://github.com/BerlingskeMedia/bm.terraform-module.drone-io?ref=tags/0.1.1"
  enabled    = var.drone-io_enabled
  name       = var.name
  namespace  = var.namespace
  stage      = var.stage
  attributes = compact(concat(var.attributes, ["drone"]))
}

# output drone's keys
data "aws_ssm_parameter" "access_key" {
  depends_on = [module.drone-io]
  count      = var.drone-io_enabled ? 1 : 0
  name       = module.drone-io.access_key_path
}
data "aws_ssm_parameter" "secret_key" {
  depends_on = [module.drone-io]
  count      = var.drone-io_enabled ? 1 : 0
  name       = module.drone-io.secret_key_path
}


locals {
  repository_name = length(module.ecr.repository_name) > 0 ? element(module.ecr.repository_name, 0) : ""
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

resource "aws_acm_certificate" "alb_cert" {
  count                     = (var.alb_internal_create || var.alb_external_create) && var.alb_main_domain != "" ? 1 : 0
  domain_name               = "${var.name}.${var.namespace}.${var.alb_main_domain}"
  subject_alternative_names = ["*.${var.name}.${var.namespace}.${var.alb_main_domain}"]
  validation_method         = "DNS"
}

resource "aws_route53_record" "alb_cert_validation" {
  count   = (var.alb_internal_create || var.alb_external_create) && var.alb_main_domain != "" ? 1 : 0
  name    = aws_acm_certificate.alb_cert.0.domain_validation_options.0.resource_record_name
  type    = aws_acm_certificate.alb_cert.0.domain_validation_options.0.resource_record_type
  zone_id = data.aws_route53_zone.zone.zone_id
  records = [aws_acm_certificate.alb_cert.0.domain_validation_options.0.resource_record_value]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "alb_cert" {
  count                   = (var.alb_internal_create || var.alb_external_create) && var.alb_main_domain != "" ? 1 : 0
  certificate_arn         = aws_acm_certificate.alb_cert.0.arn
  validation_record_fqdns = [aws_route53_record.alb_cert_validation.0.fqdn]
}

# ALB

# ALB short names and ALBs target groups names
locals {
  alb_namespace_short           = substr(var.namespace, 0, 4)
  alb_stage_short               = substr(var.stage, 0, 1)
  alb_internal_name_short       = "${substr(var.name, 0, min(length(var.name), 18))}-i"
  alb_external_name_short       = "${substr(var.name, 0, min(length(var.name), 18))}-e"
  internal_alb_default_tg_name  = "${local.alb_namespace_short}-${local.alb_stage_short}-${local.alb_internal_name_short}dtg"
  external_alb_default_tg_name  = "${local.alb_namespace_short}-${local.alb_stage_short}-${local.alb_external_name_short}dtg"
}

module "alb_default_internal" {
  source                                  = "git::https://github.com/cloudposse/terraform-aws-alb.git?ref=tags/0.18.0"
  namespace                               = local.alb_namespace_short
  name                                    = local.alb_internal_name_short
  stage                                   = local.alb_stage_short
  attributes                              = var.attributes
  vpc_id                                  = var.vpc_id
  security_group_ids                      = [module.security.alb_sg_id]
  subnet_ids                              = var.private_subnets
  internal                                = true
  target_group_name                       = local.internal_alb_default_tg_name
  http_enabled                            = var.alb_internal_http_enable && var.alb_internal_create ? true : false
  http_redirect                           = var.alb_internal_http_redirect && var.alb_internal_create ? true : false
  https_enabled                           = var.alb_internal_https_enable && var.alb_internal_create ? true : false
  https_ssl_policy                        = var.alb_internal_https_enable && var.alb_internal_create ? var.alb_https_policy : null
  certificate_arn                         = aws_acm_certificate.alb_cert[0].arn
  access_logs_enabled                     = false
  alb_access_logs_s3_bucket_force_destroy = true
  access_logs_region                      = var.region
  cross_zone_load_balancing_enabled       = true
  http2_enabled                           = var.alb_internal_http2_enable && var.alb_internal_create ? true : false
  deletion_protection_enabled             = false
  tags                                    = module.label.tags
  health_check_path                       = "/"
}

module "alb_default_external" {
  source                                  = "git::https://github.com/cloudposse/terraform-aws-alb.git?ref=tags/0.18.0"
  namespace                               = local.alb_namespace_short
  name                                    = local.alb_external_name_short
  stage                                   = local.alb_stage_short
  attributes                              = var.attributes
  vpc_id                                  = var.vpc_id
  security_group_ids                      = [module.security.alb_sg_id]
  subnet_ids                              = var.public_subnets
  internal                                = false
  target_group_name                       = local.external_alb_default_tg_name
  http_enabled                            = var.alb_external_http_enable && var.alb_external_create ? true : false
  http_redirect                           = var.alb_external_http_redirect && var.alb_external_create ? true : false
  https_enabled                           = var.alb_external_https_enable && var.alb_external_create ? true : false
  https_ssl_policy                        = var.alb_external_https_enable && var.alb_external_create ? var.alb_https_policy : null
  certificate_arn                         = aws_acm_certificate.alb_cert[0].arn
  access_logs_enabled                     = false
  alb_access_logs_s3_bucket_force_destroy = true
  access_logs_region                      = var.region
  cross_zone_load_balancing_enabled       = true
  http2_enabled                           = var.alb_external_http2_enable && var.alb_external_create ? true : false
  deletion_protection_enabled             = false
  tags                                    = module.label.tags
  health_check_path                       = "/"
}