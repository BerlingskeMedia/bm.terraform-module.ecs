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
  source  = "git@github.com:BerlingskeMedia/bm.terraform-module.rds-cluster?ref=tags/0.1.2"
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
    values = ["amzn2-ami-ecs-hvm-2.0*"]
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

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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





