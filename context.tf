module "this" {
  source = "git@github.com:BerlingskeMedia/bm.terraform-module.context?ref=tags/1.0.0"

  enabled                             = var.enabled
  namespace                           = var.namespace
  stage                               = var.stage
  name                                = var.name
  delimiter                           = var.delimiter
  attributes                          = var.attributes
  tags                                = var.tags
  region                              = var.region
  vpc_id                              = var.vpc_id
  launch_type                         = var.launch_type
  ecs_cluster_arn                     = aws_ecs_cluster.default.arn
  aws_logs_region                     = var.region
  aws_cloudwatch_log_group_name       = aws_cloudwatch_log_group.app.name
  deploy_iam_access_key               = module.drone-io.access_key
  deploy_iam_secret_key               = module.drone-io.secret_key
  domain_name                         = "${var.name}.${var.namespace}.${var.alb_main_domain}"
  domain_zone_id                      = (var.alb_internal_enabled || var.alb_external_enabled) && var.alb_main_domain != "" ? data.aws_route53_zone.zone.zone_id : ""
  alb_acm_certificate_arn             = (var.alb_internal_enabled || var.alb_external_enabled) && length(aws_acm_certificate.alb_cert) > 0 ? aws_acm_certificate.alb_cert[0].arn : ""
  kms_key_alias_arn                   = module.kms_key.alias_arn
  kms_key_alias_name                  = module.kms_key.alias_name
  kms_key_arn                         = module.kms_key.key_arn
  kms_key_id                          = module.kms_key.key_id
  kms_key_access_policy_arn           = aws_iam_policy.kms_key_access_policy.arn
  service_discovery_namespace_id      = join("", aws_service_discovery_private_dns_namespace.default.*.id)
  service_discovery_name              = join("", aws_service_discovery_private_dns_namespace.default.*.name)
  service_internal_security_group     = aws_security_group.ecs_sg_internal.id
  private_subnets                     = var.private_subnets
  alb_external_enabled                = var.alb_external_enabled
  alb_external_listener_arn           = var.alb_external_enabled ? module.alb_default_external.https_listener_arn : null
  alb_external_dns_name               = var.alb_external_enabled ? module.alb_default_external.alb_dns_name : null
  alb_external_dns_zone_id            = var.alb_external_enabled ? module.alb_default_external.alb_zone_id : null
  alb_external_allowed_security_group = var.alb_external_enabled ? module.alb_default_external.security_group_id : null
  alb_internal_enabled                = var.alb_internal_enabled
  alb_internal_listener_arn           = var.alb_internal_enabled ? module.alb_default_internal.https_listener_arn : null
  alb_internal_dns_name               = var.alb_internal_enabled ? module.alb_default_internal.alb_dns_name : null
  alb_internal_dns_zone_id            = var.alb_internal_enabled ? module.alb_default_internal.alb_zone_id : null
  alb_internal_allowed_security_group = var.alb_internal_enabled ? module.alb_default_internal.security_group_id : null
}

