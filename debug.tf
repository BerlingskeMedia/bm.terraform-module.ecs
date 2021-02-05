locals {
  debug = {
    var1 = "test"
    var2 = ["aa"]
  }
}

output "debug" {
  value = local.debug
}


output "context_input_context" {
  value = module.this.cloudposse_context
}

output "alb_internal_listener_arn" {
  //value = module.alb_default_internal.listener_arns
  //value = var.alb_internal_enabled ? module.alb_default_internal.https_listener_arn : null
  value = module.alb_default_internal.https_listener_arn
}


output "context_aila" {
  value = module.this.aila
}