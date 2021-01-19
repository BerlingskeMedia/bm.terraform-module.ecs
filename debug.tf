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