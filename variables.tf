variable "region" {
  type        = string
  description = "AWS Region for S3 bucket"
  #sane default
}

variable "vpc_id" {
  type        = string
  description = "ID of vpc for this infrastructure"
}

variable "igw_id" {
  type        = string
  description = "Internet Gateway ID"
}

variable "nat_id" {
  type        = string
  description = "NAT Gateway ID"
}

variable "availability_zones" {
  type        = list(string)
  description = "List of availability zones"
  default     = []
  #sane default, computed
}

variable "application_cidr" {
  type        = string
  description = "CIDR block within required subnets will be created"
  #no default. requied range
}

variable "namespace" {
  type        = string
  description = "Namespace (e.g. `eg` or `cp`)"
  #no default.
}

variable "stage" {
  type        = string
  description = "Stage (e.g. `prod`, `testing`, `staging`)"
  #no default.
}

variable "name" {
  type        = string
  description = "Name of the application"
  #no default
}

variable "delimiter" {
  type        = string
  default     = "-"
  description = "Delimiter between `namespace`, `stage`, `name` and `attributes`"
  #sane default
}

variable "attributes" {
  type        = list(string)
  description = "Additional attributes (_e.g._ \"1\")"
  default     = []
  #sane default
}

variable "tags" {
  type        = map(string)
  description = "Additional tags (_e.g._ { BusinessUnit : ABC })"
  #no default
}

#### RDS section
variable "run_rds" {
  type        = bool
  description = "Should run RDS cluster?"
  default     = false
}
variable "rds_port" {
  type        = string
  description = "RDS port"
  default     = "3306"
  #sane default
}


#### ECS section

variable "entrypoint" {
  type        = list(string)
  description = "The entry point that is passed to the container"
  default     = null
}

variable "command" {
  type        = list(string)
  description = "The command that is passed to the container"
  default     = null
}

variable "mount_points" {
  type = list(object({
    containerPath = string
    sourceVolume  = string
  }))

  description = "Container mount points. This is a list of maps, where each map should contain a `containerPath` and `sourceVolume`"
  default     = null
}

variable "codepipeline_enabled" {
  type        = bool
  description = "A boolean to enable/disable AWS Codepipeline and ECR"
  default     = false
}

variable "container_image" {
  type        = string
  description = "The default container image to use in container definition"
  #no default 
}

variable "container_cpu" {
  type        = number
  description = "The vCPU setting to control cpu limits of container. (If FARGATE launch type is used below, this must be a supported vCPU size from the table here: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html)"
  default     = 256
}

variable "container_memory" {
  type        = number
  description = "The amount of RAM to allow container to use in MB. (If FARGATE launch type is used below, this must be a supported Memory size from the table here: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html)"
  default     = 512
}

variable "container_memory_reservation" {
  type        = number
  description = "The amount of RAM (Soft Limit) to allow container to use in MB. This value must be less than `container_memory` if set"
  default     = 128
}

variable "ulimits" {
  type = list(object({
    name      = string
    softLimit = number
    hardLimit = number
  }))

  description = "The ulimits to configure for the container. This is a list of maps. Each map should contain \"name\", \"softLimit\" and \"hardLimit\""

  default = []
}

variable "container_port" {
  type        = number
  description = "The port number on the container bound to assigned host_port"
  default     = 80
  #sane default
}

variable "container_port_mappings" {
  type = list(object({
    containerPort = number
    hostPort      = number
    protocol      = string
  }))

  description = "The port mappings to configure for the container. This is a list of maps. Each map should contain \"containerPort\", \"hostPort\", and \"protocol\", where \"protocol\" is one of \"tcp\" or \"udp\". If using containers in a task with the awsvpc or host network mode, the hostPort can either be left blank or set to the same value as the containerPort"

  /*default = [
    {
      containerPort = 80
      hostPort      = 80
      protocol      = "tcp"
    }
  ]*/
  default = null
}

variable "desired_count" {
  type        = number
  description = "The desired number of tasks to start with. Set this to 0 if using DAEMON Service type. (FARGATE does not suppoert DAEMON Service type)"
  default     = 1
}

variable "launch_type" {
  type        = string
  description = "The ECS launch type (valid options: FARGATE or EC2)"
  default     = "FARGATE"
}

variable "environment" {
  type = list(object({
    name  = string
    value = string
  }))
  description = "The environment variables to pass to the container. This is a list of maps"
  default     = null
}

variable "secrets" {
  type = list(object({
    name      = string
    valueFrom = string
  }))
  description = "The secrets to pass to the container. This is a list of maps"
  default     = null
}

# https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_HealthCheck.html
variable "healthcheck" {
  type = object({
    command     = list(string)
    retries     = number
    timeout     = number
    interval    = number
    startPeriod = number
  })
  description = "A map containing command (string), timeout, interval (duration in seconds), retries (1-10, number of times to retry before marking container unhealthy), and startPeriod (0-300, optional grace period to wait, in seconds, before failed healthchecks count toward retries)"
  default     = null
}

variable "health_check_grace_period_seconds" {
  type        = number
  description = "Seconds to ignore failing load balancer health checks on newly instantiated tasks to prevent premature shutdown, up to 7200. Only valid for services configured to use load balancers"
  default     = 0
}

variable "alb_target_group_alarms_enabled" {
  type        = bool
  description = "A boolean to enable/disable CloudWatch Alarms for ALB Target metrics"
  default     = false
}

variable "alb_target_group_alarms_3xx_threshold" {
  type        = number
  description = "The maximum number of 3XX HTTPCodes in a given period for ECS Service"
  default     = 25
}

variable "alb_target_group_alarms_4xx_threshold" {
  type        = number
  description = "The maximum number of 4XX HTTPCodes in a given period for ECS Service"
  default     = 25
}

variable "alb_target_group_alarms_5xx_threshold" {
  type        = number
  description = "The maximum number of 5XX HTTPCodes in a given period for ECS Service"
  default     = 25
}

variable "alb_target_group_alarms_response_time_threshold" {
  type        = number
  description = "The maximum ALB Target Group response time"
  default     = 0.5
}

variable "alb_target_group_alarms_period" {
  type        = number
  description = "The period (in seconds) to analyze for ALB CloudWatch Alarms"
  default     = 300
}

variable "alb_target_group_alarms_evaluation_periods" {
  type        = number
  description = "The number of periods to analyze for ALB CloudWatch Alarms"
  default     = 1
}

variable "alb_ingress_healthcheck_path" {
  type        = string
  description = "The path of the healthcheck which the ALB checks"
  default     = "/"
}

variable "alb_ingress_listener_unauthenticated_priority" {
  type        = number
  default     = 1000
  description = "The priority for the rules without authentication, between 1 and 50000 (1 being highest priority). Must be different from `alb_ingress_listener_authenticated_priority` since a listener can't have multiple rules with the same priority"
}

variable "alb_ingress_listener_authenticated_priority" {
  type        = number
  default     = 300
  description = "The priority for the rules with authentication, between 1 and 50000 (1 being highest priority). Must be different from `alb_ingress_listener_unauthenticated_priority` since a listener can't have multiple rules with the same priority"
}

variable "alb_ingress_unauthenticated_hosts" {
  type        = list(string)
  default     = []
  description = "Unauthenticated hosts to match in Hosts header"
}

variable "alb_ingress_authenticated_hosts" {
  type        = list(string)
  default     = []
  description = "Authenticated hosts to match in Hosts header"
}

variable "alb_ingress_unauthenticated_paths" {
  type        = list(string)
  default     = []
  description = "Unauthenticated path pattern to match (a maximum of 1 can be defined)"
}

variable "alb_ingress_authenticated_paths" {
  type        = list(string)
  default     = []
  description = "Authenticated path pattern to match (a maximum of 1 can be defined)"
}

variable "alb_ingress_authenticated_listener_arns" {
  type        = list(string)
  description = "A list of authenticated ALB listener ARNs to attach ALB listener rules to"
  default     = []
}

variable "alb_ingress_authenticated_listener_arns_count" {
  type        = number
  description = "The number of authenticated ARNs in `alb_ingress_authenticated_listener_arns`. This is necessary to work around a limitation in Terraform where counts cannot be computed"
  default     = 0
}

variable "aws_logs_region" {
  type        = string
  description = "The region for the AWS Cloudwatch Logs group"
  default     = "eu-west-1"
}

variable "log_driver" {
  type        = string
  description = "The log driver to use for the container. If using Fargate launch type, only supported value is awslogs"
  default     = "awslogs"
}

variable "log_retention_in_days" {
  type        = string
  description = "Log retention measured in days"
  default     = "14"
}

variable "ecs_alarms_enabled" {
  type        = bool
  description = "A boolean to enable/disable CloudWatch Alarms for ECS Service metrics"
  default     = true
}

variable "ecs_alarms_cpu_utilization_high_threshold" {
  type        = number
  description = "The maximum percentage of CPU utilization average"
  default     = 80
}

variable "ecs_alarms_cpu_utilization_high_evaluation_periods" {
  type        = number
  description = "Number of periods to evaluate for the alarm"
  default     = 1
}

variable "ecs_alarms_cpu_utilization_high_period" {
  type        = number
  description = "Duration in seconds to evaluate for the alarm"
  default     = 300
}

variable "ecs_alarms_cpu_utilization_low_threshold" {
  type        = number
  description = "The minimum percentage of CPU utilization average"
  default     = 20
}

variable "ecs_alarms_cpu_utilization_low_evaluation_periods" {
  type        = number
  description = "Number of periods to evaluate for the alarm"
  default     = 1
}

variable "ecs_alarms_cpu_utilization_low_period" {
  type        = number
  description = "Duration in seconds to evaluate for the alarm"
  default     = 300
}

variable "ecs_alarms_memory_utilization_high_threshold" {
  type        = number
  description = "The maximum percentage of Memory utilization average"
  default     = 80
}

variable "ecs_alarms_memory_utilization_high_evaluation_periods" {
  type        = number
  description = "Number of periods to evaluate for the alarm"
  default     = 1
}

variable "ecs_alarms_memory_utilization_high_period" {
  type        = number
  description = "Duration in seconds to evaluate for the alarm"
  default     = 300
}

variable "ecs_alarms_memory_utilization_low_threshold" {
  type        = number
  description = "The minimum percentage of Memory utilization average"
  default     = 20
}

variable "ecs_alarms_memory_utilization_low_evaluation_periods" {
  type        = number
  description = "Number of periods to evaluate for the alarm"
  default     = 1
}

variable "ecs_alarms_memory_utilization_low_period" {
  type        = number
  description = "Duration in seconds to evaluate for the alarm"
  default     = 300
}

variable "ecs_security_group_ids" {
  type        = list(string)
  description = "Additional Security Group IDs to allow into ECS Service"
  default     = []
}

/*variable "codepipeline_github_oauth_token" {
  type        = string
  description = "GitHub Oauth Token with permissions to access private repositories"
  default     = ""
}*/
variable "ssm_github_oauth_token" {
  type        = string
  description = "ARN of parameter storing github oauth token"
  default     = ""
}

variable "github_webhooks_token" {
  type        = string
  description = "GitHub OAuth Token with permissions to create webhooks. If not provided, can be sourced from the `GITHUB_TOKEN` environment variable"
  default     = ""
}

variable "codepipeline_github_webhook_events" {
  type        = list(string)
  description = "A list of events which should trigger the webhook. See a list of [available events](https://developer.github.com/v3/activity/events/types/)"
  default     = ["push"]
}

variable "github_repo_owner" {
  type        = string
  description = "GitHub Organization or Username"
  default     = ""
}

variable "github_repo_name" {
  type        = string
  description = "GitHub repository name of the application to be built and deployed to ECS"
  default     = ""
}

variable "github_branch_name" {
  type        = string
  description = "Branch of the GitHub repository, e.g. `master`"
  default     = ""
}

variable "codepipeline_badge_enabled" {
  type        = bool
  default     = false
  description = "Generates a publicly-accessible URL for the projects build badge. Available as badge_url attribute when enabled"
}

variable "codepipeline_build_image" {
  type        = string
  default     = "aws/codebuild/docker:17.09.0"
  description = "Docker image for build environment, _e.g._ `aws/codebuild/docker:docker:17.09.0`"
}

variable "codepipeline_build_timeout" {
  type        = number
  default     = 60
  description = "How long in minutes, from 5 to 480 (8 hours), for AWS CodeBuild to wait until timing out any related build that does not get marked as completed"
}

variable "codepipeline_buildspec" {
  type        = string
  description = "Declaration to use for building the project. [For more info](http://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html)"
  default     = ""
}

variable "autoscaling_enabled" {
  type        = bool
  description = "A boolean to enable/disable Autoscaling policy for ECS Service"
  default     = false
}

variable "autoscaling_dimension" {
  type        = string
  description = "Dimension to autoscale on (valid options: cpu, memory)"
  default     = "memory"
}

variable "autoscaling_min_capacity" {
  type        = number
  description = "Minimum number of running instances of a Service"
  default     = 1
}

variable "autoscaling_max_capacity" {
  type        = number
  description = "Maximum number of running instances of a Service"
  default     = 2
}

variable "autoscaling_scale_up_adjustment" {
  type        = number
  description = "Scaling adjustment to make during scale up event"
  default     = 1
}

variable "autoscaling_scale_up_cooldown" {
  type        = number
  description = "Period (in seconds) to wait between scale up events"
  default     = 60
}

variable "autoscaling_scale_down_adjustment" {
  type        = number
  description = "Scaling adjustment to make during scale down event"
  default     = -1
}

variable "autoscaling_scale_down_cooldown" {
  type        = number
  description = "Period (in seconds) to wait between scale down events"
  default     = 300
}

variable "poll_source_changes" {
  type        = bool
  default     = false
  description = "Periodically check the location of your source content and run the pipeline if changes are detected"
}

variable "webhook_enabled" {
  type        = bool
  description = "Set to false to prevent the module from creating any webhook resources"
  default     = false
}

variable "webhook_target_action" {
  type        = string
  description = "The name of the action in a pipeline you want to connect to the webhook. The action must be from the source (first) stage of the pipeline"
  default     = "Source"
}

variable "webhook_authentication" {
  type        = string
  description = "The type of authentication to use. One of IP, GITHUB_HMAC, or UNAUTHENTICATED"
  default     = "GITHUB_HMAC"
}

variable "webhook_filter_json_path" {
  type        = string
  description = "The JSON path to filter on"
  default     = "$.ref"
}

variable "webhook_filter_match_equals" {
  type        = string
  description = "The value to match on (e.g. refs/heads/{Branch})"
  default     = "refs/heads/{Branch}"
}

variable "authentication_type" {
  type        = string
  description = "Authentication type. Supported values are `COGNITO` and `OIDC`"
  default     = ""
}

variable "authentication_cognito_user_pool_arn" {
  type        = string
  description = "Cognito User Pool ARN"
  default     = ""
}

variable "authentication_cognito_user_pool_client_id" {
  type        = string
  description = "Cognito User Pool Client ID"
  default     = ""
}

variable "authentication_cognito_user_pool_domain" {
  type        = string
  description = "Cognito User Pool Domain. The User Pool Domain should be set to the domain prefix (`xxx`) instead of full domain (https://xxx.auth.us-west-2.amazoncognito.com)"
  default     = ""
}

variable "authentication_oidc_client_id" {
  type        = string
  description = "OIDC Client ID"
  default     = ""
}

variable "authentication_oidc_client_secret" {
  type        = string
  description = "OIDC Client Secret"
  default     = ""
}

variable "authentication_oidc_issuer" {
  type        = string
  description = "OIDC Issuer"
  default     = ""
}

variable "authentication_oidc_authorization_endpoint" {
  type        = string
  description = "OIDC Authorization Endpoint"
  default     = ""
}

variable "authentication_oidc_token_endpoint" {
  type        = string
  description = "OIDC Token Endpoint"
  default     = ""
}

variable "authentication_oidc_user_info_endpoint" {
  type        = string
  description = "OIDC User Info Endpoint"
  default     = ""
}

variable "codepipeline_s3_bucket_force_destroy" {
  type        = bool
  description = "A boolean that indicates all objects should be deleted from the CodePipeline artifact store S3 bucket so that the bucket can be destroyed without error"
  default     = false
}

variable "volumes" {
  type = list(object({
    host_path = string
    name      = string
    docker_volume_configuration = list(object({
      autoprovision = bool
      driver        = string
      driver_opts   = map(string)
      labels        = map(string)
      scope         = string
    }))
  }))
  description = "Task volume definitions as list of configuration objects"
  default     = []
}


variable "init_containers" {
  type = list(object({
    container_definition = any
    condition            = string
  }))
  description = "A list of additional init containers to start. The map contains the container_definition (JSON) and the main container's dependency condition (string) on the init container. The latter can be one of START, COMPLETE, SUCCESS or HEALTHY."
  default     = []
}

//variable "custom_container_definitions" {}

variable "task_cpu" {
  type        = number
  description = "The number of CPU units used by the task. If unspecified, it will default to `container_cpu`. If using `FARGATE` launch type `task_cpu` must match supported memory values (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#task_size)"
  default     = null
}

variable "task_memory" {
  type        = number
  description = "The amount of memory (in MiB) used by the task. If unspecified, it will default to `container_memory`. If using Fargate launch type `task_memory` must match supported cpu value (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#task_size)"
  default     = null
}

variable "build_timeout" {
  type        = number
  default     = 60
  description = "How long in minutes, from 5 to 480 (8 hours), for AWS CodeBuild to wait until timing out any related build that does not get marked as completed"
}

variable "alb_target_group_alarms_alarm_actions" {
  type        = list(string)
  description = "A list of ARNs (i.e. SNS Topic ARN) to execute when ALB Target Group alarms transition into an ALARM state from any other state"
  default     = []
}

variable "alb_target_group_alarms_ok_actions" {
  type        = list(string)
  description = "A list of ARNs (i.e. SNS Topic ARN) to execute when ALB Target Group alarms transition into an OK state from any other state"
  default     = []
}

variable "alb_target_group_alarms_insufficient_data_actions" {
  type        = list(string)
  description = "A list of ARNs (i.e. SNS Topic ARN) to execute when ALB Target Group alarms transition into an INSUFFICIENT_DATA state from any other state"
  default     = []
}

variable "alb_arn_suffix" {
  type        = string
  description = "ARN suffix of the ALB for the Target Group"
  default     = ""
}

variable "ecs_alarms_memory_utilization_low_ok_actions" {
  type        = list(string)
  description = "A list of ARNs (i.e. SNS Topic ARN) to notify on Memory Utilization Low OK action"
  default     = []
}

variable "ecs_alarms_memory_utilization_high_alarm_actions" {
  type        = list(string)
  description = "A list of ARNs (i.e. SNS Topic ARN) to notify on Memory Utilization High Alarm action"
  default     = []
}

variable "ecs_alarms_memory_utilization_high_ok_actions" {
  type        = list(string)
  description = "A list of ARNs (i.e. SNS Topic ARN) to notify on Memory Utilization High OK action"
  default     = []
}

variable "ecs_alarms_memory_utilization_low_alarm_actions" {
  type        = list(string)
  description = "A list of ARNs (i.e. SNS Topic ARN) to notify on Memory Utilization Low Alarm action"
  default     = []
}

variable "ecs_alarms_cpu_utilization_high_alarm_actions" {
  type        = list(string)
  description = "A list of ARNs (i.e. SNS Topic ARN) to notify on CPU Utilization High Alarm action"
  default     = []
}

variable "ecs_alarms_cpu_utilization_high_ok_actions" {
  type        = list(string)
  description = "A list of ARNs (i.e. SNS Topic ARN) to notify on CPU Utilization High OK action"
  default     = []
}

variable "ecs_alarms_cpu_utilization_low_alarm_actions" {
  type        = list(string)
  description = "A list of ARNs (i.e. SNS Topic ARN) to notify on CPU Utilization Low Alarm action"
  default     = []
}

variable "ecs_alarms_cpu_utilization_low_ok_actions" {
  type        = list(string)
  description = "A list of ARNs (i.e. SNS Topic ARN) to notify on CPU Utilization Low OK action"
  default     = []
}


variable "drone-io_enabled" {
  type        = bool
  description = "Determines if should use Drone.io"
  default     = false
}

variable "ecr_namespaces" {
  type        = list(string)
  description = "If provided, will create namespaces for ECR"
  default     = []
}

variable "ecr_enabled" {
  type        = bool
  description = "Determine if ECR should be created (codepipeline_enabled=true also will result creating ECR)"
  default     = false
}

variable "disable_primary_container_definition" {
  type        = bool
  description = "If set true - will prevent using auto generated container definition. In this case you have to provide custom configuration with 'custom_container_definition"
  default     = false
}

variable "custom_container_definition_1" {
  description = ""
  //type = list(object())
  default = []
}

variable "disable_secondary_container_definition" {
  type        = bool
  description = "If set true - will prevent using auto generated container definition. In this case you have to provide custom configuration with 'custom_container_definition"
  default     = false
}

variable "custom_container_definition_2" {
  description = ""
  //type = list(object())
  default = []
}

variable "ignore_changes_task_definition" {
  type = bool
  default = true
  description = "Whether to ignore changes in container definition and task definition in the ECS service"

}