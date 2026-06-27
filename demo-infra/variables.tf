variable "aws_region" {
  description = "AWS region for the demo ALB"
  type        = string
  default     = "us-east-1"
}

variable "ssl_policy" {
  description = "TLS security policy for the HTTPS listener. Set explicitly so a plan diff is visible when migrating."
  type        = string
  # VERIFY: Confirm this is still a valid classical policy name before use:
  # https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
  default = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "project_tag" {
  description = "Tag applied to all resources for easy teardown."
  type        = string
  default     = "cryptiq-pqc-demo"
}
