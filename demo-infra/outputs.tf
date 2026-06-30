output "alb_arn" {
  description = "ARN of the demo ALB — use this with Cryptiq's /aws/alb-listeners"
  value       = aws_lb.demo.arn
}

output "alb_name" {
  description = "Name of the demo ALB"
  value       = aws_lb.demo.name
}

output "listener_arn" {
  description = "ARN of the HTTPS listener (the migration target)"
  value       = aws_lb_listener.https.arn
}

output "current_ssl_policy" {
  description = "Current ssl_policy — should be classical before migration"
  value       = aws_lb_listener.https.ssl_policy
}
