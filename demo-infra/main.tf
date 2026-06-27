terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.5"
}

provider "aws" {
  region = var.aws_region
}

# ── Self-signed cert (demo only — do NOT use in production) ──────────────────

resource "tls_private_key" "demo" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "demo" {
  private_key_pem = tls_private_key.demo.private_key_pem

  subject {
    common_name  = "cryptiq-demo.example.com"
    organization = "Cryptiq Demo"
  }

  validity_period_hours = 8760 # 1 year

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "aws_acm_certificate" "demo" {
  private_key      = tls_private_key.demo.private_key_pem
  certificate_body = tls_self_signed_cert.demo.cert_pem

  tags = {
    Project     = var.project_tag
    Environment = "staging"
    ManagedBy   = "cryptiq-demo"
  }
}

# ── Networking (default VPC) ──────────────────────────────────────────────────

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "alb" {
  name        = "${var.project_tag}-alb-sg"
  description = "Allow HTTPS inbound for Cryptiq demo ALB"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project = var.project_tag
  }
}

# ── ALB ───────────────────────────────────────────────────────────────────────

resource "aws_lb" "demo" {
  name               = "${var.project_tag}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.default.ids

  tags = {
    Project     = var.project_tag
    Environment = "staging"
    ManagedBy   = "cryptiq-demo"
  }
}

resource "aws_lb_target_group" "demo" {
  name        = "${var.project_tag}-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.default.id
  target_type = "ip"

  health_check {
    path    = "/"
    matcher = "200-404"
  }

  tags = {
    Project = var.project_tag
  }
}

# ── HTTPS Listener (the thing Cryptiq will migrate) ───────────────────────────
#
# ssl_policy is set EXPLICITLY so that:
#   1. Cryptiq discovery can read it via DescribeListeners.
#   2. A `terraform plan` produces a visible one-line diff when migrating.
#
# VERIFY: "ELBSecurityPolicy-TLS13-1-2-2021-06" is the intended classical
# policy — confirm it still exists before using:
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.demo.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = aws_acm_certificate.demo.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.demo.arn
  }

  tags = {
    Project     = var.project_tag
    Environment = "staging"
    ManagedBy   = "cryptiq-demo"
  }
}
