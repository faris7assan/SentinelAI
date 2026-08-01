# ============================================================
# SentinelAI — Terraform AWS Infrastructure
# EKS + RDS + ElastiCache + MSK + OpenSearch
# ============================================================

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }
  }
  backend "s3" {
    bucket = "sentinelai-tfstate"
    key    = "production/terraform.tfstate"
    region = "us-east-1"
    encrypt = true
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "SentinelAI"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "SecurityTeam"
    }
  }
}

# ─── Variables ───────────────────────────────────────────────
variable "aws_region"     { default = "us-east-1" }
variable "environment"    { default = "production" }
variable "cluster_name"   { default = "sentinelai-eks" }
variable "db_password"    { sensitive = true }
variable "redis_password" { sensitive = true }

locals {
  vpc_cidr = "10.100.0.0/16"
  azs      = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
}

# ─── VPC ─────────────────────────────────────────────────────
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"

  name = "sentinelai-vpc"
  cidr = local.vpc_cidr
  azs  = local.azs

  private_subnets  = ["10.100.1.0/24", "10.100.2.0/24", "10.100.3.0/24"]
  public_subnets   = ["10.100.11.0/24", "10.100.12.0/24", "10.100.13.0/24"]
  database_subnets = ["10.100.21.0/24", "10.100.22.0/24", "10.100.23.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = false  # HA: one per AZ
  enable_vpn_gateway     = false
  enable_dns_hostnames   = true
  enable_dns_support     = true
  create_database_subnet_group = true

  private_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"           = "1"
  }
  public_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                    = "1"
  }
}

# ─── EKS Cluster ─────────────────────────────────────────────
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"

  cluster_name    = var.cluster_name
  cluster_version = "1.29"

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true

  cluster_addons = {
    coredns = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni = { most_recent = true }
    aws-ebs-csi-driver = { most_recent = true }
  }

  eks_managed_node_groups = {
    # General workload nodes
    general = {
      name           = "general"
      instance_types = ["m5.xlarge"]
      min_size       = 2
      max_size       = 10
      desired_size   = 3
      disk_size      = 100
      labels = { role = "general" }
    }

    # AI/ML nodes (higher CPU for inference)
    ai_nodes = {
      name           = "ai-nodes"
      instance_types = ["c5.2xlarge"]
      min_size       = 1
      max_size       = 5
      desired_size   = 2
      disk_size      = 200
      labels = { role = "ai" }
      taints = [{
        key    = "ai-workload"
        value  = "true"
        effect = "NO_SCHEDULE"
      }]
    }
  }

  # AWS Auth ConfigMap
  manage_aws_auth_configmap = true
}

# ─── RDS PostgreSQL ──────────────────────────────────────────
resource "aws_db_subnet_group" "sentinelai" {
  name       = "sentinelai-db"
  subnet_ids = module.vpc.database_subnets
}

resource "aws_security_group" "rds" {
  name   = "sentinelai-rds-sg"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }
}

resource "aws_db_instance" "sentinelai" {
  identifier              = "sentinelai-db"
  engine                  = "postgres"
  engine_version          = "16.2"
  instance_class          = "db.t3.large"
  allocated_storage       = 100
  max_allocated_storage   = 500
  storage_encrypted       = true
  storage_type            = "gp3"

  db_name  = "sentinelai"
  username = "sentinelai"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.sentinelai.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  multi_az               = true
  backup_retention_period = 14
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
  deletion_protection     = true
  skip_final_snapshot     = false
  final_snapshot_identifier = "sentinelai-final"

  performance_insights_enabled = true
  monitoring_interval          = 60
}

# ─── ElastiCache Redis ───────────────────────────────────────
resource "aws_security_group" "redis" {
  name   = "sentinelai-redis-sg"
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }
}

resource "aws_elasticache_subnet_group" "sentinelai" {
  name       = "sentinelai-redis"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_replication_group" "sentinelai" {
  replication_group_id       = "sentinelai-redis"
  description                = "SentinelAI Redis cluster"
  node_type                  = "cache.r6g.large"
  num_cache_clusters         = 3
  port                       = 6379
  parameter_group_name       = "default.redis7"
  automatic_failover_enabled = true
  multi_az_enabled           = true
  subnet_group_name          = aws_elasticache_subnet_group.sentinelai.name
  security_group_ids         = [aws_security_group.redis.id]
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = var.redis_password
}

# ─── Amazon OpenSearch ───────────────────────────────────────
resource "aws_security_group" "opensearch" {
  name   = "sentinelai-opensearch-sg"
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }
}

resource "aws_opensearch_domain" "sentinelai" {
  domain_name    = "sentinelai-logs"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type          = "r6g.large.search"
    instance_count         = 3
    zone_awareness_enabled = true
    zone_awareness_config {
      availability_zone_count = 3
    }
    dedicated_master_enabled = true
    dedicated_master_type    = "c6g.large.search"
    dedicated_master_count   = 3
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 200
    volume_type = "gp3"
    throughput  = 250
  }

  encrypt_at_rest       { enabled = true }
  node_to_node_encryption { enabled = true }
  domain_endpoint_options { enforce_https = true; tls_security_policy = "Policy-Min-TLS-1-2-2019-07" }

  vpc_options {
    subnet_ids         = slice(module.vpc.private_subnets, 0, 3)
    security_group_ids = [aws_security_group.opensearch.id]
  }

  advanced_security_options {
    enabled                        = true
    anonymous_auth_enabled         = false
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = "admin"
      master_user_password = var.db_password
    }
  }
}

# ─── Amazon MSK (Kafka) ──────────────────────────────────────
resource "aws_security_group" "kafka" {
  name   = "sentinelai-kafka-sg"
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port   = 9092
    to_port     = 9092
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }
  ingress {
    from_port   = 9094
    to_port     = 9094
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }
}

resource "aws_msk_cluster" "sentinelai" {
  cluster_name           = "sentinelai-kafka"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type  = "kafka.m5.large"
    client_subnets = module.vpc.private_subnets
    storage_info {
      ebs_storage_info { volume_size = 200 }
    }
    security_groups = [aws_security_group.kafka.id]
  }

  encryption_info {
    encryption_in_transit { client_broker = "TLS" }
    encryption_at_rest { data_volume_kms_key_id = aws_kms_key.sentinelai.arn }
  }

  open_monitoring {
    prometheus {
      jmx_exporter  { enabled_in_broker = true }
      node_exporter { enabled_in_broker = true }
    }
  }
}

# ─── KMS Key ─────────────────────────────────────────────────
resource "aws_kms_key" "sentinelai" {
  description             = "SentinelAI encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "sentinelai" {
  name          = "alias/sentinelai"
  target_key_id = aws_kms_key.sentinelai.key_id
}

# ─── Outputs ─────────────────────────────────────────────────
output "eks_cluster_endpoint"    { value = module.eks.cluster_endpoint }
output "eks_cluster_name"        { value = module.eks.cluster_name }
output "rds_endpoint"            { value = aws_db_instance.sentinelai.endpoint }
output "redis_endpoint"          { value = aws_elasticache_replication_group.sentinelai.primary_endpoint_address }
output "opensearch_endpoint"     { value = aws_opensearch_domain.sentinelai.endpoint }
output "kafka_bootstrap_brokers" { value = aws_msk_cluster.sentinelai.bootstrap_brokers_tls }
