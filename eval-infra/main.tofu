data "aws_vpc" "default" {
  count   = var.vpc_id == "" ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.subnet_id == "" ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [var.vpc_id != "" ? var.vpc_id : data.aws_vpc.default[0].id]
  }
}

resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  name_prefix = "con-unit-eval-${random_id.suffix.hex}"

  resolved_vpc_id    = var.vpc_id != "" ? var.vpc_id : data.aws_vpc.default[0].id
  resolved_subnet_id = var.subnet_id != "" ? var.subnet_id : sort(data.aws_subnets.default[0].ids)[0]

  public_key = trimspace(var.ssh_public_key != "" ? var.ssh_public_key : (fileexists(pathexpand(var.ssh_public_key_path)) ? file(pathexpand(var.ssh_public_key_path)) : ""))

  # AMI selection: explicit variable first, then the per-region pin in amis.json.
  # The aws_ami data sources below only describe the chosen image or, optionally,
  # the newest candidate. They never decide what gets launched.
  ami_catalog   = jsondecode(file("${path.module}/amis.json"))
  pinned_ami_id = try(local.ami_catalog.pins[var.aws_region].ami_id, "")
  ami_id        = var.ami_id != "" ? var.ami_id : local.pinned_ami_id
}

# Description of the AMI that will actually be launched (name and creation date go into the outputs).
# Restricted to the Canonical owner so a mistyped or foreign AMI ID fails at plan time.
data "aws_ami" "selected" {
  count              = local.ami_id != "" ? 1 : 0
  owners             = [local.ami_catalog.owner]
  include_deprecated = true
  most_recent        = false

  filter {
    name   = "image-id"
    values = [local.ami_id]
  }
}

# Discovery only: newest Canonical AMI matching the catalogue pattern.
data "aws_ami" "latest_available" {
  count       = var.discover_latest_ami ? 1 : 0
  owners      = [local.ami_catalog.owner]
  most_recent = true

  filter {
    name   = "name"
    values = [local.ami_catalog.name_pattern]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_key_pair" "eval_key" {
  key_name   = local.name_prefix
  public_key = local.public_key

  lifecycle {
    precondition {
      condition     = local.public_key != ""
      error_message = "No SSH public key found. Set ssh_public_key or point ssh_public_key_path at an existing .pub file."
    }
  }

  tags = {
    Name = local.name_prefix
  }
}

resource "aws_security_group" "eval_sg" {
  name        = local.name_prefix
  description = "ConUnit evaluation: SSH from one operator address, outbound for package, toolchain and registry access"
  vpc_id      = local.resolved_vpc_id

  ingress {
    description = "SSH from the operator"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # Egress stays open. The destinations (Ubuntu mirrors, go.dev, proxy.golang.org,
  # public.ecr.aws) sit behind CDNs with changing addresses. The instance has no IAM
  # role, no credentials and IMDSv2 with hop limit 1, so there is nothing to exfiltrate
  # from the host beyond the public datasets.
  egress {
    description = "Outbound for apt, Go toolchain and module downloads, and the ECR Public mirror"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = local.name_prefix
  }
}

resource "aws_instance" "eval_node" {
  ami                         = local.ami_id
  instance_type               = var.instance_type
  subnet_id                   = local.resolved_subnet_id
  vpc_security_group_ids      = [aws_security_group.eval_sg.id]
  key_name                    = aws_key_pair.eval_key.key_name
  associate_public_ip_address = true

  # The watchdog and a manual `sudo poweroff` must end in termination, not in a
  # stopped instance that keeps its EBS volume and keeps billing.
  instance_initiated_shutdown_behavior = "terminate"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_size           = var.volume_size_gb
    volume_type           = "gp3"
    iops                  = 3000
    throughput            = 125
    delete_on_termination = true
    encrypted             = true
    tags = {
      Name  = "${local.name_prefix}-root"
      RunId = var.run_id
    }
  }

  user_data = templatefile("${path.module}/user_data.sh", {
    run_id               = var.run_id
    benchmark_iterations = var.benchmark_iterations
    auto_shutdown        = var.auto_shutdown
    watchdog_minutes     = var.auto_shutdown_timeout_minutes
  })
  user_data_replace_on_change = true

  lifecycle {
    precondition {
      condition     = local.ami_id != ""
      error_message = "No AMI for region ${var.aws_region}. Pin one with `just pin-ami ${var.aws_region}` or pass -var ami_id=ami-..."
    }
  }

  tags = {
    Name = local.name_prefix
  }
}
