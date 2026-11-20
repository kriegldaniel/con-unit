variable "aws_region" {
  description = "AWS Region for the evaluation deployment."
  type        = string
  default     = "eu-central-1"
}

variable "run_id" {
  description = "Unique run identifier. Used for the RunId tag on every resource and for the results directory name."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$", var.run_id))
    error_message = "run_id must be 1 to 48 characters of letters, digits, dot, underscore or hyphen and must start with a letter or digit."
  }
}

variable "vpc_id" {
  description = "Optional custom VPC ID. If blank, the default VPC is discovered."
  type        = string
  default     = ""
}

variable "subnet_id" {
  description = "Optional custom subnet ID. If blank, the lexicographically first subnet of the VPC is used."
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "EC2 instance type. Must be an x86_64 type listed in locals.hourly_usd_us_east_1. c6i.metal is intended for the RQ3 timing run only."
  type        = string
  default     = "c6i.2xlarge"

  validation {
    condition     = contains(["c6i.xlarge", "c6i.2xlarge", "c6i.4xlarge", "c6i.8xlarge", "c6i.metal"], var.instance_type)
    error_message = "instance_type must be one of c6i.xlarge, c6i.2xlarge, c6i.4xlarge, c6i.8xlarge, c6i.metal (the evaluation is pinned to linux/amd64)."
  }
}

variable "volume_size_gb" {
  description = "Root EBS gp3 volume size in GB. Holds the container image store for the 100 image dataset."
  type        = number
  default     = 150

  validation {
    condition     = var.volume_size_gb >= 50 && var.volume_size_gb <= 1000
    error_message = "volume_size_gb must be between 50 and 1000."
  }
}

variable "ami_id" {
  description = "Explicit AMI ID. If blank, the pin for aws_region in amis.json is used (see just pin-ami)."
  type        = string
  default     = ""

  validation {
    condition     = var.ami_id == "" || can(regex("^ami-[0-9a-f]{8,17}$", var.ami_id))
    error_message = "ami_id must be empty or look like ami-0123456789abcdef0."
  }
}

variable "discover_latest_ami" {
  description = "Also look up the newest Canonical AMI and show it in the outputs. Discovery only, never used to launch."
  type        = bool
  default     = false
}

variable "ssh_public_key" {
  description = "Literal public SSH key content. If blank, ssh_public_key_path is read."
  type        = string
  default     = ""
}

variable "ssh_public_key_path" {
  description = "Path to the public SSH key file."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "ssh_private_key_path" {
  description = "Path to the matching private key. Only used to render the ssh and rsync commands in the outputs."
  type        = string
  default     = "~/.ssh/id_ed25519"
}

variable "allowed_ssh_cidr" {
  description = "CIDR permitted to reach SSH. Required. Use the caller's public address as a /32. 0.0.0.0/0 and networks wider than /16 are rejected."
  type        = string

  validation {
    condition     = can(cidrhost(var.allowed_ssh_cidr, 0)) && try(tonumber(split("/", var.allowed_ssh_cidr)[1]) >= 16, false)
    error_message = "allowed_ssh_cidr must be a valid IPv4 CIDR no wider than /16, for example 203.0.113.7/32."
  }
}

variable "benchmark_iterations" {
  description = "Timed trials per image for the RQ3 benchmark. Written to /etc/con-unit/run.env and used as the default of remote_eval.sh."
  type        = number
  default     = 10

  validation {
    condition     = var.benchmark_iterations >= 1 && var.benchmark_iterations <= 100
    error_message = "benchmark_iterations must be between 1 and 100."
  }
}

variable "auto_shutdown" {
  description = "Arm the safety watchdog. When it fires the instance powers off and, because instance_initiated_shutdown_behavior is terminate, is terminated."
  type        = bool
  default     = true
}

variable "auto_shutdown_timeout_minutes" {
  description = "Minutes after boot at which the watchdog terminates the instance regardless of progress."
  type        = number
  default     = 360

  validation {
    condition     = var.auto_shutdown_timeout_minutes >= 30 && var.auto_shutdown_timeout_minutes <= 1440
    error_message = "auto_shutdown_timeout_minutes must be between 30 and 1440."
  }
}
