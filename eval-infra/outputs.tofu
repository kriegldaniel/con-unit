locals {
  # On-demand list prices in USD per hour for us-east-1. Other regions differ,
  # eu-central-1 is typically 10 to 15 percent higher. Reference values only.
  hourly_usd_us_east_1 = {
    "c6i.xlarge"  = 0.17
    "c6i.2xlarge" = 0.34
    "c6i.4xlarge" = 0.68
    "c6i.8xlarge" = 1.36
    "c6i.metal"   = 5.44
  }
  ebs_usd_per_gb_month = 0.08 # gp3, us-east-1

  compute_hourly_usd = local.hourly_usd_us_east_1[var.instance_type]
  ebs_hourly_usd     = var.volume_size_gb * local.ebs_usd_per_gb_month / 730
  watchdog_hours     = var.auto_shutdown_timeout_minutes / 60
  cost_upper_bound   = (local.compute_hourly_usd + local.ebs_hourly_usd) * local.watchdog_hours

  ssh_key = var.ssh_private_key_path
}

output "run_id" {
  description = "Run identifier carried in the RunId tag of every resource."
  value       = var.run_id
}

output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.eval_node.id
}

output "public_ip" {
  description = "Public IPv4 address of the evaluation node."
  value       = aws_instance.eval_node.public_ip
}

output "availability_zone" {
  description = "Availability zone of the evaluation node."
  value       = aws_instance.eval_node.availability_zone
}

output "region" {
  description = "AWS region of the deployment."
  value       = var.aws_region
}

output "instance_type" {
  description = "EC2 instance type."
  value       = var.instance_type
}

output "ami_id" {
  description = "AMI that was launched."
  value       = local.ami_id
}

output "ami_name" {
  description = "Name of the launched AMI."
  value       = try(data.aws_ami.selected[0].name, null)
}

output "ami_creation_date" {
  description = "Creation date of the launched AMI."
  value       = try(data.aws_ami.selected[0].creation_date, null)
}

output "ami_deprecation_time" {
  description = "Deprecation time of the launched AMI, if Canonical has deprecated it. Deprecated AMIs still launch."
  value       = try(data.aws_ami.selected[0].deprecation_time, null)
}

output "latest_available_ami" {
  description = "Newest Canonical AMI matching the catalogue pattern. Only set when discover_latest_ami is true. Informational."
  value = var.discover_latest_ami ? {
    id            = data.aws_ami.latest_available[0].id
    name          = data.aws_ami.latest_available[0].name
    creation_date = data.aws_ami.latest_available[0].creation_date
  } : null
}

output "ssh_command" {
  description = "SSH connection string for the evaluation node."
  value       = "ssh -i ${local.ssh_key} ubuntu@${aws_instance.eval_node.public_ip}"
}

output "tail_log_command" {
  description = "Command to follow the remote evaluation log."
  value       = "ssh -i ${local.ssh_key} ubuntu@${aws_instance.eval_node.public_ip} 'tail -f /opt/con-unit/results/${var.run_id}/remote_eval.log'"
}

output "download_results_command" {
  description = "rsync command to fetch the results directory of this run."
  value       = "rsync -a -e 'ssh -i ${local.ssh_key}' ubuntu@${aws_instance.eval_node.public_ip}:/opt/con-unit/results/${var.run_id}/ ./results/${var.run_id}/"
}

output "estimated_cost" {
  description = "Approximate cost upper bound until the watchdog fires. Computed from instance type, volume size and watchdog timeout using us-east-1 on-demand reference prices."
  value = format(
    "approx. %.2f USD per hour compute plus %.3f USD per hour for %d GB gp3 (us-east-1 on-demand reference prices, other regions differ). Upper bound until the %d minute watchdog: approx. %.2f USD.",
    local.compute_hourly_usd,
    local.ebs_hourly_usd,
    var.volume_size_gb,
    var.auto_shutdown_timeout_minutes,
    local.cost_upper_bound,
  )
}
