#!/bin/bash
# ConUnit evaluation node bootstrap. Rendered by OpenTofu (templatefile), runs once as root at first boot.
#
# Scope is deliberately small. Everything that shapes the measurement (container runtime,
# Go toolchain, registry mirror, tool build) is installed by remote_eval.sh so that it is
# versioned with the evaluation and recorded in the results bundle.
#
# Template notes: sequences that start with a dollar sign and a brace belong to OpenTofu.
# Shell variables below therefore use the plain $NAME form, and the curl write-out format
# is escaped as a doubled percent sign.
#
# No credentials are written anywhere. The instance has no IAM role.
set -euo pipefail

LOG=/var/log/con-unit-userdata.log
exec > >(tee -a "$LOG") 2>&1

stamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
info() { echo "$(stamp) [INFO ] $*"; }
ok() { echo "$(stamp) [ OK  ] $*"; }
fail() {
    echo "$(stamp) [FAIL ] $*" >&2
    exit 1
}

info "ConUnit evaluation node bootstrap, run id ${run_id}"
export DEBIAN_FRONTEND=noninteractive

# 1. Run configuration for remote_eval.sh. Plain KEY=VALUE, safe to source.
install -d -m 0755 /etc/con-unit
cat > /etc/con-unit/run.env <<'EOF'
RUN_ID=${run_id}
BENCHMARK_ITERATIONS=${benchmark_iterations}
WATCHDOG_MINUTES=${watchdog_minutes}
EOF
chmod 0644 /etc/con-unit/run.env
ok "wrote /etc/con-unit/run.env"

# 2. Safety watchdog. A transient systemd timer powers the node off after the timeout.
#    EC2 instance_initiated_shutdown_behavior is set to terminate in OpenTofu, so the
#    poweroff ends in termination and the root volume is deleted with the instance.
#    Disarm for debugging with: sudo systemctl stop con-unit-watchdog.timer
if [ "${auto_shutdown}" = "true" ]; then
    systemd-run --unit=con-unit-watchdog \
        --description="ConUnit evaluation safety watchdog (terminates the instance)" \
        --on-active="${watchdog_minutes}m" \
        --timer-property=AccuracySec=10s \
        /usr/bin/systemctl poweroff
    ok "watchdog armed: poweroff in ${watchdog_minutes} minutes"
else
    info "watchdog disabled by configuration (auto_shutdown = false)"
fi

# 3. Bootstrap packages needed by the transfer and status tooling. apt can be busy right after
#    boot, so wait for the dpkg lock and retry a few times.
apt_retry() {
    local attempt
    for attempt in 1 2 3 4 5 6; do
        if apt-get -o DPkg::Lock::Timeout=300 "$@"; then
            return 0
        fi
        info "apt-get $1 failed, attempt $attempt of 6"
        sleep 20
    done
    return 1
}
info "updating package index"
apt_retry update -y || fail "apt-get update failed"
apt_retry install -y ca-certificates curl jq rsync || fail "apt-get install failed"
ok "package index updated, bootstrap packages installed"

# 4. Lingering lets rootless Podman sensitivity runs use a user systemd instance
#    without an interactive login.
loginctl enable-linger ubuntu
ok "lingering enabled for user ubuntu"

# 5. Working directories owned by the SSH user.
install -d -o ubuntu -g ubuntu -m 0755 /opt/con-unit /opt/con-unit/incoming /opt/con-unit/results
install -d -m 0755 /var/lib/con-unit

# 6. Smoke checks. The ready marker is written only if all of them pass.
info "running smoke checks"

if [ "${auto_shutdown}" = "true" ]; then
    [ "$(systemctl is-active con-unit-watchdog.timer)" = "active" ] || fail "smoke: watchdog timer is not active"
    ok "smoke: watchdog timer active"
fi

[ -e /var/lib/systemd/linger/ubuntu ] || fail "smoke: lingering not enabled for ubuntu"
ok "smoke: lingering enabled"

sudo -u ubuntu test -w /opt/con-unit/results || fail "smoke: results directory not writable by ubuntu"
ok "smoke: results directory writable"

TOKEN="$(curl -fsS -m 5 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)" ||
    fail "smoke: IMDSv2 token request failed"
curl -fsS -m 5 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id > /dev/null ||
    fail "smoke: IMDSv2 metadata request failed"
ok "smoke: IMDSv2 reachable"

# Reachability of the services the run depends on. Any HTTP response proves the path works,
# the ECR Public endpoint answers an anonymous probe with 401 by design.
for url in https://public.ecr.aws/v2/ https://go.dev/dl/ https://proxy.golang.org/; do
    code="$(curl -sS -m 20 -o /dev/null -w '%%{http_code}' "$url")" || fail "smoke: cannot reach $url"
    [ "$code" != "000" ] || fail "smoke: no HTTP response from $url"
    ok "smoke: $url answered HTTP $code"
done

ok "all smoke checks passed"
{
    echo "ready_at=$(stamp)"
    echo "run_id=${run_id}"
} > /var/lib/con-unit/ready
info "bootstrap complete, ready marker written at /var/lib/con-unit/ready"
