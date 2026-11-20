#!/usr/bin/env bash
# Render user_data.sh through OpenTofu (templatefile) and check the result: valid bash, every
# template variable substituted, no stray template syntax. Needs an initialized working
# directory (tofu init -backend=false) and makes no AWS calls.
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
out="$(mktemp)"
trap 'rm -f "$out"' EXIT

# shellcheck disable=SC2016 # the dollar-brace sequence is OpenTofu syntax, not a shell expansion
expr='templatefile("${path.module}/user_data.sh", { run_id = "render-check", benchmark_iterations = 3, auto_shutdown = true, watchdog_minutes = 90 })'
printf '%s\n' "$expr" |
    tofu console -no-color -var run_id=render-check -var allowed_ssh_cidr=203.0.113.7/32 2> /dev/null |
    awk '/^<<EOT$/ { next } /^EOT$/ { next } { print }' > "$out"

fail=0
check() { # description, command...
    local desc=$1
    shift
    if "$@" > /dev/null 2>&1; then
        printf '  [PASS] %s\n' "$desc"
    else
        printf '  [FAIL] %s\n' "$desc"
        fail=1
    fi
}

echo "rendered user_data.sh: $(wc -l < "$out" | tr -d ' ') lines"
check "valid bash syntax" bash -n "$out"
check "run id substituted" grep -q '^RUN_ID=render-check$' "$out"
check "iterations substituted" grep -q '^BENCHMARK_ITERATIONS=3$' "$out"
check "watchdog minutes substituted" grep -q '^WATCHDOG_MINUTES=90$' "$out"
check "watchdog timer uses 90m" grep -q -- '--on-active="90m"' "$out"
check "curl write-out survived escaping" grep -q "%{http_code}" "$out"
check "no leftover template interpolation" bash -c "! grep -q '[$]{' '$out'"
check "ready marker is written last" bash -c "tail -n 8 '$out' | grep -q '/var/lib/con-unit/ready'"
check "no credential-looking strings" bash -c "! grep -Eqi 'AKIA[0-9A-Z]{16}|aws_secret|password' '$out'"
exit "$fail"
