#!/usr/bin/env bash
# Offline test of the pure logic in remote_eval.sh: argument validation, dataset helpers,
# the status file and the final result classification. Needs bash, jq, awk and sha256sum or
# shasum. It never touches AWS, apt, podman or /opt.
#
# Usage: bash eval-infra/tests/test_remote_eval.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../remote_eval.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
check() { # description, expected, actual
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
        printf '  [PASS] %s\n' "$1"
    else
        fail=$((fail + 1))
        printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"
    fi
}

# Library view of the script: everything except the final "main" call.
sed '$d' "$SCRIPT" > "$WORK/lib.sh"

# sha256sum is not available on stock macOS
if ! command -v sha256sum > /dev/null; then
    sha256sum() { shasum -a 256 "$@"; }
fi

run_in_harness() { # bash snippet executed after sourcing the library
    CONUNIT_BASE_DIR="$WORK/base" bash -c '
        set -uo pipefail
        sha256sum() { if command -v sha256sum >/dev/null; then command sha256sum "$@"; else shasum -a 256 "$@"; fi; }
        # shellcheck disable=SC1091
        . "$1"
        set +e # the sourced library enables errexit, the assertions below read exit codes
        fix_ownership() { :; }
        shift
        eval "$1"
    ' _ "$WORK/lib.sh" "$1"
}

echo "== argument validation"
good=(--run-id r1 --commit abcdef1 --bundle-sha256 "$(printf 'a%.0s' {1..64})")
rc_of() { run_in_harness "parse_args $*; validate_args" > /dev/null 2>&1; echo $?; }
check "valid minimal arguments (eval and export need no external tool)" 0 "$(rc_of "${good[*]} --stages eval,export")"
check "the default stages include rq3, which needs dockle, so they need the lock hash" 2 "$(rc_of "${good[*]}")"
check "the default stages are valid with the lock hash" 0 "$(rc_of "${good[*]} --tools-lock-sha256 $(printf 'b%.0s' {1..64})")"
check "unknown stage rejected" 2 "$(rc_of "${good[*]} --stages eval,bogus")"
check "bad mode rejected" 2 "$(rc_of "${good[*]} --mode docker")"
check "dataset with parent path rejected" 2 "$(rc_of "${good[*]} --dataset ../etc/passwd")"
check "absolute dataset rejected" 2 "$(rc_of "${good[*]} --dataset /etc/passwd")"
check "short bundle sha rejected" 2 "$(rc_of "--run-id r1 --commit abcdef1 --bundle-sha256 abc")"
check "run id with slash rejected" 2 "$(rc_of "--run-id a/b --commit abcdef1 --bundle-sha256 ${good[5]}")"
check "canary and rootless accepted" 0 "$(rc_of "${good[*]} --canary 3 --mode rootless --stages eval,export")"
lock_sha="$(printf 'b%.0s' {1..64})"
check "every stage is accepted" 0 "$(rc_of "${good[*]} --stages eval,export,rq3,rq1,lint,crosscheck,attribute,ablate,reliability --tools-lock-sha256 $lock_sha")"
check "run A stages are accepted with the lock hash" 0 "$(rc_of "${good[*]} --stages eval,export,rq3,rq1,lint,crosscheck --tools-lock-sha256 $lock_sha")"
check "run B stages are accepted without a lock hash, they need no tool" 0 "$(rc_of "${good[*]} --stages eval,export,attribute,ablate,reliability")"
check "lint alone needs no lock hash" 0 "$(rc_of "${good[*]} --stages lint")"
check "run A stages without the lock hash are refused" 2 "$(rc_of "${good[*]} --stages eval,export,rq3,rq1,lint,crosscheck")"
check "rq3 alone without the lock hash is refused, it needs dockle" 2 "$(rc_of "${good[*]} --stages rq3")"
check "crosscheck alone without the lock hash is refused" 2 "$(rc_of "${good[*]} --stages crosscheck")"
check "a lock hash of the wrong length is refused" 2 "$(rc_of "${good[*]} --stages crosscheck --tools-lock-sha256 abc")"
check "a lock hash with upper case letters is refused" 2 "$(rc_of "${good[*]} --stages crosscheck --tools-lock-sha256 $(printf 'B%.0s' {1..64})")"
check "a malformed lock hash is refused even when no tool is needed" 2 "$(rc_of "${good[*]} --stages eval --tools-lock-sha256 abc")"
check "--rq1-cases 4 is accepted" 0 "$(rc_of "${good[*]} --stages eval --rq1-cases 4")"
check "--rq1-cases 0 means all cases and is accepted" 0 "$(rc_of "${good[*]} --stages eval --rq1-cases 0")"
check "--rq1-cases abc is refused" 2 "$(rc_of "${good[*]} --stages eval --rq1-cases abc")"
check "--rq1-cases -1 is refused" 2 "$(rc_of "${good[*]} --stages eval --rq1-cases -1")"
check "a stage name that is only a prefix is refused" 2 "$(rc_of "${good[*]} --stages eval,rq")"
check "an empty --stages is refused" yes "$([ "$(rc_of "${good[*]} --stages ''")" != 0 ] && echo yes || echo no)"

echo "== dataset helpers"
cat > "$WORK/ds.txt" <<'EOF'
# header
# another comment

index.docker.io/library/nginx@sha256:aaaa
   
index.docker.io/library/busybox@sha256:bbbb
# trailing comment
index.docker.io/library/alpine@sha256:cccc
EOF
printf '# only comments\n\n' > "$WORK/empty.txt"
check "count_images counts image lines" 3 "$(run_in_harness "count_images $WORK/ds.txt")"
check "count_images on comment-only file" 0 "$(run_in_harness "count_images $WORK/empty.txt")"
check "image_lines on comment-only file keeps exit 0" 0 "$(run_in_harness "image_lines $WORK/empty.txt > /dev/null; echo \$?")"
check "canary derivation takes first N image lines" \
    "index.docker.io/library/nginx@sha256:aaaa|index.docker.io/library/busybox@sha256:bbbb" \
    "$(run_in_harness "image_lines $WORK/ds.txt | awk -v n=2 'NR <= n' | paste -sd '|' -")"

echo "== package pre-check"
# apt-cache, apt_run and dpkg are replaced by functions. The point is the order: every name is
# checked first, and a missing name stops the run before any install is attempted.
snippet=$(cat <<'EOS'
PACKAGES=(podman fakeone faketwo)
apt_run() { echo "apt_run $*"; }
apt-cache() { case "$3" in fakeone | faketwo) return 100 ;; *) return 0 ;; esac; }
dpkg() { return 0; }
install_packages
EOS
)
out=$(run_in_harness "$snippet" 2>&1)
rc=$?
check "unknown package names stop the run" 1 "$rc"
check "all missing names are reported at once" yes "$(case "$out" in *'fakeone faketwo'*) echo yes ;; *) echo no ;; esac)"
check "the existing name is not reported" no "$(case "$out" in *'release: podman'*) echo yes ;; *) echo no ;; esac)"
check "nothing is installed after a failed check" no "$(case "$out" in *'apt_run install'*) echo yes ;; *) echo no ;; esac)"
snippet=${snippet/PACKAGES=(podman fakeone faketwo)/PACKAGES=(podman crun)}
out=$(run_in_harness "$snippet" 2>&1)
rc=$?
check "known names pass the check" 0 "$rc"
check "known names are installed in one call" yes "$(case "$out" in *'apt_run install -y podman crun'*) echo yes ;; *) echo no ;; esac)"
snippet=$(cat <<'EOS'
printf '%s\n' "${PACKAGES[@]}"
EOS
)
check "the pinned package list does not contain containers-common (absent on Ubuntu 24.04)" 0 "$(run_in_harness "$snippet" | grep -cx containers-common)"

echo "== registry remap reaches the tool"
remap='docker.io/library -> public.ecr.aws/docker/library'
check "rootless branch hands the remap to the command" "$remap" "$(run_in_harness 'MODE=rootless; engine_user printenv CONUNIT_REGISTRY_REMAP')"
# sudo is replaced by a function that drops its two flags and runs the rest, which is env with
# the remap argument. That is the part that has to survive sudo's environment reset.
check "rootful branch hands the remap to the command" "$remap" "$(run_in_harness 'MODE=rootful; sudo() { shift 2; "$@"; }; engine_user printenv CONUNIT_REGISTRY_REMAP')"

echo "== status file and result classification"
# scenario <name> <expected-result> <expected-code> <stage-spec>...
# stage-spec: name:state:exit
scenario() {
    local name=$1 want_result=$2 want_code=$3 requested=$4
    shift 4
    local specs="$*"
    local out
    out=$(run_in_harness "
        RUN_ID=t; COMMIT=abcdef1; STAGES='$requested'
        RESULTS_DIR='$WORK/res-$name'; STATUS_FILE=\$RESULTS_DIR/status.json
        mkdir -p \"\$RESULTS_DIR/host\"
        status_init
        for spec in $specs; do
            IFS=: read -r n s c <<< \"\$spec\"
            stage_begin \"\$n\"; stage_end \"\$n\" \"\$s\" \"\$c\"
        done
        finalize > /dev/null 2>&1; code=\$?
        printf '%s %s %s' \"\$(jq -r .result \$STATUS_FILE)\" \"\$code\" \"\$(test -f \$RESULTS_DIR/BENCHMARK_COMPLETE && echo marker || echo nomarker)\"
    ")
    check "scenario $name" "$want_result $want_code marker" "$out"
}
scenario all-ok complete 0 eval,export,rq3 eval:ok:0 export:ok:0 rq3:ok:0
scenario eval-incomplete incomplete 3 eval,export,rq3 eval:incomplete:3 export:ok:0 rq3:ok:0
scenario export-failed failed 1 eval,export,rq3 eval:ok:0 export:failed:1 rq3:ok:0
scenario eval-incomplete-export-failed failed 1 eval,export,rq3 eval:incomplete:3 export:failed:66 rq3:ok:0
scenario requested-stage-missing failed 1 eval,export,rq3 eval:ok:0 export:ok:0
scenario subset-ok complete 0 eval,export eval:ok:0 export:ok:0
scenario rq3-only complete 0 rq3 rq3:ok:0
scenario run-a-ok complete 0 eval,export,rq3,rq1,lint,crosscheck eval:ok:0 export:ok:0 rq3:ok:0 rq1:ok:0 lint:ok:0 crosscheck:ok:0
scenario run-b-ok complete 0 eval,export,attribute,ablate,reliability eval:ok:0 export:ok:0 attribute:ok:0 ablate:ok:0 reliability:ok:0
scenario attribute-incomplete incomplete 3 eval,export,attribute,ablate,reliability eval:ok:0 export:ok:0 attribute:incomplete:3 ablate:ok:0 reliability:ok:0
scenario reliability-incomplete incomplete 3 eval,reliability eval:ok:0 reliability:incomplete:3
scenario crosscheck-guard-failed failed 1 eval,lint,crosscheck eval:ok:0 lint:ok:0 crosscheck:failed:127
scenario rq1-failed-and-attribute-incomplete failed 1 eval,rq1,attribute eval:ok:0 rq1:failed:1 attribute:incomplete:3
scenario requested-new-stage-missing failed 1 eval,lint,crosscheck eval:ok:0 lint:ok:0
scenario tools-prerequisite-failed failed 1 eval,rq1 eval:ok:0 rq1:ok:0 tools:failed:1

echo "== finalize writes consistent checksums and marker"
out=$(run_in_harness "
    RUN_ID=t; COMMIT=abcdef1; STAGES='eval'
    RESULTS_DIR='$WORK/res-sums'; STATUS_FILE=\$RESULTS_DIR/status.json
    mkdir -p \"\$RESULTS_DIR/host\"; echo data > \$RESULTS_DIR/empirical_study.json; echo log > \$RESULTS_DIR/remote_eval.log
    status_init; stage_begin eval; stage_end eval ok 0
    finalize > /dev/null 2>&1
    cd \$RESULTS_DIR
    if command -v sha256sum >/dev/null; then sha256sum -c REMOTE_SHA256SUMS >/dev/null 2>&1; else shasum -a 256 -c REMOTE_SHA256SUMS >/dev/null 2>&1; fi; echo \$?
    grep -c remote_eval.log REMOTE_SHA256SUMS; grep -c BENCHMARK_COMPLETE REMOTE_SHA256SUMS
")
check "checksums verify, log and marker excluded" "0 0 0" "$(echo "$out" | tr '\n' ' ' | sed 's/ $//')"
check "marker contains the status JSON" "complete" "$(jq -r .result "$WORK/res-sums/BENCHMARK_COMPLETE")"

echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
