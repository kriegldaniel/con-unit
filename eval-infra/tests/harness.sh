#!/usr/bin/env bash
# Shared helpers of the offline tests that call functions of remote_eval.sh. Source it, do not run it.
#
#   HERE=...; . "$HERE/harness.sh"
#
# Provides: WORK (a temporary directory, removed on exit), check, run_in_harness, finish.
# run_in_harness executes a bash snippet after sourcing everything of remote_eval.sh except the final
# "main" call, with CONUNIT_BASE_DIR and CONUNIT_TOOLS_BIN_DIR pointing into WORK. Nothing touches AWS,
# apt, podman or /opt.

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

mkdir -p "$WORK/base" "$WORK/bin"

run_in_harness() { # bash snippet executed after sourcing the library
    CONUNIT_BASE_DIR="$WORK/base" CONUNIT_TOOLS_BIN_DIR="$WORK/bin" bash -c '
        set -uo pipefail
        sha256sum() { if command -v sha256sum > /dev/null; then command sha256sum "$@"; else shasum -a 256 "$@"; fi; }
        # shellcheck disable=SC1090
        . "$1"
        set +e # the sourced library enables errexit, the assertions below read exit codes
        fix_ownership() { :; }
        shift
        eval "$1"
    ' _ "$WORK/lib.sh" "$1"
}

finish() {
    echo
    printf 'passed %d, failed %d\n' "$pass" "$fail"
    [ "$fail" -eq 0 ]
}
