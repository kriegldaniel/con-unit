#!/usr/bin/env bash
# Offline test of the justfile: the recipes of the two final runs (stages, run ids, watchdog, the
# pass-through of extra arguments), the canary recipe, and that `just validate` runs every test file.
# It only asks just to print the commands (--dry-run), nothing is executed and nothing touches AWS.
#
# Usage: bash eval-infra/tests/test_justfile.sh   (needs just)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA="$(cd "$HERE/.." && pwd)"
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

command -v just > /dev/null || {
    echo "just is not installed, enter the dev shell (nix develop ./eval-infra)" >&2
    exit 2
}

# The command line that a recipe would run. Extra environment goes in front of the call.
dry() { (cd "$INFRA" && env "$@" 2>&1 > /dev/null | grep 'run_eval.sh'); }
opt() { printf '%s\n' "$1" | sed -n "s/.*--$2 \([^ ]*\).*/\1/p"; } # value of one option in a printed command

echo "== final-a and final-b"
A="$(dry just --dry-run final-a)"
B="$(dry just --dry-run final-b)"
check "final-a stages" "eval,export,rq3,rq1,lint,crosscheck" "$(opt "$A" stages)"
check "final-b stages" "eval,export,attribute,ablate,reliability" "$(opt "$B" stages)"
check "final-a run id" "eval-v1-a" "$(opt "$A" run-id)"
check "final-b run id" "eval-v1-b" "$(opt "$B" run-id)"
check "the run ids differ by the suffix only" "eval-v1" "$(opt "$A" run-id | sed 's/-a$//')"
check "both suffixes belong to one base" "$(opt "$A" run-id | sed 's/-a$//')" "$(opt "$B" run-id | sed 's/-b$//')"
check "final-a watchdog" "240" "$(opt "$A" watchdog-min)"
check "final-b watchdog" "240" "$(opt "$B" watchdog-min)"
check "final-a is no canary" "0" "$(printf '%s\n' "$A" | grep -c -- '--canary')"
check "final-b is no canary" "0" "$(printf '%s\n' "$B" | grep -c -- '--canary')"

A2="$(dry FINAL_RUN_BASE=eval-v1-rc3 just --dry-run final-a --tag eval-v1-rc3)"
B2="$(dry FINAL_RUN_BASE=eval-v1-rc3 just --dry-run final-b --tag eval-v1-rc3)"
check "FINAL_RUN_BASE names a pilot (run A)" "eval-v1-rc3-a" "$(opt "$A2" run-id)"
check "FINAL_RUN_BASE names a pilot (run B)" "eval-v1-rc3-b" "$(opt "$B2" run-id)"
check "extra arguments reach run_eval.sh (run A)" "eval-v1-rc3" "$(opt "$A2" tag)"
check "extra arguments reach run_eval.sh (run B)" "eval-v1-rc3" "$(opt "$B2" tag)"

echo "== the values are accepted by run_eval.sh"
ALL_STAGES="$(sed -n 's/^ALL_STAGES="\(.*\)"/\1/p' "$INFRA/run_eval.sh")"
for recipe in "$A" "$B"; do
    for stage in $(opt "$recipe" stages | tr ',' ' '); do
        case ",$ALL_STAGES," in
            *",$stage,"*) check "stage $stage is known to run_eval.sh" yes yes ;;
            *) check "stage $stage is known to run_eval.sh" yes no ;;
        esac
    done
    id="$(opt "$recipe" run-id)"
    if [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$ ]]; then check "run id $id is valid" yes yes; else check "run id $id is valid" yes no; fi
done
# A base that makes the run id longer than 48 characters is a usage error of run_eval.sh (exit code 2,
# raised before anything else happens), so it cannot start a run by accident.
long="$(dry FINAL_RUN_BASE="$(printf 'x%.0s' {1..60})" just --dry-run final-a)"
bash "$INFRA/run_eval.sh" --run-id "$(opt "$long" run-id)" > /dev/null 2>&1
check "an overlong run id is refused by run_eval.sh with exit code 2" 2 "$?"

echo "== the canary recipe and the full recipe"
C="$(dry just --dry-run canary --tag eval-v1-rc3)"
check "canary passes --canary" "1" "$(printf '%s\n' "$C" | grep -c -- '--canary')"
check "canary passes its arguments on" "eval-v1-rc3" "$(opt "$C" tag)"
check "canary does not choose stages, run_eval.sh runs all of them" "" "$(opt "$C" stages)"
F="$(dry just --dry-run full)"
check "full keeps the default stages" "" "$(opt "$F" stages)"

echo "== just validate runs every test file"
shown="$(cd "$INFRA" && just --show validate)"
for f in "$INFRA"/tests/test_*.sh; do
    name="$(basename "$f")"
    case "$shown" in
        *"bash tests/$name"*) check "validate runs $name" yes yes ;;
        *) check "validate runs $name" yes no ;;
    esac
done

echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
