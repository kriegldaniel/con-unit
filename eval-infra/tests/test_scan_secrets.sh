#!/usr/bin/env bash
# Offline test of scan_secrets.sh: detection of each credential pattern, the guarantee that the
# matched text is never printed, repo mode (ignored files are not scanned, untracked files are),
# identifier mode with stubbed aws and curl, usage errors, and a clean scan of the scanner itself.
# Needs bash, git and grep. It never touches AWS or the network.
#
# Fixture secrets are assembled from two halves, so this file does not trip the scanner either.
#
# Usage: bash eval-infra/tests/test_scan_secrets.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="$HERE/../scan_secrets.sh"
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

OUT=''
RC=0
scan() { # arguments of scan_secrets.sh
    OUT=$(bash "$SCAN" "$@" 2>&1)
    RC=$?
}
contains() { case "$OUT" in *"$1"*) echo yes ;; *) echo no ;; esac }

KEY_HEADER="-----BEGIN OPENSSH ""PRIVATE KEY-----"
KEY_ID="AKIA""IOSFODNN7EXAMPLE"
SECRET_LINE="aws_secret_""access_key = wJalrXUtnFEMI"
HOME_PATH="/Us""ers/someone/project"

echo "== fixed patterns"
mkdir -p "$WORK/clean" "$WORK/key" "$WORK/keyid" "$WORK/secret" "$WORK/home"
printf 'nothing to see here\n/home/ubuntu is a generic path\nAWS_PROFILE=conunit\n' > "$WORK/clean/a.txt"
scan "$WORK/clean"
check "clean tree exits 0" 0 "$RC"
check "clean tree says CLEAN" yes "$(contains CLEAN)"

printf 'line one\n%s\nline three\n' "$KEY_HEADER" > "$WORK/key/id"
scan "$WORK/key"
check "private key block exits 1" 1 "$RC"
check "private key block is labeled" yes "$(contains 'private key block')"
check "private key block reports file and line" yes "$(contains 'key/id:2')"
check "private key text is not printed" no "$(contains 'OPENSSH')"

printf 'key=%s\n' "$KEY_ID" > "$WORK/keyid/env"
scan "$WORK/keyid"
check "AWS access key id exits 1" 1 "$RC"
check "AWS access key id is labeled" yes "$(contains 'AWS access key id')"
check "AWS access key id value is not printed" no "$(contains "$KEY_ID")"

printf '[default]\n%s\n' "$SECRET_LINE" > "$WORK/secret/credentials"
scan "$WORK/secret"
check "secret assignment exits 1" 1 "$RC"
check "secret value is not printed" no "$(contains wJalrXUtnFEMI)"

printf 'path: %s\n' "$HOME_PATH" > "$WORK/home/log.txt"
scan "$WORK/home"
check "macOS home directory exits 1" 1 "$RC"
check "home directory name is not printed" no "$(contains someone)"

scan "$WORK/key" "$WORK/clean"
check "several paths, one finding" "1 FINDINGS" "$(printf '%s' "$OUT" | grep -o '[0-9]* FINDINGS')"

echo "== repo mode"
REPO="$WORK/repo"
mkdir -p "$REPO"
git -C "$REPO" init -q
printf 'ignored.key\n' > "$REPO/.gitignore"
printf 'fine\n' > "$REPO/tracked.txt"
printf '%s\n' "$KEY_HEADER" > "$REPO/ignored.key"
git -C "$REPO" add .gitignore tracked.txt
scan --repo "$REPO"
check "ignored file with a key is not scanned" 0 "$RC"
printf '%s\n' "$KEY_HEADER" > "$REPO/untracked.txt"
scan --repo "$REPO"
check "untracked and not ignored file is scanned" 1 "$RC"
check "finding path is relative to the repo" yes "$(contains 'untracked.txt:1')"
rm -f "$REPO/untracked.txt" "$REPO/tracked.txt"
scan --repo "$REPO"
check "tracked file deleted from the work tree is skipped" 0 "$RC"

echo "== identifier mode with stubbed aws and curl"
mkdir -p "$WORK/stubs" "$WORK/ids-hit" "$WORK/ids-miss"
printf '#!/bin/sh\nprintf "123456789012\\tarn:aws:iam::123456789012:user/Test.User\\n"\n' > "$WORK/stubs/aws"
printf '#!/bin/sh\necho 203.0.113.9\n' > "$WORK/stubs/curl"
chmod +x "$WORK/stubs/aws" "$WORK/stubs/curl"
printf 'account 123456789012\nuser Test.User\nssh from 203.0.113.9/32\n' > "$WORK/ids-hit/run_eval.log"
printf 'account unknown\nssh from <operator>/32\n' > "$WORK/ids-miss/run_eval.log"
OUT=$(PATH="$WORK/stubs:$PATH" bash "$SCAN" --identifiers "$WORK/ids-hit" 2>&1)
RC=$?
check "identifiers found in a bundle exit 1" 1 "$RC"
check "account id is labeled" yes "$(contains 'AWS account id')"
check "principal name is labeled" yes "$(contains 'AWS principal name')"
check "public address is labeled" yes "$(contains 'operator public IPv4 address')"
check "identifier values are not printed" "no no no" "$(contains 123456789012) $(contains Test.User) $(contains 203.0.113.9)"
OUT=$(PATH="$WORK/stubs:$PATH" bash "$SCAN" --identifiers "$WORK/ids-miss" 2>&1)
RC=$?
check "redacted bundle exits 0" 0 "$RC"
scan "$WORK/ids-hit"
check "without --identifiers the same bundle is not flagged" 0 "$RC"

echo "== usage and self scan"
scan
check "no arguments is a usage error" 2 "$RC"
scan "$WORK/does-not-exist"
check "missing path is a usage error" 2 "$RC"
scan --bogus
check "unknown option is a usage error" 2 "$RC"
scan "$SCAN" "${BASH_SOURCE[0]}"
check "the scanner and its test scan clean" 0 "$RC"

echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
