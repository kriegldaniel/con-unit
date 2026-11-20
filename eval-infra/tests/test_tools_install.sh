#!/usr/bin/env bash
# Offline test of the external tool handling of remote_eval.sh: the format of tools.lock, the
# parsing of the checksum files that releases publish, the version check, which stage needs which
# tool, and the installer against a fake release server (a directory: no network, no sudo, no /usr/local).
#
# Every behaviour has positive, negative and edge cases. The installer cases cover the three
# integrity checks (lock hash, download hash, release checksum file) and the checks after the install.
#
# Usage: bash eval-infra/tests/test_tools_install.sh   (needs bash 4+, jq, tar, awk, sha256sum or shasum)
#
# shellcheck disable=SC2016 # the snippets are single quoted on purpose, they expand inside the harness
# shellcheck source-path=SCRIPTDIR
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.sh
. "$HERE/harness.sh"

sha() { if command -v sha256sum > /dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
has() { case "$1" in *"$2"*) echo yes ;; *) echo no ;; esac; }

A=$(printf 'a%.0s' {1..64})
B=$(printf 'b%.0s' {1..64})
REAL_LOCK="$HERE/../tools.lock"
GOOD="$(grep -v '^[[:space:]]*#' "$REAL_LOCK")"

echo "== tools.lock format"
lock_case() { # description expected-rc file [expected-text-in-output]
    local out rc
    out=$(run_in_harness "validate_tools_lock '$3'" 2>&1)
    rc=$?
    check "$1" "$2" "$rc"
    if [ -n "${4:-}" ]; then check "$1: the message names the problem" yes "$(has "$out" "$4")"; fi
}
lock_text() { printf '%s' "$1" > "$WORK/lock.txt"; echo "$WORK/lock.txt"; }
first() { printf '%s\n' "$GOOD" | grep "^$1 "; }
without() { printf '%s\n' "$GOOD" | grep -v "^$1 "; }
DOCKLE_LINE="$(first dockle)"
TRIVY_LINE="$(first trivy)"
UPPER_SHA="$(printf '%s' "${TRIVY_LINE##* }" | tr 'a-f' 'A-F')"

lock_case "the committed tools.lock is valid" 0 "$REAL_LOCK"
lock_case "comments, blank and indented comment lines are ignored" 0 "$(lock_text "$(printf '# c\n\n   \n  # indented\n%s\n' "$GOOD")")"
lock_case "no newline at the end of the file" 0 "$(lock_text "$GOOD")"
lock_case "a missing file" 1 "$WORK/does-not-exist" "not found"
lock_case "a tool is not pinned" 1 "$(lock_text "$(without dockle)")" "dockle is not pinned"
lock_case "a tool listed twice" 1 "$(lock_text "$(printf '%s\n%s\n' "$GOOD" "$DOCKLE_LINE")")" "listed twice"
lock_case "an unknown tool" 1 "$(lock_text "$(printf '%s\ngrype 0.1.0 https://github.com/anchore/grype/releases/download/v0.1.0/grype %s\n' "$GOOD" "$A")")" "unknown tool 'grype'"
lock_case "three fields" 1 "$(lock_text "$(printf '%s\n%s\n' "$(without trivy)" "${TRIVY_LINE% *}")")" "expected 4 fields"
lock_case "five fields" 1 "$(lock_text "$(printf '%s\n%s extra\n' "$(without trivy)" "$TRIVY_LINE")")" "expected 4 fields"
lock_case "a placeholder instead of a hash" 1 "$(lock_text "$(printf '%s\n%s\n' "$(without trivy)" "${TRIVY_LINE% *} UNVERIFIED-no-checksum-file")")" "placeholder"
lock_case "a hash that is too short" 1 "$(lock_text "$(printf '%s\n%s\n' "$(without trivy)" "${TRIVY_LINE% *} abc123")")" "64 lowercase hex"
lock_case "an upper case hash" 1 "$(lock_text "$(printf '%s\n%s\n' "$(without trivy)" "${TRIVY_LINE% *} $UPPER_SHA")")" "64 lowercase hex"
lock_case "a plain http url" 1 "$(lock_text "$(printf '%s\n' "${GOOD//https:\/\/github.com\/goodwithtech/http://github.com/goodwithtech}")")" "github.com release download url"
lock_case "a host other than github.com" 1 "$(lock_text "$(printf '%s\n' "${GOOD//https:\/\/github.com\/goodwithtech/https://example.com/goodwithtech}")")" "github.com release download url"
lock_case "a url of another version than the version field" 1 "$(lock_text "$(printf '%s\n' "${GOOD/dockle 0.4.15/dockle 0.4.14}")")" "does not belong to version"
lock_case "a version that is not x.y.z" 1 "$(lock_text "$(printf '%s\n' "${GOOD/dockle 0.4.15/dockle 0.4}")")" "is not x.y.z"
lock_case "a carriage return" 1 "$(lock_text "$(printf '%s\r\n' "$GOOD")")" "carriage return"

echo "== release checksum files"
sum_case() { # description expected-rc expected-hash content asset
    local out rc
    printf '%s' "$4" > "$WORK/sums.txt"
    out=$(run_in_harness "checksum_for_asset '$WORK/sums.txt' '$5'" 2>&1)
    rc=$?
    check "$1: exit code" "$2" "$rc"
    if [ "$2" = 0 ]; then check "$1: hash" "$3" "$out"; fi
}
sum_case "two spaces layout (dockle, trivy, container-structure-test)" 0 "$A" "$A  asset.tgz
$B  other.tgz
" asset.tgz
sum_case "binary mode layout with a star (hadolint)" 0 "$A" "$A *hadolint-linux-x86_64
" hadolint-linux-x86_64
sum_case "the asset sits among many entries" 0 "$B" "$A  a
$B  asset.tgz
$A  c
" asset.tgz
sum_case "the asset is not listed" 1 "" "$A  other.tgz
" asset.tgz
sum_case "the asset is listed twice" 1 "" "$A  asset.tgz
$B  asset.tgz
" asset.tgz
sum_case "a malformed hash" 1 "" "zz  asset.tgz
" asset.tgz
sum_case "an upper case hash" 1 "" "$(printf '%s' "$A" | tr a-f A-F)  asset.tgz
" asset.tgz
sum_case "a longer name that contains the asset name" 1 "" "$A  asset.tgz.sig
" asset.tgz
sum_case "an empty file" 1 "" "" asset.tgz

echo "== version output"
ver_case() { # description expected-rc output version
    OUT_UNDER_TEST="$3" run_in_harness "version_matches \"\$OUT_UNDER_TEST\" '$4'" > /dev/null 2>&1
    check "$1" "$2" "$?"
}
ver_case "dockle output" 0 "dockle version 0.4.15" 0.4.15
ver_case "hadolint output" 0 "Haskell Dockerfile Linter 2.14.0" 2.14.0
ver_case "trivy output, first of several lines" 0 "$(printf 'Version: 0.76.1\nVulnerability DB:\n  Version: 2')" 0.76.1
ver_case "container-structure-test output" 0 "1.22.1" 1.22.1
ver_case "a leading v is ignored" 0 "v1.22.1" 1.22.1
ver_case "a longer patch number is not the version" 1 "dockle version 0.4.150" 0.4.15
ver_case "a longer major number is not the version" 1 "dockle version 10.4.15" 0.4.15
ver_case "a pre-release suffix is not the version" 1 "dockle version 0.4.15-rc1" 0.4.15
ver_case "another version" 1 "dockle version 0.4.14" 0.4.15
ver_case "empty output" 1 "" 0.4.15
ver_case "output without a version" 1 "version" 0.4.15

echo "== which stage needs which tool"
tools_case() { # description stages expected
    check "$1" "$3" "$(run_in_harness "STAGES='$2'; required_tools | paste -sd' ' -")"
}
ALL4="dockle hadolint trivy container-structure-test"
tools_case "eval and export need no tool" "eval,export" ""
tools_case "run B stages need no tool" "eval,export,attribute,ablate,reliability" ""
tools_case "run A stages need all four" "eval,export,rq3,rq1,lint,crosscheck" "$ALL4"
tools_case "rq1 needs all four" "rq1" "$ALL4"
tools_case "crosscheck needs dockle" "crosscheck" "dockle"
tools_case "rq3 needs dockle" "rq3" "dockle"
tools_case "lint is static and needs no tool" "lint" ""
tools_case "rq3 and crosscheck list dockle once" "rq3,crosscheck" "dockle"
tools_case "the order of --stages does not matter" "crosscheck,rq1" "$ALL4"

echo "== installer against a fake release server"
# One release directory holds a stub executable per tool (it prints its version in the format the
# real tool uses), the archives and the checksum files in the layout of each project, and a lock file
# for them. The versions are fake on purpose, so a result cannot be mistaken for the real pins.
make_stub() { # path version-flag output
    cat > "$1" << EOF
#!/bin/sh
if [ "\$1" = "$2" ]; then
cat << 'OUT'
$3
OUT
exit 0
fi
exit 2
EOF
    chmod +x "$1"
}
DOCKLE_ASSET=dockle_1.1.1_Linux-64bit.tar.gz

# Pack a dockle stub into the archive and publish its hash in the lock file and the checksum file.
publish_dockle() { # release-dir version-output member-name
    local d=$1 s="$1/stage-dockle" h
    rm -rf "$s"
    mkdir -p "$s"
    make_stub "$s/$3" --version "$2"
    (cd "$s" && tar -czf "$d/$DOCKLE_ASSET" "$3")
    h=$(sha "$d/$DOCKLE_ASSET")
    printf '%s  other_Linux-ARM.tar.gz\n%s  %s\n' "$B" "$h" "$DOCKLE_ASSET" > "$d/dockle_1.1.1_checksums.txt"
    awk -v h="$h" '$1 == "dockle" { $4 = h } { print }' "$d/tools.lock" > "$d/tools.lock.new"
    mv "$d/tools.lock.new" "$d/tools.lock"
    rm -rf "$s"
}

make_release() { # dir [hadolint layout: per-asset or aggregate]
    local dir=$1 layout=${2:-per-asset} asset name ver s="$1/stage"
    mkdir -p "$s"
    : > "$dir/tools.lock"
    for name in dockle hadolint trivy container-structure-test; do
        case $name in
            dockle)
                printf 'dockle 1.1.1 https://github.com/acme/dockle/releases/download/v1.1.1/%s %s\n' "$DOCKLE_ASSET" "$A" >> "$dir/tools.lock"
                publish_dockle "$dir" "dockle version 1.1.1" dockle
                ;;
            hadolint)
                ver=2.2.2
                asset=hadolint-linux-x86_64
                make_stub "$dir/$asset" --version "Haskell Dockerfile Linter 2.2.2"
                printf '%s %s https://github.com/acme/%s/releases/download/v%s/%s %s\n' "$name" "$ver" "$name" "$ver" "$asset" "$(sha "$dir/$asset")" >> "$dir/tools.lock"
                if [ "$layout" = per-asset ]; then
                    printf '%s *%s\n' "$(sha "$dir/$asset")" "$asset" > "$dir/$asset.sha256"
                else
                    printf '%s *hadolint-linux-arm64\n%s *%s\n' "$B" "$(sha "$dir/$asset")" "$asset" > "$dir/checksums.sha256"
                fi
                ;;
            trivy)
                ver=3.3.3
                asset=trivy_3.3.3_Linux-64bit.tar.gz
                make_stub "$s/trivy" --version "$(printf 'Version: 3.3.3\nVulnerability DB: none')"
                printf 'readme\n' > "$s/README.md"
                (cd "$s" && tar -czf "$dir/$asset" trivy README.md)
                printf '%s %s https://github.com/acme/%s/releases/download/v%s/%s %s\n' "$name" "$ver" "$name" "$ver" "$asset" "$(sha "$dir/$asset")" >> "$dir/tools.lock"
                printf '%s  %s\n%s  trivy_3.3.3_macOS-64bit.tar.gz\n' "$(sha "$dir/$asset")" "$asset" "$B" > "$dir/trivy_3.3.3_checksums.txt"
                ;;
            container-structure-test)
                ver=4.4.4
                asset=container-structure-test-linux-amd64
                make_stub "$dir/$asset" version "4.4.4"
                printf '%s %s https://github.com/acme/%s/releases/download/v%s/%s %s\n' "$name" "$ver" "$name" "$ver" "$asset" "$(sha "$dir/$asset")" >> "$dir/tools.lock"
                printf '%s  %s\n%s  container-structure-test-darwin-amd64\n' "$(sha "$dir/$asset")" "$asset" "$B" > "$dir/checksums.txt"
                ;;
        esac
    done
    rm -rf "$s"
}

export FAKE_SHADOW="$WORK/shadow"
mkdir -p "$FAKE_SHADOW"
printf '#!/bin/sh\nexit 0\n' > "$FAKE_SHADOW/dockle"
chmod +x "$FAKE_SHADOW/dockle"

# install_case <release-dir> <stages> [snippet run after the setup and before install_tools]
# Sets OUT, RC and RES (the results directory of the case).
install_case() {
    local rel=$1 stages=$2 extra=${3:-}
    rm -rf "${WORK:?}/base" "${WORK:?}/bin" "$rel/fetch.log"
    mkdir -p "$WORK/bin"
    RES="$WORK/base/results/t"
    OUT=$(FAKE_RELEASE="$rel" run_in_harness "
        sudo() { shift; \"\$@\"; }
        fetch() {
            [ -f \"\$FAKE_RELEASE/\${1##*/}\" ] || return 22
            echo \"\$1\" >> \"\$FAKE_RELEASE/fetch.log\"
            cp \"\$FAKE_RELEASE/\${1##*/}\" \"\$2\"
        }
        STAGES='$stages'; RUN_ID=t; COMMIT=abcdef1
        RESULTS_DIR=\$CONUNIT_BASE_DIR/results/t; STATUS_FILE=\$RESULTS_DIR/status.json
        mkdir -p \"\$RESULTS_DIR/host\" \"\$INCOMING_DIR\"
        cp \"\$FAKE_RELEASE/tools.lock\" \"\$TOOLS_LOCK\"
        TOOLS_LOCK_SHA256=\$(sha256_of \"\$TOOLS_LOCK\")
        status_init
        PATH=\$CONUNIT_TOOLS_BIN_DIR:\$PATH
        $extra
        install_tools
        echo INSTALL_DONE
    " 2>&1)
    RC=$?
}
tv() { jq -r "$1" "$RES/host/tool_versions.json" 2> /dev/null; }

REL="$WORK/rel"
mkdir -p "$REL"
make_release "$REL"

install_case "$REL" "eval,export,rq3,rq1,lint,crosscheck"
check "run A stages: the install succeeds" 0 "$RC"
check "all four tools are recorded" "container-structure-test dockle hadolint trivy" "$(tv '.tools | keys | join(" ")')"
check "the recorded versions are the locked ones" "1.1.1 2.2.2 3.3.3 4.4.4" "$(tv '[.tools.dockle.version, .tools.hadolint.version, .tools.trivy.version, .tools["container-structure-test"].version] | join(" ")')"
check "every binary is executable in the bin directory" 4 "$(find "$WORK/bin" -type f -perm -u+x | wc -l | tr -d ' ')"
check "the binary hash is recorded" "$(sha "$WORK/bin/hadolint")" "$(tv '.tools.hadolint.binary_sha256')"
check "the download hash is the pinned one" "$(grep '^dockle ' "$REL/tools.lock" | awk '{print $4}')" "$(tv '.tools.dockle.download_sha256')"
check "the release checksum file that was used is recorded" "https://github.com/acme/hadolint/releases/download/v2.2.2/hadolint-linux-x86_64.sha256" "$(tv '.tools.hadolint.release_checksum_file')"
check "the version line of trivy is the first output line" "Version: 3.3.3" "$(tv '.tools.trivy.version_output')"
check "the lock hash is recorded" "$(sha "$REL/tools.lock")" "$(tv '.lock_sha256')"
check "all pins are listed, installed or not" 4 "$(tv '.locked | length')"
check "the lock file is copied into the bundle" 0 "$(cmp -s "$REL/tools.lock" "$RES/host/tools.lock"; echo $?)"
check "the status file carries the installed tools" "1.1.1" "$(jq -r '.external_tools.tools.dockle.version' "$RES/status.json")"
check "the schema is named" "conunit-tool-versions/1" "$(tv '.schema')"

install_case "$REL" "crosscheck"
check "crosscheck only: the install succeeds" 0 "$RC"
check "crosscheck only: just dockle is installed" "dockle" "$(tv '.tools | keys | join(" ")')"
check "crosscheck only: no other tool was downloaded" 0 "$(grep -c -E 'hadolint|trivy|container-structure' "$REL/fetch.log")"

install_case "$REL" "eval,export,attribute,ablate,reliability"
check "run B stages: the install succeeds" 0 "$RC"
check "run B stages: no tool is installed" "{}" "$(tv '.tools | tostring')"
check "run B stages: nothing was downloaded" no "$([ -e "$REL/fetch.log" ] && echo yes || echo no)"
check "run B stages: the lock hash is null" null "$(tv '.lock_sha256')"
check "run B stages: the file for the manifest exists" yes "$([ -s "$RES/host/tool_versions.json" ] && echo yes || echo no)"

AGG="$WORK/rel-aggregate"
mkdir -p "$AGG"
make_release "$AGG" aggregate
install_case "$AGG" "rq1"
check "hadolint release with one aggregate checksum file: the install succeeds" 0 "$RC"
check "hadolint release with one aggregate checksum file: the fallback name is recorded" "https://github.com/acme/hadolint/releases/download/v2.2.2/checksums.sha256" "$(tv '.tools.hadolint.release_checksum_file')"

echo "== the installer refuses"
# Every case works on its own copy of the release. A mutation is a function of that directory.
mut_tamper_download() { printf 'x' >> "$1/$DOCKLE_ASSET"; }
mut_other_hash_in_release() { printf '%s  %s\n' "$B" "$DOCKLE_ASSET" > "$1/dockle_1.1.1_checksums.txt"; }
mut_asset_not_listed() { printf '%s  other.tgz\n' "$B" > "$1/dockle_1.1.1_checksums.txt"; }
mut_no_checksum_file() { rm "$1/dockle_1.1.1_checksums.txt"; }
mut_download_missing() { rm "$1/$DOCKLE_ASSET"; }
mut_archive_without_binary() { publish_dockle "$1" "dockle version 1.1.1" other; }
mut_wrong_version_output() { publish_dockle "$1" "dockle version 9.9.9" dockle; }
mut_placeholder() { awk '$1 == "trivy" { $4 = "UNVERIFIED-no-release-checksum" } { print }' "$1/tools.lock" > "$1/tools.lock.new"; mv "$1/tools.lock.new" "$1/tools.lock"; }
mut_none() { :; }

refuse_case() { # description stages mutation expected-text [snippet before install_tools]
    local d="$WORK/rel-case"
    rm -rf "$d"
    cp -R "$REL" "$d"
    "$3" "$d"
    install_case "$d" "$2" "${5:-}"
    check "$1: exit code 1" 1 "$RC"
    check "$1: the message says why" yes "$(has "$OUT" "$4")"
    check "$1: the install did not complete" no "$(has "$OUT" INSTALL_DONE)"
}
refuse_case "a tampered download" crosscheck mut_tamper_download "sha256 of the download is"
refuse_case "a release checksum file that lists another hash" crosscheck mut_other_hash_in_release "the release checksum file lists"
refuse_case "a release checksum file without the asset" crosscheck mut_asset_not_listed "exactly once"
refuse_case "a release without any checksum file" crosscheck mut_no_checksum_file "no checksum file under any of the names"
refuse_case "a download that fails" crosscheck mut_download_missing "download failed"
refuse_case "an archive without the binary" crosscheck mut_archive_without_binary "no member named dockle"
refuse_case "a binary that reports another version" crosscheck mut_wrong_version_output "does not carry the pinned version 1.1.1"
refuse_case "a lock file with a placeholder" rq1 mut_placeholder "placeholder"
refuse_case "a lock hash that differs from the one the operator computed" crosscheck mut_none "tools.lock sha256 mismatch" "TOOLS_LOCK_SHA256=$A"
refuse_case "a binary that PATH resolves elsewhere" crosscheck mut_none "another binary shadows the pinned one" 'PATH=$FAKE_SHADOW:$PATH'
refuse_case "a copy to the bin directory that fails" crosscheck mut_none "cannot install to" 'sudo() { return 1; }'

echo "== a placeholder is refused before anything is downloaded"
d="$WORK/rel-case"
rm -rf "$d"
cp -R "$REL" "$d"
mut_placeholder "$d"
install_case "$d" rq1
check "no download was attempted" no "$([ -e "$d/fetch.log" ] && echo yes || echo no)"

finish
