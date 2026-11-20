#!/usr/bin/env bash
# ConUnit remote evaluation. Runs ON the evaluation instance.
#
# Normally streamed by run_eval.sh without any nested quoting:
#     ssh host 'bash -s -- <flags>' < remote_eval.sh
# It can also be run from a file (bash remote_eval.sh <flags>) for debugging after --keep.
#
# What it does, in order
#   1. verifies the shipped source bundle (sha256) and unpacks it
#   2. installs the Go toolchain named in go.mod and verifies its checksum against go.dev
#   3. installs the container runtime packages and records their versions
#   3b. installs the external tools the requested stages need (dockle, hadolint, trivy,
#       container-structure-test) from tools.lock, verifies every download against the pinned
#       sha256 and against the release's own checksum file, records host/tool_versions.json
#   4. installs the registry remap of CONTRACT section 9 and proves it is active
#   5. records host facts (kernel, CPU, podman info, packages, registries conf)
#   6. builds con-unit, export_latex, benchmark_rq3, rq1, crosscheck, attribute_exec and
#      reliability with the commit stamped in
#   7. runs the stages: eval, export, rq3, rq1, lint, crosscheck, attribute, ablate,
#      reliability (each stage records its state, exit code and output checksum)
#   8. writes status.json, REMOTE_SHA256SUMS and finally BENCHMARK_COMPLETE
#
# Exit codes: 0 complete, 1 failed, 2 usage error, 3 incomplete (a stage ended with exit code 3,
# partial results are kept).
#
# The whole script is read before any command runs (the last line is the only call), so
# commands inside it can never consume the script from stdin.
#
# shellcheck disable=SC2329 # functions are invoked indirectly through prereq and run_stage
# shellcheck disable=SC2016 # jq programs and dpkg-query formats are intentionally single quoted
# shellcheck disable=SC1091 # /etc/os-release is not available where the script is linted
# shellcheck disable=SC2094 # REMOTE_SHA256SUMS is excluded from its own file list
set -Eeuo pipefail

BASE_DIR=${CONUNIT_BASE_DIR:-/opt/con-unit} # overridable for offline tests only
INCOMING_DIR=$BASE_DIR/incoming
SRC_DIR=$BASE_DIR/src
TOOLS_BIN_DIR=${CONUNIT_TOOLS_BIN_DIR:-/usr/local/bin} # overridable for offline tests only
TOOLS_LOCK=$INCOMING_DIR/tools.lock
RUN_ENV=/etc/con-unit/run.env
READY_MARKER=/var/lib/con-unit/ready
REGISTRY_CONF=/etc/containers/registries.conf.d/50-conunit-mirror.conf
REGISTRY_CONF_BODY='[[registry]]
prefix = "docker.io/library"
location = "public.ecr.aws/docker/library"'
REGISTRY_REMAP_DESC='docker.io/library -> public.ecr.aws/docker/library'
HUB_BLOCK_BEGIN='# BEGIN con-unit docker-hub block'
HUB_BLOCK_END='# END con-unit docker-hub block'
HUB_HOSTS='registry-1.docker.io index.docker.io auth.docker.io production.cloudflare.docker.com'
MIN_FREE_GB=40

# Runtime packages. Installed WITH recommended packages on purpose: the resulting set is
# recorded in host/dpkg_versions_all.tsv instead of being constrained by flags.
# Ubuntu 24.04 has no package named containers-common. Its files ship in
# golang-github-containers-common and golang-github-containers-image, which podman depends on.
PACKAGES=(podman uidmap crun conmon netavark aardvark-dns passt slirp4netns fuse-overlayfs
    catatonit ca-certificates curl jq rsync)
RECORDED_PACKAGES=(podman crun conmon netavark aardvark-dns passt slirp4netns uidmap
    fuse-overlayfs catatonit golang-github-containers-common
    golang-github-containers-image runc systemd linux-aws)

# External tools that tools.lock pins. A stage that needs one fails before it runs when it is missing.
KNOWN_TOOLS='dockle hadolint trivy container-structure-test'
# Every stage in the order in which they run, whatever the order of --stages.
ALL_STAGES='eval export rq3 rq1 lint crosscheck attribute ablate reliability'
# Trivy is only ever run with offline settings. The vulnerability database, the checks bundle and
# the Java index are not fetched, no version check or telemetry goes out, so nothing on the host
# has to reach a registry and the Docker Hub block stays intact. The variables are the
# environment form of the flags --skip-db-update, --skip-java-db-update, --skip-check-update,
# --skip-version-check, --offline-scan and --disable-telemetry (checked against v0.76.2).
TRIVY_OFFLINE_ENV=(TRIVY_SKIP_DB_UPDATE=true TRIVY_SKIP_JAVA_DB_UPDATE=true TRIVY_SKIP_CHECK_UPDATE=true
    TRIVY_SKIP_VERSION_CHECK=true TRIVY_OFFLINE_SCAN=true TRIVY_DISABLE_TELEMETRY=true TRIVY_NO_PROGRESS=true)
# Window values of the reliability stage: three repeats at the short one, one run each at the others.
REL_W_SHORT='3s'
REL_W_MID='10s'
REL_W_LONG='30s'

# ---------------------------------------------------------------- defaults
RUN_ID=''
COMMIT=''
TAG=''
BUNDLE_KIND='tag'
TAINTED='false'
BUNDLE_SHA256=''
DATASET='fixtures/evaluation_dataset_pinned.txt'
RQ3_DATASET='fixtures/evaluation_dataset_top10_pinned.txt'
MODE='rootful'
STAGES='eval,export,rq3'
PACK='cis'
PLATFORM='linux/amd64'
ENGINE='podman'
IMAGE_SOURCE='auto'
PROBE_WINDOW='3s'
RQ3_ITERATIONS=''
RQ3_WARMUP='1'
RQ1_CASES='0'
TOOLS_LOCK_SHA256=''
CANARY='0'
RESUME='0'
BLOCK_HUB='true'

RESULTS_DIR=''
STATUS_FILE=''
CURRENT_STAGE=''
FAIL_MSG=''
FINALIZED=0
GO_VERSION=''
PROOF_REF=''
EVAL_DATASET_PATH=''
RQ3_DATASET_PATH=''
RELIABILITY_DATASET_PATH=''
SEEDED_STATE=''
STAGE_RC=0
ENV_RUN_ID=''
ENV_ITERATIONS='10'

# ---------------------------------------------------------------- logging
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '%s [%-5s] %s\n' "$(now)" "$1" "$2"; }
info() { log INFO "$*"; }
ok() { log OK "$*"; }
warn() { log WARN "$*"; }
err() { log FAIL "$*" >&2; }
section() {
    local rule
    rule=$(printf '%.0s=' {1..72})
    printf '\n%s\n  %s\n%s\n' "$rule" "$*" "$rule"
}
die() {
    FAIL_MSG="$*"
    err "$*"
    exit 1
}

usage() {
    cat <<'EOF'
remote_eval.sh --run-id ID --commit SHA --bundle-sha256 HEX [options]

Required
  --run-id ID              run identifier (must match /etc/con-unit/run.env)
  --commit SHA             commit the bundle was built from
  --bundle-sha256 HEX      sha256 of /opt/con-unit/incoming/con-unit-bundle.tar.gz

Options
  --tag TAG                release tag, informational
  --bundle-kind tag|worktree
  --tainted true|false     stamped into the binaries (BuildTainted)
  --dataset PATH           eval dataset, relative to the bundle root
  --rq3-dataset PATH       the 10 image dataset of the rq3 and reliability stages, relative to the bundle root
  --canary N               use only the first N image lines of the datasets
  --rq1-cases N            run only the first N cases of the RQ1 oracle (default 0, all of them)
  --tools-lock-sha256 HEX  sha256 of incoming/tools.lock, required when a requested stage needs an external tool
  --mode rootful|rootless  Podman mode (default rootful)
  --stages LIST            comma list of eval,export,rq3,rq1,lint,crosscheck,attribute,ablate,reliability
                           (default eval,export,rq3)
  --pack NAME              rule pack (default cis)
  --platform OS/ARCH       default linux/amd64
  --engine NAME            default podman
  --image-source POLICY    auto|local|registry (default auto)
  --probe-window DURATION  Tier 3 window W (default 3s)
  --rq3-iterations N       timed trials (default: BENCHMARK_ITERATIONS from /etc/con-unit/run.env)
  --rq3-warmup N           discarded warm-up iterations (default 1)
  --block-docker-hub BOOL  make Docker Hub unreachable on this host (default true)
  --resume                 pass --resume to eval and reuse an existing results directory
EOF
}

# ---------------------------------------------------------------- argument parsing
parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --run-id) RUN_ID=${2:?missing value for $1}; shift 2 ;;
            --commit) COMMIT=${2:?missing value for $1}; shift 2 ;;
            --tag) TAG=${2:?missing value for $1}; shift 2 ;;
            --bundle-kind) BUNDLE_KIND=${2:?missing value for $1}; shift 2 ;;
            --tainted) TAINTED=${2:?missing value for $1}; shift 2 ;;
            --bundle-sha256) BUNDLE_SHA256=${2:?missing value for $1}; shift 2 ;;
            --dataset) DATASET=${2:?missing value for $1}; shift 2 ;;
            --rq3-dataset) RQ3_DATASET=${2:?missing value for $1}; shift 2 ;;
            --canary) CANARY=${2:?missing value for $1}; shift 2 ;;
            --rq1-cases) RQ1_CASES=${2:?missing value for $1}; shift 2 ;;
            --tools-lock-sha256) TOOLS_LOCK_SHA256=${2:?missing value for $1}; shift 2 ;;
            --mode) MODE=${2:?missing value for $1}; shift 2 ;;
            --stages) STAGES=${2:?missing value for $1}; shift 2 ;;
            --pack) PACK=${2:?missing value for $1}; shift 2 ;;
            --platform) PLATFORM=${2:?missing value for $1}; shift 2 ;;
            --engine) ENGINE=${2:?missing value for $1}; shift 2 ;;
            --image-source) IMAGE_SOURCE=${2:?missing value for $1}; shift 2 ;;
            --probe-window) PROBE_WINDOW=${2:?missing value for $1}; shift 2 ;;
            --rq3-iterations) RQ3_ITERATIONS=${2:?missing value for $1}; shift 2 ;;
            --rq3-warmup) RQ3_WARMUP=${2:?missing value for $1}; shift 2 ;;
            --block-docker-hub) BLOCK_HUB=${2:?missing value for $1}; shift 2 ;;
            --resume) RESUME=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
        esac
    done
}

usage_error() {
    echo "usage error: $*" >&2
    exit 2
}

validate_args() {
    local stage
    [[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$ ]] || usage_error "--run-id missing or malformed"
    [[ "$COMMIT" =~ ^[0-9a-f]{7,64}$ ]] || usage_error "--commit must be a lowercase hex sha"
    [[ "$BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] || usage_error "--bundle-sha256 must be 64 hex characters"
    [[ "$TAINTED" =~ ^(true|false)$ ]] || usage_error "--tainted must be true or false"
    [[ "$BUNDLE_KIND" =~ ^(tag|worktree)$ ]] || usage_error "--bundle-kind must be tag or worktree"
    [[ "$MODE" =~ ^(rootful|rootless)$ ]] || usage_error "--mode must be rootful or rootless"
    [[ "$BLOCK_HUB" =~ ^(true|false)$ ]] || usage_error "--block-docker-hub must be true or false"
    [[ "$IMAGE_SOURCE" =~ ^(auto|local|registry)$ ]] || usage_error "--image-source must be auto, local or registry"
    [[ "$PLATFORM" =~ ^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$ ]] || usage_error "--platform malformed"
    [[ "$ENGINE" =~ ^(auto|podman|docker)$ ]] || usage_error "--engine must be auto, podman or docker"
    [[ "$PROBE_WINDOW" =~ ^[0-9]+(\.[0-9]+)?(ms|s|m)$ ]] || usage_error "--probe-window must look like 3s"
    [[ "$PACK" =~ ^[A-Za-z0-9._-]+$ ]] || usage_error "--pack malformed"
    [[ "$CANARY" =~ ^[0-9]+$ ]] || usage_error "--canary must be a non-negative integer"
    [[ "$RQ1_CASES" =~ ^[0-9]+$ ]] || usage_error "--rq1-cases must be a non-negative integer"
    [[ "$RQ3_WARMUP" =~ ^[0-9]+$ ]] || usage_error "--rq3-warmup must be a non-negative integer"
    [ -z "$RQ3_ITERATIONS" ] || [[ "$RQ3_ITERATIONS" =~ ^[0-9]+$ ]] || usage_error "--rq3-iterations must be an integer"
    [[ "$DATASET" =~ ^[A-Za-z0-9._/-]+$ ]] && [[ "$DATASET" != /* ]] && [[ "$DATASET" != *..* ]] || usage_error "--dataset must be a safe relative path"
    [[ "$RQ3_DATASET" =~ ^[A-Za-z0-9._/-]+$ ]] && [[ "$RQ3_DATASET" != /* ]] && [[ "$RQ3_DATASET" != *..* ]] || usage_error "--rq3-dataset must be a safe relative path"
    [ -n "$STAGES" ] || usage_error "--stages is empty"
    # shellcheck disable=SC2086 # word splitting of the comma list is intended
    for stage in ${STAGES//,/ }; do
        case " $ALL_STAGES " in
            *" $stage "*) ;;
            *) usage_error "unknown stage '$stage' in --stages" ;;
        esac
    done
    [ -z "$TOOLS_LOCK_SHA256" ] || [[ "$TOOLS_LOCK_SHA256" =~ ^[0-9a-f]{64}$ ]] || usage_error "--tools-lock-sha256 must be 64 hex characters"
    # The lock file is only read when a requested stage needs an external tool, but then its hash
    # must have come from the operator machine, so a swapped file on the instance is caught.
    if [ -n "$(required_tools)" ]; then
        [[ "$TOOLS_LOCK_SHA256" =~ ^[0-9a-f]{64}$ ]] || usage_error "--tools-lock-sha256 (64 hex characters) is required: stage(s) $(tool_stage_list) need external tools"
    fi
}

stage_requested() {
    local want=$1 stage
    # shellcheck disable=SC2086 # word splitting of the comma list is intended
    for stage in ${STAGES//,/ }; do
        [ "$stage" = "$want" ] && return 0
    done
    return 1
}

# ---------------------------------------------------------------- tools each stage needs
# External tools a stage needs on PATH, space separated. Stages that are not listed need none.
# lint is static, the attribution stages and the reliability runs only need the engine.
stage_tools() {
    case $1 in
        rq1) echo 'dockle hadolint trivy container-structure-test' ;;
        rq3 | crosscheck) echo 'dockle' ;;
        *) echo '' ;;
    esac
}

# Binaries built from the bundle that a stage needs, relative to bin/.
stage_binaries() {
    case $1 in
        eval | lint) echo 'con-unit' ;;
        export) echo 'export_latex' ;;
        rq3) echo 'benchmark_rq3' ;;
        rq1) echo 'rq1 con-unit' ;;
        crosscheck) echo 'crosscheck' ;;
        attribute) echo 'attribute_exec rq1 con-unit' ;; # rq1 and con-unit build the seeded images when absent
        ablate) echo 'attribute_exec' ;;
        reliability) echo 'con-unit reliability' ;;
        *) echo '' ;;
    esac
}

# The tools of the requested stages, one per line, in the order of KNOWN_TOOLS.
required_tools() {
    local tool stage
    for tool in $KNOWN_TOOLS; do
        # shellcheck disable=SC2086 # word splitting of the comma list is intended
        for stage in ${STAGES//,/ }; do
            case " $(stage_tools "$stage") " in
                *" $tool "*) echo "$tool"; break ;;
            esac
        done
    done
}

# The requested stages that need a tool, comma separated, for messages.
tool_stage_list() {
    local stage out=''
    # shellcheck disable=SC2086 # word splitting of the comma list is intended
    for stage in ${STAGES//,/ }; do
        [ -z "$(stage_tools "$stage")" ] || out="${out:+$out,}$stage"
    done
    echo "$out"
}

# True when the 10 image dataset is read: by the rq3 benchmark and by the reliability repeats.
top10_needed() { stage_requested rq3 || stage_requested reliability; }

# ---------------------------------------------------------------- status file
status_write() {
    local tmp
    tmp=$(mktemp "$RESULTS_DIR/.status.XXXXXX")
    if jq "$@" "$STATUS_FILE" > "$tmp"; then
        mv "$tmp" "$STATUS_FILE"
    else
        rm -f "$tmp"
        return 1
    fi
}

status_init() {
    local stages_json
    # shellcheck disable=SC2086 # word splitting of the comma list is intended
    stages_json=$(printf '%s\n' ${STAGES//,/ } | jq -R . | jq -s .)
    jq -n \
        --arg run_id "$RUN_ID" --arg commit "$COMMIT" --arg tag "$TAG" --arg kind "$BUNDLE_KIND" \
        --argjson tainted "$TAINTED" --arg mode "$MODE" --argjson requested "$stages_json" \
        --arg dataset "$DATASET" --arg rq3_dataset "$RQ3_DATASET" --argjson canary "$CANARY" \
        --arg platform "$PLATFORM" --arg engine "$ENGINE" --arg image_source "$IMAGE_SOURCE" \
        --arg probe_window "$PROBE_WINDOW" --arg pack "$PACK" --argjson block_hub "$BLOCK_HUB" \
        --arg remap "$REGISTRY_REMAP_DESC" --arg started "$(now)" \
        --argjson rq1_cases "$RQ1_CASES" --arg lock_sha "$TOOLS_LOCK_SHA256" \
        '{schema: "conunit-remote-status/1", run_id: $run_id, commit: $commit, tag: $tag,
          bundle_kind: $kind, tainted: $tainted, mode: $mode, stages_requested: $requested,
          dataset: $dataset, rq3_dataset: $rq3_dataset, canary: $canary, platform: $platform,
          engine: $engine, image_source_policy: $image_source, probe_window: $probe_window,
          pack: $pack, docker_hub_blocked: $block_hub, registry_remap: $remap,
          rq1_cases: $rq1_cases, tools_lock_sha256: (if $lock_sha == "" then null else $lock_sha end),
          started_at: $started, finished_at: null, result: "running", exit_code: null,
          error: null, stages: {}}' > "$STATUS_FILE"
}

stage_begin() {
    CURRENT_STAGE=$1
    status_write --arg n "$1" --arg t "$(now)" '.stages[$n] = {state: "running", started_at: $t}'
}

stage_end() { # name state exit_code
    status_write --arg n "$1" --arg s "$2" --argjson rc "$3" --arg t "$(now)" \
        '.stages[$n] += {state: $s, exit_code: $rc, finished_at: $t}'
    CURRENT_STAGE=''
}

prereq() { # name function
    local name=$1
    shift
    section "PREREQUISITE: $name"
    stage_begin "$name"
    "$@"
    stage_end "$name" ok 0
}

# Per stage bundle checksum. Lists every file below RESULTS_DIR/<dir> with its sha256 in a fixed
# order and records the number of files and the sha256 of that listing in the status file. The
# listing of the whole bundle is REMOTE_SHA256SUMS, this one ties a stage to its own outputs.
stage_outputs() { # name dir-relative-to-RESULTS_DIR
    local name=$1 rel=$2 listing='' f files digest
    if [ -d "$RESULTS_DIR/$rel" ]; then
        while IFS= read -r -d '' f; do
            listing="$listing$(sha256_of "$RESULTS_DIR/$f")  $f"$'\n'
        done < <(cd "$RESULTS_DIR" && find "$rel" -type f -print0 | LC_ALL=C sort -z)
    fi
    files=$(printf '%s' "$listing" | awk 'END { print NR }')
    digest=$(printf '%s' "$listing" | sha256sum | awk '{print $1}')
    status_write --arg n "$name" --arg d "$rel" --argjson f "$files" --arg s "$digest" \
        '.stages[$n] += {outputs: {dir: $d, files: $f, listing_sha256: $s}}'
}

# Record the end of a stage whose command ended with STAGE_RC. 0 is ok, 3 is incomplete (partial
# results are kept), anything else is failed. A stage that claims success but did not write its
# main output (the optional third argument, relative to RESULTS_DIR) is failed with exit code 66.
stage_finish() { # name outputs-dir [required-file]
    local name=$1 rel=${2:-} required=${3:-}
    fix_ownership
    if [ "$STAGE_RC" -eq 0 ] && [ -n "$required" ] && [ ! -s "$RESULTS_DIR/$required" ]; then
        err "$name ended with exit code 0 but $required is missing or empty"
        STAGE_RC=66
    fi
    case "$STAGE_RC" in
        0) stage_end "$name" ok 0; ok "$name complete" ;;
        3) stage_end "$name" incomplete 3; warn "$name incomplete (exit 3): partial results are kept" ;;
        *) stage_end "$name" failed "$STAGE_RC"; err "$name failed with exit code $STAGE_RC" ;;
    esac
    if [ -n "$rel" ]; then stage_outputs "$name" "$rel"; fi
}

# A stage that cannot start for a reason of its own is recorded as failed with the given exit code,
# and the reason goes to its stage log.
stage_fail() { # name exit-code message
    run_stage "$1" bash -c 'echo "$1" >&2; exit "$2"' _ "$3" "$2"
    stage_end "$1" failed "$STAGE_RC"
    err "$1: $3"
}

# A stage whose input file is missing fails with exit code 66 before it runs anything.
stage_missing_input() { # name path description
    stage_fail "$1" 66 "$3 is missing or empty ($2), nothing to do"
}

# The tools and binaries a stage needs must be in place before it starts. Otherwise the stage is
# recorded as failed with exit code 127 and nothing runs. A tool counts as in place when it is on
# PATH and the installer recorded a version for it in host/tool_versions.json.
tool_recorded_version() { jq -r --arg t "$1" '.tools[$t].version // empty' "$RESULTS_DIR/host/tool_versions.json" 2> /dev/null || true; }

stage_guard() { # name
    local name=$1 tool bin missing=''
    for tool in $(stage_tools "$name"); do
        if ! command -v "$tool" > /dev/null 2>&1 || [ -z "$(tool_recorded_version "$tool")" ]; then
            missing="$missing tool:$tool"
        fi
    done
    for bin in $(stage_binaries "$name"); do
        [ -x "$SRC_DIR/bin/$bin" ] || missing="$missing binary:$bin"
    done
    [ -z "$missing" ] && return 0
    section "STAGE: $name"
    stage_begin "$name"
    err "stage $name cannot start, not in place:$missing"
    mkdir -p "$RESULTS_DIR/stage_logs"
    printf '%s stage %s cannot start, not in place:%s\n' "$(now)" "$name" "$missing" >> "$RESULTS_DIR/stage_logs/$name.log"
    stage_end "$name" failed 127
    return 1
}

# Combine two exit codes of one stage: a code other than 0 and 3 wins, then 3, then 0.
combine_rc() {
    local a=$1 b=$2
    if [ "$a" -ne 0 ] && [ "$a" -ne 3 ]; then echo "$a"; return; fi
    if [ "$b" -ne 0 ] && [ "$b" -ne 3 ]; then echo "$b"; return; fi
    if [ "$a" -eq 3 ] || [ "$b" -eq 3 ]; then echo 3; return; fi
    echo 0
}

# ---------------------------------------------------------------- privilege helpers
# pm: podman in the selected mode. In rootful mode the user session variables are removed so
# Podman does not mix rootless runtime directories into a rootful run.
pm() {
    if [ "$MODE" = rootful ]; then
        sudo -n -H env -u XDG_RUNTIME_DIR -u DBUS_SESSION_BUS_ADDRESS "PATH=$PATH" podman "$@"
    else
        podman "$@"
    fi
}

# engine_user: run any command with the privileges of the selected Podman mode. It also hands the
# registry remap to the tool, which records it in run.registry_remap of its result files. sudo
# resets the environment, so the value has to travel through env in the rootful branch.
engine_user() {
    if [ "$MODE" = rootful ]; then
        sudo -n -H env -u XDG_RUNTIME_DIR -u DBUS_SESSION_BUS_ADDRESS "PATH=$PATH" "CONUNIT_REGISTRY_REMAP=$REGISTRY_REMAP_DESC" "$@"
    else
        env "CONUNIT_REGISTRY_REMAP=$REGISTRY_REMAP_DESC" "$@"
    fi
}

fix_ownership() {
    sudo -n chown -R ubuntu:ubuntu "$RESULTS_DIR"
}

# Non-comment, non-blank lines. awk keeps the exit status 0 for files without image lines.
image_lines() { awk '!/^[[:space:]]*(#|$)/' "$1"; }
count_images() { awk 'BEGIN { n = 0 } !/^[[:space:]]*(#|$)/ { n++ } END { print n }' "$1"; }

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

# ---------------------------------------------------------------- exit handling
on_err() {
    FAIL_MSG="line $1: command failed: $2"
}

on_exit() {
    local rc=$?
    trap - EXIT
    if [ "$FINALIZED" != 1 ] && [ -n "$STATUS_FILE" ] && [ -f "$STATUS_FILE" ]; then
        err "aborted with exit code $rc: ${FAIL_MSG:-no message}"
        if [ -n "$CURRENT_STAGE" ]; then
            stage_end "$CURRENT_STAGE" failed "$rc" || true
        fi
        status_write --arg t "$(now)" --argjson rc "$rc" --arg m "${FAIL_MSG:-aborted}" \
            '.result = "failed" | .exit_code = $rc | .error = $m | .finished_at = $t' || true
        fix_ownership || true
    fi
    exit "$rc"
}

# ---------------------------------------------------------------- prerequisites
# run.env is parsed, never sourced, so it cannot overwrite variables of this script.
load_run_env() {
    ENV_RUN_ID=$(sed -n 's/^RUN_ID=//p' "$RUN_ENV")
    ENV_ITERATIONS=$(sed -n 's/^BENCHMARK_ITERATIONS=//p' "$RUN_ENV")
    [[ "$ENV_RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$ ]] || die "$RUN_ENV has no valid RUN_ID"
    [[ "$ENV_ITERATIONS" =~ ^[0-9]+$ ]] || die "$RUN_ENV has no valid BENCHMARK_ITERATIONS"
    [ "$ENV_RUN_ID" = "$RUN_ID" ] || die "this instance belongs to run '$ENV_RUN_ID', not '$RUN_ID'"
}

check_host() {
    local avail os_id os_version c
    [ "$(uname -m)" = x86_64 ] || die "this evaluation is pinned to x86_64 hosts, found $(uname -m)"
    os_id=$(. /etc/os-release && echo "${ID:-?}")
    os_version=$(. /etc/os-release && echo "${VERSION_ID:-?}")
    [ "$os_id" = ubuntu ] && [ "$os_version" = 24.04 ] || die "expected Ubuntu 24.04, found $os_id $os_version"
    sudo -n true || die "passwordless sudo is required"
    for c in jq curl rsync tar awk sha256sum; do
        command -v "$c" > /dev/null || die "required command missing: $c"
    done
    [ -f "$READY_MARKER" ] || die "instance is not ready ($READY_MARKER missing). Check /var/log/con-unit-userdata.log"
    [ -f "$RUN_ENV" ] || die "$RUN_ENV missing"
    load_run_env
    avail=$(df -BG --output=avail "$BASE_DIR" | tail -n 1 | tr -dc '0-9')
    [ "${avail:-0}" -ge "$MIN_FREE_GB" ] || die "only ${avail:-0} GB free under $BASE_DIR, need $MIN_FREE_GB"
    info "host ok: $(uname -sr), Ubuntu $os_version, ${avail} GB free, run.env run id $ENV_RUN_ID, default RQ3 iterations $ENV_ITERATIONS"
}

verify_bundle() {
    local bundle=$INCOMING_DIR/con-unit-bundle.tar.gz actual shipped listing commit_file
    [ -f "$bundle" ] || die "bundle not found: $bundle"
    actual=$(sha256_of "$bundle")
    [ "$actual" = "$BUNDLE_SHA256" ] || die "bundle sha256 mismatch: expected $BUNDLE_SHA256, got $actual"
    if [ -f "$bundle.sha256" ]; then
        shipped=$(awk '{print $1}' "$bundle.sha256")
        [ "$shipped" = "$actual" ] || die "shipped checksum file disagrees with the bundle: $shipped vs $actual"
    fi
    ok "bundle sha256 verified: $actual"

    listing=$(mktemp)
    tar -tzf "$bundle" > "$listing"
    if grep -qE '(^/|(^|/)\.\.(/|$))' "$listing"; then
        rm -f "$listing"
        die "bundle contains absolute or parent-relative paths"
    fi
    rm -f "$listing"

    rm -rf "$SRC_DIR"
    mkdir -p "$SRC_DIR"
    tar -xzf "$bundle" -C "$SRC_DIR" --strip-components=1
    [ -f "$SRC_DIR/go.mod" ] || die "bundle has no go.mod at its root"
    [ -f "$SRC_DIR/$DATASET" ] || die "dataset not in bundle: $DATASET"

    commit_file=$INCOMING_DIR/COMMIT
    if [ -f "$commit_file" ]; then
        grep -q "^commit=$COMMIT$" "$commit_file" || die "COMMIT file does not match --commit $COMMIT"
        cp "$commit_file" "$RESULTS_DIR/bundle_COMMIT.txt"
    else
        warn "no COMMIT file shipped"
    fi
    info "bundle unpacked to $SRC_DIR (commit $COMMIT, kind $BUNDLE_KIND, tainted $TAINTED)"
}

install_go() {
    local tmp entry filename sha
    GO_VERSION=$(awk '$1 == "toolchain" {sub(/^go/, "", $2); print $2; exit}' "$SRC_DIR/go.mod")
    [ -n "$GO_VERSION" ] || GO_VERSION=$(awk '$1 == "go" {print $2; exit}' "$SRC_DIR/go.mod")
    [[ "$GO_VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?((rc|beta)[0-9]+)?$ ]] || die "cannot read a Go version from go.mod (got '$GO_VERSION')"
    info "go.mod requires Go $GO_VERSION"

    tmp=$(mktemp -d)
    curl -fsSL --retry 3 --max-time 120 'https://go.dev/dl/?mode=json&include=all' -o "$tmp/releases.json"
    entry=$(jq -r --arg v "go$GO_VERSION" \
        '.[] | select(.version == $v) | .files[]? | select(.os == "linux" and .arch == "amd64" and .kind == "archive") | "\(.filename) \(.sha256)"' \
        "$tmp/releases.json")
    [ -n "$entry" ] || die "Go $GO_VERSION (linux/amd64) not found in https://go.dev/dl/?mode=json&include=all"
    read -r filename sha <<< "$entry"
    [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "go.dev returned a malformed checksum for $filename"

    curl -fsSL --retry 3 --max-time 600 "https://go.dev/dl/$filename" -o "$tmp/$filename"
    printf '%s  %s\n' "$sha" "$tmp/$filename" | sha256sum -c - || die "Go tarball checksum mismatch for $filename"
    ok "Go tarball $filename verified against go.dev metadata (sha256 $sha)"

    sudo -n rm -rf /usr/local/go
    sudo -n tar -C /usr/local -xzf "$tmp/$filename"
    printf '%s  %s\n' "$sha" "$filename" > "$RESULTS_DIR/host/go_dist.sha256"
    rm -rf "$tmp"

    export PATH=/usr/local/go/bin:$PATH
    export GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0
    export GOPATH=$BASE_DIR/gopath GOCACHE=$BASE_DIR/gocache
    mkdir -p "$GOPATH" "$GOCACHE"
    [ "$(go version)" = "go version go$GO_VERSION linux/amd64" ] || die "unexpected go version: $(go version)"
    ok "$(go version) installed, GOTOOLCHAIN=local"
}

# ---------------------------------------------------------------- external tools (tools.lock)
# The lock file pins name, version, url and sha256 of each tool. A tool is installed only when
#   1. the lock file has the sha256 the operator machine computed (--tools-lock-sha256),
#   2. the lock file is well formed and has no placeholder,
#   3. the download has the pinned sha256, and
#   4. the checksum file that the release itself publishes, fetched from another path than the
#      download, lists the same sha256 for the same file name.
# Afterwards the binary has to run, report the pinned version and be the one that PATH resolves.

# The line of a tool in the lock file, as "version url sha256". Fails when the tool is not listed.
lock_entry() { # name
    awk -v n="$1" '!/^[[:space:]]*(#|$)/ && $1 == n { print $2, $3, $4; found = 1; exit } END { exit !found }' "$TOOLS_LOCK"
}

# Prints every problem of the lock file and returns 1 when there is one. An unverified value is
# written as a placeholder instead of a hash, so it is refused here and never installed.
validate_tools_lock() { # file
    local file=$1 line n=0 bad=0 name version url sha extra seen=' ' tool
    local url_re='^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/releases/download/v[0-9]+\.[0-9]+\.[0-9]+/[A-Za-z0-9._-]+$'
    [ -f "$file" ] || { err "tools lock file not found: $file"; return 1; }
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        if [[ "$line" =~ ^[[:space:]]*(#|$) ]]; then continue; fi
        if [[ "$line" == *$'\r'* ]]; then err "$file:$n: carriage return in line"; bad=1; continue; fi
        name='' version='' url='' sha='' extra=''
        read -r name version url sha extra <<< "$line"
        if [ -z "$sha" ] || [ -n "$extra" ]; then err "$file:$n: expected 4 fields (name version url sha256)"; bad=1; continue; fi
        case " $KNOWN_TOOLS " in
            *" $name "*) ;;
            *) err "$file:$n: unknown tool '$name'"; bad=1; continue ;;
        esac
        case "$seen" in
            *" $name "*) err "$file:$n: tool $name is listed twice"; bad=1; continue ;;
        esac
        seen="$seen$name "
        [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { err "$file:$n: $name version '$version' is not x.y.z"; bad=1; }
        [[ "$url" =~ $url_re ]] || { err "$file:$n: $name url is not a github.com release download url"; bad=1; }
        case "$url" in
            *"/v$version/"*) ;;
            *) err "$file:$n: $name url does not belong to version $version"; bad=1 ;;
        esac
        [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { err "$file:$n: $name sha256 '$sha' is not 64 lowercase hex characters (a placeholder has to be replaced by a verified value)"; bad=1; }
    done < "$file"
    for tool in $KNOWN_TOOLS; do
        case "$seen" in
            *" $tool "*) ;;
            *) err "$file: tool $tool is not pinned"; bad=1 ;;
        esac
    done
    return "$bad"
}

fetch() { curl -fsSL --retry 3 --max-time 600 "$1" -o "$2"; }

# File names under which a release publishes its own checksums, in the order they are tried. They
# sit in the release directory, next to the download and never inside it.
tool_checksum_candidates() { # name version asset
    case $1 in
        dockle) echo "dockle_$2_checksums.txt" ;;
        trivy) echo "trivy_$2_checksums.txt" ;;
        hadolint) echo "$3.sha256 checksums.sha256" ;;
        container-structure-test) echo 'checksums.txt' ;;
    esac
}

# The one hash that a checksum file lists for an asset. Both layouts occur: "<hex>  <name>" and
# "<hex> *<name>". Fails when the asset is listed zero or several times or the hash is malformed.
checksum_for_asset() { # checksum-file asset
    local hash
    hash=$(awk -v f="$2" '{ n = $2; sub(/^\*/, "", n); if (n == f) { print $1; c++ } } END { exit c != 1 }' "$1") || return 1
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$hash"
}

# dockle and trivy ship as an archive that holds the binary under its own name.
tool_is_archive() { case $1 in dockle | trivy) return 0 ;; *) return 1 ;; esac; }

# True when a whitespace separated token of the output is the version, a leading v is ignored. The
# comparison is exact, so 0.4.150 is not 0.4.15. The formats seen at the pinned versions: dockle
# "dockle version 0.4.15", hadolint "Haskell Dockerfile Linter 2.14.0", trivy "Version: 0.76.1",
# container-structure-test "1.22.1" (and "v1.22.1" in the run block).
version_matches() { # output version
    printf '%s\n' "$1" | awk -v v="$2" '{ for (i = 1; i <= NF; i++) { t = $i; sub(/^v/, "", t); if (t == v) f = 1 } } END { exit !f }'
}

# container-structure-test has no --version flag, the others have.
tool_version_output() { # path name
    case $2 in
        container-structure-test) "$1" version 2>&1 ;;
        *) "$1" --version 2>&1 ;;
    esac
}

TOOLS_JSON='{}'

install_one_tool() { # name tmp-dir
    local name=$1 tmp=$2 version url sha asset file actual cand sumfile='' rel members member src dest resolved out first bin_sha
    read -r version url sha <<< "$(lock_entry "$name")"
    asset=${url##*/}
    file=$tmp/$asset
    info "tool $name $version: downloading $url"
    fetch "$url" "$file" || die "tool $name: download failed ($url)"
    actual=$(sha256_of "$file")
    [ "$actual" = "$sha" ] || die "tool $name: sha256 of the download is $actual, tools.lock pins $sha"

    for cand in $(tool_checksum_candidates "$name" "$version" "$asset"); do
        rm -f "$tmp/$name.checksums"
        if fetch "${url%/*}/$cand" "$tmp/$name.checksums" 2> /dev/null; then
            sumfile=${url%/*}/$cand
            break
        fi
    done
    [ -n "$sumfile" ] || die "tool $name: the release has no checksum file under any of the names: $(tool_checksum_candidates "$name" "$version" "$asset")"
    rel=$(checksum_for_asset "$tmp/$name.checksums" "$asset") || die "tool $name: $sumfile does not list $asset exactly once with a valid sha256"
    [ "$rel" = "$sha" ] || die "tool $name: the release checksum file lists $rel for $asset, tools.lock pins $sha"
    ok "tool $name: download matches the pin and the checksum file of the release ($sumfile)"

    src=$file
    if tool_is_archive "$name"; then
        members=$(tar -tzf "$file") || die "tool $name: cannot read the archive $asset"
        member=$(grep -Ex "(\./)?$name" <<< "$members" | head -n 1 || true)
        [ -n "$member" ] || die "tool $name: the archive has no member named $name"
        tar -xzf "$file" -C "$tmp" "$member" || die "tool $name: cannot extract $member"
        src=$tmp/$member
    fi
    dest=$TOOLS_BIN_DIR/$name
    sudo -n install -m 0755 "$src" "$dest" || die "tool $name: cannot install to $dest"
    hash -r
    resolved=$(command -v "$name" || true)
    [ "$resolved" = "$dest" ] || die "tool $name: PATH resolves it to '${resolved:-nothing}' instead of $dest, another binary shadows the pinned one"
    out=$(tool_version_output "$dest" "$name") || die "tool $name: the version command failed: ${out%%$'\n'*}"
    first=${out%%$'\n'*}
    version_matches "$out" "$version" || die "tool $name: the version output '$first' does not carry the pinned version $version"
    bin_sha=$(sha256_of "$dest")
    ok "tool $name installed: $dest ('$first', sha256 $bin_sha)"
    TOOLS_JSON=$(jq --arg n "$name" --arg v "$version" --arg u "$url" --arg d "$sha" --arg c "$sumfile" \
        --arg p "$dest" --arg b "$bin_sha" --arg o "$first" \
        '. + {($n): {version: $v, url: $u, download_sha256: $d, release_checksum_file: $c, binary_path: $p, binary_sha256: $b, version_output: $o}}' <<< "$TOOLS_JSON")
}

# host/tool_versions.json: the pins, what was installed and from where. run_eval.sh copies it into
# the manifest under tool_versions.installed.
write_tool_versions() { # lock-sha256 or empty
    local locked='{}'
    if [ -n "$1" ] && [ -f "$TOOLS_LOCK" ]; then
        locked=$(awk '!/^[[:space:]]*(#|$)/ { print $1 "\t" $2 }' "$TOOLS_LOCK" |
            jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add // {}')
    fi
    jq -n --argjson t "$TOOLS_JSON" --arg l "$1" --argjson locked "$locked" \
        '{schema: "conunit-tool-versions/1", lock_file: "tools.lock", lock_sha256: (if $l == "" then null else $l end), locked: $locked, tools: $t}' \
        > "$RESULTS_DIR/host/tool_versions.json"
    status_write --slurpfile t "$RESULTS_DIR/host/tool_versions.json" '.external_tools = $t[0]'
}

install_tools() {
    local tmp name needed lock_actual
    TOOLS_JSON='{}'
    needed=$(required_tools)
    mkdir -p "$RESULTS_DIR/host"
    if [ -z "$needed" ]; then
        info "no external tool is needed by the requested stages ($STAGES)"
        write_tool_versions ''
        return 0
    fi
    [ -f "$TOOLS_LOCK" ] || die "tools lock file not found: $TOOLS_LOCK (run_eval.sh ships it next to the bundle)"
    lock_actual=$(sha256_of "$TOOLS_LOCK")
    [ "$lock_actual" = "$TOOLS_LOCK_SHA256" ] || die "tools.lock sha256 mismatch: expected $TOOLS_LOCK_SHA256, got $lock_actual"
    validate_tools_lock "$TOOLS_LOCK" || die "tools.lock is not usable, see the lines above"
    cp "$TOOLS_LOCK" "$RESULTS_DIR/host/tools.lock"
    info "tools needed by the requested stages ($(tool_stage_list)): $(tr '\n' ' ' <<< "$needed")"
    tmp=$(mktemp -d)
    for name in $needed; do
        install_one_tool "$name" "$tmp"
    done
    rm -rf "$tmp"
    write_tool_versions "$lock_actual"
    ok "external tools installed and recorded in host/tool_versions.json"
}

# apt may be busy right after boot (unattended-upgrades, cloud-init). Wait for the dpkg lock and retry.
apt_run() {
    local attempt
    for attempt in 1 2 3 4 5 6; do
        if sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 "$@"; then
            return 0
        fi
        warn "apt-get $1 failed (attempt $attempt/6), retrying in 20 seconds"
        sleep 20
    done
    return 1
}

install_packages() {
    local pkg
    local -a absent=()
    apt_run update || die "apt-get update failed"
    # A wrong package name is permanent, apt_run would retry it six times. Check every name first,
    # so that one run reports all names that do not exist on this release.
    for pkg in "${PACKAGES[@]}"; do
        apt-cache show --no-all-versions "$pkg" > /dev/null 2>&1 || absent+=("$pkg")
    done
    [ "${#absent[@]}" -eq 0 ] || die "not available in the apt sources of this release: ${absent[*]}"
    apt_run install -y "${PACKAGES[@]}" || die "apt-get install failed"
    for pkg in "${PACKAGES[@]}"; do
        dpkg -s "$pkg" > /dev/null 2>&1 || die "package not installed after apt-get: $pkg"
    done
    ok "installed: ${PACKAGES[*]}"
}

configure_registry() {
    sudo -n install -d -m 0755 "$(dirname "$REGISTRY_CONF")"
    printf '%s\n' "$REGISTRY_CONF_BODY" | sudo -n tee "$REGISTRY_CONF" > /dev/null
    sudo -n chmod 0644 "$REGISTRY_CONF"
    printf '%s\n' "$REGISTRY_CONF_BODY" | cmp -s - "$REGISTRY_CONF" || die "registry conf content differs from CONTRACT section 9"
    ok "installed $REGISTRY_CONF (single remap: $REGISTRY_REMAP_DESC, no Docker Hub fallback)"
}

block_docker_hub() {
    local addr
    if [ "$BLOCK_HUB" != true ]; then
        warn "Docker Hub is NOT blocked on this host (--block-docker-hub false). A fallback to Docker Hub would be silent."
        return 0
    fi
    sudo -n sed -i "/$HUB_BLOCK_BEGIN/,/$HUB_BLOCK_END/d" /etc/hosts
    {
        echo "$HUB_BLOCK_BEGIN"
        echo "0.0.0.0 $HUB_HOSTS"
        echo "$HUB_BLOCK_END"
    } | sudo -n tee -a /etc/hosts > /dev/null
    addr=$(getent ahostsv4 registry-1.docker.io | awk 'NR == 1 {print $1}')
    [ "$addr" = 0.0.0.0 ] || die "Docker Hub block did not take effect (registry-1.docker.io resolves to '$addr')"
    if curl -sS -m 5 -o /dev/null https://registry-1.docker.io/v2/ 2> /dev/null; then
        die "Docker Hub is still reachable after the block"
    fi
    ok "Docker Hub hosts resolve to 0.0.0.0: any fallback to Docker Hub fails loudly"
}

prepare_mode() {
    if [ "$MODE" = rootless ]; then
        grep -q '^ubuntu:' /etc/subuid || sudo -n usermod --add-subuids 100000-165535 ubuntu
        grep -q '^ubuntu:' /etc/subgid || sudo -n usermod --add-subgids 100000-165535 ubuntu
        [ -e /var/lib/systemd/linger/ubuntu ] || die "lingering is not enabled for ubuntu"
        XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
        export XDG_RUNTIME_DIR
        [ -d "$XDG_RUNTIME_DIR" ] || die "XDG_RUNTIME_DIR $XDG_RUNTIME_DIR does not exist"
    fi
    info "engine mode: $MODE"
}

# The 10 image dataset is read by the rq3 benchmark and by the reliability repeats. In canary mode
# both get the same first N lines of it, which is the small reliability subset of the canary.
derive_datasets() {
    local n_eval n_top
    EVAL_DATASET_PATH=$DATASET
    RQ3_DATASET_PATH=$RQ3_DATASET
    if [ "$CANARY" -gt 0 ]; then
        EVAL_DATASET_PATH=fixtures/evaluation_dataset_canary.txt
        RQ3_DATASET_PATH=fixtures/evaluation_dataset_top10_canary.txt
        image_lines "$SRC_DIR/$DATASET" | awk -v n="$CANARY" 'NR <= n' > "$SRC_DIR/$EVAL_DATASET_PATH"
        if top10_needed; then
            [ -f "$SRC_DIR/$RQ3_DATASET" ] || die "10 image dataset not in bundle: $RQ3_DATASET"
            image_lines "$SRC_DIR/$RQ3_DATASET" | awk -v n="$CANARY" 'NR <= n' > "$SRC_DIR/$RQ3_DATASET_PATH"
        fi
        warn "CANARY mode: first $CANARY image lines only ($EVAL_DATASET_PATH). Results are not a study result."
    elif top10_needed; then
        [ -f "$SRC_DIR/$RQ3_DATASET" ] || die "10 image dataset not in bundle: $RQ3_DATASET"
    fi
    RELIABILITY_DATASET_PATH=$RQ3_DATASET_PATH
    [ -s "$SRC_DIR/$EVAL_DATASET_PATH" ] || die "dataset is empty: $EVAL_DATASET_PATH"
    n_eval=$(count_images "$SRC_DIR/$EVAL_DATASET_PATH")
    [ "$n_eval" -gt 0 ] || die "dataset has no image lines: $EVAL_DATASET_PATH"
    status_write --arg e "$EVAL_DATASET_PATH" --arg es "$(sha256_of "$SRC_DIR/$EVAL_DATASET_PATH")" \
        --argjson en "$n_eval" '.dataset_used = {path: $e, sha256: $es, entries: $en}'
    if top10_needed; then
        n_top=$(count_images "$SRC_DIR/$RQ3_DATASET_PATH")
        [ "$n_top" -gt 0 ] || die "10 image dataset has no image lines: $RQ3_DATASET_PATH"
        status_write --arg p "$RQ3_DATASET_PATH" --arg s "$(sha256_of "$SRC_DIR/$RQ3_DATASET_PATH")" \
            --argjson n "$n_top" '.rq3_dataset_used = {path: $p, sha256: $s, entries: $n}'
        info "10 image dataset (rq3, reliability): $RQ3_DATASET_PATH ($n_top images)"
        if stage_requested reliability; then
            status_write --arg p "$RELIABILITY_DATASET_PATH" --arg s "$(sha256_of "$SRC_DIR/$RELIABILITY_DATASET_PATH")" \
                --argjson n "$n_top" '.reliability_dataset_used = {path: $p, sha256: $s, entries: $n}'
        fi
    fi
    info "eval dataset: $EVAL_DATASET_PATH ($n_eval images)"
}

pick_proof_ref() {
    local f=$SRC_DIR/$EVAL_DATASET_PATH ref
    ref=$(image_lines "$f" | awk '/\/library\/busybox@/ && !done {print; done = 1}')
    [ -n "$ref" ] || ref=$(image_lines "$f" | awk '/\/library\/alpine@/ && !done {print; done = 1}')
    [ -n "$ref" ] || ref=$(image_lines "$f" | awk 'NR == 1')
    [ -n "$ref" ] || die "no image reference found for the mirror proof"
    printf '%s' "$ref"
}

mirror_proof() {
    local log=$RESULTS_DIR/host/mirror_proof_pull.log ref
    ref=$(pick_proof_ref)
    PROOF_REF=$ref
    info "proof image: $ref"
    # Start from a clean slate so the pull really goes to a registry.
    pm rmi -f "$ref" > /dev/null 2>&1 || true
    if ! pm pull --log-level=debug --platform "$PLATFORM" "$ref" > "$log" 2>&1; then
        tail -n 30 "$log" >&2
        die "podman pull of the proof image failed (full debug log: host/mirror_proof_pull.log)"
    fi
    grep -q 'public\.ecr\.aws' "$log" || die "the debug log never mentions public.ecr.aws: the registry remap is NOT active"
    if grep -q 'registry-1\.docker\.io' "$log"; then
        die "the debug log mentions registry-1.docker.io: Podman contacted Docker Hub"
    fi
    ok "remap proven: pull of $ref went to public.ecr.aws (debug log saved)"
    status_write --arg r "$PROOF_REF" \
        '.mirror_proof = {proof_image: $r, public_ecr_in_debug_log: true, docker_hub_in_debug_log: false, log: "host/mirror_proof_pull.log"}'

    case "$ref" in
        */library/busybox@* | */library/alpine@*)
            pm run --rm --network=none --pids-limit=64 "$ref" true || die "podman run smoke check failed"
            ok "smoke: podman run works in $MODE mode"
            ;;
        *)
            warn "smoke run skipped: dataset has neither busybox nor alpine to run safely"
            ;;
    esac

    # Remove the proof image so every dataset image follows the same pull path in the eval.
    pm rmi -f "$ref" > /dev/null
    if pm image exists "$ref"; then
        die "proof image could not be removed"
    fi
    info "proof image removed from the local store"
}

collect_host_info() {
    local h=$RESULTS_DIR/host token='' p
    {
        echo "# uname -a"
        uname -a
        echo
        echo "# /etc/os-release"
        cat /etc/os-release
        echo
        echo "# systemd-detect-virt"
        systemd-detect-virt || true
        echo
        echo "# DMI"
        for f in sys_vendor product_name bios_vendor bios_version; do
            printf '%s=%s\n' "$f" "$(cat "/sys/class/dmi/id/$f" 2> /dev/null || echo unknown)"
        done
        echo
        echo "# cgroup"
        stat -f -c 'fs_type=%T' /sys/fs/cgroup
        cat /sys/fs/cgroup/cgroup.controllers 2> /dev/null || true
        echo
        echo "# storage"
        df -hT "$BASE_DIR" /var/lib/containers 2> /dev/null || df -hT "$BASE_DIR"
        findmnt -no SOURCE,FSTYPE,OPTIONS /
        echo
        echo "# memory"
        grep -E '^(MemTotal|MemAvailable|SwapTotal):' /proc/meminfo
        echo
        echo "# kernel parameters"
        sysctl user.max_user_namespaces kernel.unprivileged_userns_clone 2> /dev/null || true
    } > "$h/system.txt" 2>&1
    uname -a > "$h/uname.txt"
    lscpu > "$h/lscpu.txt"
    lscpu -J > "$h/lscpu.json" 2> /dev/null || true

    dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' | sort > "$h/dpkg_versions_all.tsv"
    : > "$h/dpkg_versions_runtime.tsv"
    for p in "${RECORDED_PACKAGES[@]}"; do
        dpkg-query -W -f='${Package}\t${Version}\n' "$p" >> "$h/dpkg_versions_runtime.tsv" 2> /dev/null || printf '%s\tnot-installed\n' "$p" >> "$h/dpkg_versions_runtime.tsv"
    done

    pm info > "$h/podman_info.txt" 2>&1 || die "podman info failed"
    pm info --format json > "$h/podman_info.json" 2> /dev/null || true
    pm version > "$h/podman_version.txt" 2>&1 || true
    {
        echo "# $REGISTRY_CONF"
        cat "$REGISTRY_CONF"
        echo
        echo "# /etc/containers/registries.conf"
        cat /etc/containers/registries.conf 2> /dev/null || echo "(absent)"
        echo
        echo "# /etc/containers/registries.conf.d/"
        ls -la /etc/containers/registries.conf.d/
    } > "$h/registries_conf.txt"
    grep -n -A3 "$HUB_BLOCK_BEGIN" /etc/hosts > "$h/docker_hub_block.txt" 2> /dev/null || echo "docker hub block not installed" > "$h/docker_hub_block.txt"
    systemctl list-timers con-unit-watchdog.timer --no-pager > "$h/watchdog_timer.txt" 2>&1 || true

    token=$(curl -fsS -m 3 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 120' http://169.254.169.254/latest/api/token 2> /dev/null) || token=''
    imds() { curl -fsS -m 3 -H "X-aws-ec2-metadata-token: $token" "http://169.254.169.254/latest/meta-data/$1" 2> /dev/null || echo unknown; }
    jq -n --arg id "$(imds instance-id)" --arg type "$(imds instance-type)" --arg ami "$(imds ami-id)" \
        --arg az "$(imds placement/availability-zone)" --arg region "$(imds placement/region)" \
        '{instance_id: $id, instance_type: $type, ami_id: $ami, availability_zone: $az, region: $region}' > "$h/imds.json"

    local host_rootless host_cgroups host_runtime host_graph
    host_rootless=$(pm info --format '{{.Host.Security.Rootless}}' 2> /dev/null || echo unknown)
    host_cgroups=$(pm info --format '{{.Host.CgroupsVersion}}' 2> /dev/null || echo unknown)
    host_runtime=$(pm info --format '{{.Host.OCIRuntime.Name}} {{.Host.OCIRuntime.Version}}' 2> /dev/null | head -n 1 || echo unknown)
    host_graph=$(pm info --format '{{.Store.GraphDriverName}}' 2> /dev/null || echo unknown)
    if [ "$MODE" = rootful ] && [ "$host_rootless" != false ]; then die "rootful mode requested but podman reports rootless=$host_rootless"; fi
    if [ "$MODE" = rootless ] && [ "$host_rootless" != true ]; then die "rootless mode requested but podman reports rootless=$host_rootless"; fi
    [ "$host_cgroups" = v2 ] || warn "podman reports cgroups $host_cgroups, expected v2"

    jq -n --arg go "$(go version)" --arg podman "$(podman --version)" \
        --arg crun "$(crun --version 2> /dev/null | head -n 1 || echo absent)" \
        --arg conmon "$(conmon --version 2> /dev/null | head -n 1 || echo absent)" \
        --arg kernel "$(uname -r)" --arg rootless "$host_rootless" --arg cgroups "$host_cgroups" \
        --arg runtime "$host_runtime" --arg graph "$host_graph" --arg mode "$MODE" \
        --arg netavark "$(dpkg-query -W -f='${Version}' netavark 2> /dev/null || echo absent)" \
        --arg syft "$(command -v syft > /dev/null && syft version 2> /dev/null | head -n 1 || echo absent)" \
        '{go: $go, podman: $podman, crun: $crun, conmon: $conmon, netavark: $netavark, kernel: $kernel,
          podman_rootless: $rootless, cgroups: $cgroups, oci_runtime: $runtime, storage_driver: $graph,
          engine_mode: $mode, syft: $syft}' > "$h/versions.json"
    status_write --slurpfile v "$h/versions.json" --slurpfile i "$h/imds.json" '.tool_versions = $v[0] | .imds = $i[0]'
    ok "host facts recorded: kernel $(uname -r), podman rootless=$host_rootless, cgroups $host_cgroups, runtime $host_runtime, storage $host_graph"
}

build_tools() {
    local ldflags
    ldflags="-X github.com/con-unit/con-unit/pkg/runenv.BuildCommit=$COMMIT -X github.com/con-unit/con-unit/pkg/runenv.BuildTainted=$TAINTED"
    cd "$SRC_DIR"
    mkdir -p bin
    go mod download
    go mod verify
    go build -buildvcs=false -trimpath -ldflags "$ldflags" -o bin/con-unit ./cmd/con-unit
    go build -buildvcs=false -trimpath -ldflags "$ldflags" -o bin/export_latex ./tools/export_latex.go
    go build -buildvcs=false -trimpath -ldflags "$ldflags" -o bin/benchmark_rq3 ./tools/benchmark_rq3
    go build -buildvcs=false -trimpath -ldflags "$ldflags" -o bin/rq1 ./tools/rq1
    go build -buildvcs=false -trimpath -ldflags "$ldflags" -o bin/crosscheck ./tools/crosscheck
    go build -buildvcs=false -trimpath -ldflags "$ldflags" -o bin/attribute_exec ./tools/attribute_exec
    go build -buildvcs=false -trimpath -ldflags "$ldflags" -o bin/reliability ./tools/reliability
    {
        echo "# go.sum sha256"
        sha256_of go.sum
        echo
        echo "# build flags: CGO_ENABLED=$CGO_ENABLED GOTOOLCHAIN=$GOTOOLCHAIN GOFLAGS=$GOFLAGS -trimpath -ldflags \"$ldflags\""
        echo
        for b in bin/con-unit bin/export_latex bin/benchmark_rq3 bin/rq1 bin/crosscheck bin/attribute_exec bin/reliability; do
            echo "# $b sha256 $(sha256_of "$b")"
            go version -m "$b"
            echo
        done
    } > "$RESULTS_DIR/host/build_info.txt"
    ok "built con-unit, export_latex, benchmark_rq3, rq1, crosscheck, attribute_exec, reliability (commit $COMMIT, tainted $TAINTED)"
}

# ---------------------------------------------------------------- stages
run_stage() { # name command...
    local name=$1 rc=0
    shift
    section "STAGE: $name"
    stage_begin "$name"
    info "command: $*"
    set +e
    "$@" 2>&1 | tee "$RESULTS_DIR/stage_logs/$name.log"
    rc=${PIPESTATUS[0]}
    set -e
    STAGE_RC=$rc
}

stage_eval() {
    local -a cmd=(bin/con-unit eval --images "$EVAL_DATASET_PATH" --pack "$PACK" --out-dir "$RESULTS_DIR"
        --engine "$ENGINE" --platform "$PLATFORM" --image-source "$IMAGE_SOURCE" --probe-window "$PROBE_WINDOW")
    [ "$RESUME" = 1 ] && cmd+=(--resume)
    cd "$SRC_DIR"
    run_stage eval engine_user "${cmd[@]}"
    fix_ownership
    case "$STAGE_RC" in
        0) stage_end eval ok 0; ok "eval complete: every image produced a COMPLETED record" ;;
        3) stage_end eval incomplete 3; warn "eval incomplete (exit 3): some images did not complete. Partial results are kept and will be exported." ;;
        *) stage_end eval failed "$STAGE_RC"; err "eval failed with exit code $STAGE_RC" ;;
    esac
}

# The run block of empirical_study.json must carry the environment facts the paper reports.
# runenv.Detect never fails a run and leaves unknown facts empty (podman info can exceed its
# time cap on a cold host), so an empty fact is caught here instead of silently reaching the paper.
# Applies to every run, the canary exists to surface exactly this.
#
# The run block also has to carry the version of every external tool that a requested stage needs,
# and it has to be the pinned one: run.tools is what the evaluation process saw on its PATH, the
# lock file says what was meant to be installed. A tool that is absent, of unknown version or of
# another version fails the check.
run_block_missing_tools() { # study-json -> prints the failing entries, one per word
    local json=$1 tool want got
    for tool in $(required_tools); do
        want=$(lock_entry "$tool" 2> /dev/null | awk '{print $1}') || want=''
        got=$(jq -r --arg t "$tool" '.run.tools[$t] // empty' "$json") || got=''
        if [ -z "$want" ] || [ -z "$got" ]; then
            printf 'tools.%s ' "$tool"
        elif ! version_matches "$got" "$want"; then
            printf 'tools.%s(%s,pinned:%s) ' "$tool" "$got" "$want"
        fi
    done
}

stage_run_block() {
    local json=$RESULTS_DIR/empirical_study.json missing='' f
    if [ ! -s "$json" ]; then
        run_stage run_block_check bash -c 'echo "empirical_study.json is missing or empty, cannot check the run block" >&2; exit 66'
        stage_end run_block_check failed "$STAGE_RC"
        return 0
    fi
    stage_begin run_block_check
    section "STAGE: run_block_check"
    for f in engine_version cgroup_version ami_id registry_remap; do
        if [ -z "$(jq -r --arg f "$f" '.run[$f] // empty' "$json")" ]; then missing="$missing $f"; fi
    done
    if [ "$(jq -r '.run.rootless | type' "$json")" != boolean ]; then missing="$missing rootless"; fi
    f=$(run_block_missing_tools "$json")
    [ -z "$f" ] || missing="$missing ${f% }"
    # tainted is omitted by the tool when false, so absence is shown as false
    jq '{engine_name: .run.engine_name, engine_version: .run.engine_version, rootless: .run.rootless, cgroup_version: .run.cgroup_version, storage_driver: .run.storage_driver, oci_runtime: .run.oci_runtime, virtualization: .run.virtualization, execution_mode: .run.execution_mode, instance_type: .run.instance_type, ami_id: .run.ami_id, commit: .run.commit, tainted: (.run.tainted // false), registry_remap: .run.registry_remap}' "$json" | tee "$RESULTS_DIR/host/run_block_summary.json"
    if [ -n "$missing" ]; then
        err "run block is missing facts:$missing"
        stage_end run_block_check failed 1
    else
        stage_end run_block_check ok 0
        ok "run block carries engine_version, rootless, cgroup_version, ami_id, registry_remap and the tool versions of the requested stages"
    fi
}

stage_export() {
    local -a cmd=(bin/export_latex -out "$RESULTS_DIR")
    cd "$SRC_DIR"
    if [ ! -s "$RESULTS_DIR/empirical_study.json" ]; then
        run_stage export bash -c 'echo "empirical_study.json is missing or empty, nothing to export" >&2; exit 66'
        stage_end export failed "$STAGE_RC"
        err "export skipped: no empirical_study.json"
        return 0
    fi
    if [ -f fixtures/evaluation_dataset_audit.json ]; then
        cmd+=(-audit fixtures/evaluation_dataset_audit.json)
    else
        warn "fixtures/evaluation_dataset_audit.json is not in the bundle: flow macros will lack candidate and pinned counts"
    fi
    # The tag counts (alpine, slim) are read from the pinned dataset. Without it they would print
    # n/a in the paper, so a missing file fails the stage instead of leaving a silent hole.
    if [ ! -s fixtures/evaluation_dataset_pinned.json ]; then
        stage_missing_input export fixtures/evaluation_dataset_pinned.json "pinned dataset metadata"
        return 0
    fi
    cmd+=(-pinned fixtures/evaluation_dataset_pinned.json)
    cmd+=("$RESULTS_DIR/empirical_study.json")
    run_stage export "${cmd[@]}"
    fix_ownership
    if [ "$STAGE_RC" -eq 0 ]; then
        stage_end export ok 0
        ok "export complete"
    else
        stage_end export failed "$STAGE_RC"
        err "export failed with exit code $STAGE_RC"
    fi
}

stage_rq3() {
    local iterations=${RQ3_ITERATIONS:-$ENV_ITERATIONS}
    local -a cmd=(bin/benchmark_rq3 -file "$RQ3_DATASET_PATH" -pack "$PACK" -out-dir "$RESULTS_DIR/rq3"
        -iterations "$iterations" -warmup "$RQ3_WARMUP" -platform "$PLATFORM"
        -probe-window "$PROBE_WINDOW" -engine "$ENGINE" -image-source "$IMAGE_SOURCE"
        -dockle dockle)
    cd "$SRC_DIR"
    stage_guard rq3 || return 0
    mkdir -p "$RESULTS_DIR/rq3"
    status_write --argjson it "$iterations" --argjson wu "$RQ3_WARMUP" '.rq3_parameters = {iterations: $it, warmup: $wu}'
    run_stage rq3 engine_user "${cmd[@]}"
    fix_ownership
    if [ "$STAGE_RC" -eq 0 ]; then
        stage_end rq3 ok 0
        ok "rq3 complete"
    else
        stage_end rq3 failed "$STAGE_RC"
        err "rq3 failed with exit code $STAGE_RC"
    fi
}

# ---------------------------------------------------------------- RQ1 (stage rq1)
# The first RQ1_CASES case ids of the oracle, comma separated. Empty when all cases run.
rq1_case_list() {
    [ "$RQ1_CASES" -gt 0 ] || return 0
    jq -r '.cases[].id' "$SRC_DIR/fixtures/rq1/oracle.json" | awk -v n="$RQ1_CASES" 'NR <= n' | paste -sd, -
}

# The RQ1 benchmark builds its images on this host and keeps them (-keep-images), so the seeded
# images exist for the attribution afterwards. All four scanners must run: -require-all turns a
# scanner that was not run into exit code 3. Trivy gets its offline settings from the environment.
# -require-all is passed for a full run only. With a case selection (--rq1-cases, the canary) the
# cases outside it are NOT_RUN by design, so the flag would end every such run incomplete. The
# scanners themselves are still required there, by stage_guard before the stage starts.
stage_rq1() {
    local cases=''
    cd "$SRC_DIR"
    stage_guard rq1 || return 0
    if [ ! -s fixtures/rq1/oracle.json ]; then
        stage_missing_input rq1 fixtures/rq1/oracle.json "the RQ1 oracle"
        return 0
    fi
    cases=$(rq1_case_list) || cases=''
    if [ "$RQ1_CASES" -gt 0 ] && [ -z "$cases" ]; then
        stage_fail rq1 65 "--rq1-cases $RQ1_CASES selects no case of fixtures/rq1/oracle.json"
        return 0
    fi
    local -a cmd=(env "${TRIVY_OFFLINE_ENV[@]}" bin/rq1 -oracle fixtures/rq1/oracle.json -out-dir "$RESULTS_DIR/rq1"
        -conunit "$SRC_DIR/bin/con-unit" -engine "$ENGINE" -keep-images)
    if [ -n "$cases" ]; then cmd+=(-cases "$cases"); else cmd+=(-require-all); fi
    mkdir -p "$RESULTS_DIR/rq1"
    status_write --arg c "$cases" '.rq1_case_selection = (if $c == "" then "all" else $c end)'
    run_stage rq1 engine_user "${cmd[@]}"
    stage_finish rq1 rq1 rq1/rq1_results.json
}

# ---------------------------------------------------------------- lint (stage lint)
# The static image lint pack over the eval dataset. The image source follows the run, so after an
# eval stage the images come from the local store.
stage_lint() {
    local -a cmd=(bin/con-unit eval --images "$EVAL_DATASET_PATH" --pack lint --out-dir "$RESULTS_DIR/lint"
        --engine "$ENGINE" --platform "$PLATFORM" --image-source "$IMAGE_SOURCE")
    if [ "$RESUME" = 1 ]; then cmd+=(--resume); fi
    cd "$SRC_DIR"
    stage_guard lint || return 0
    mkdir -p "$RESULTS_DIR/lint"
    run_stage lint engine_user "${cmd[@]}"
    stage_finish lint lint lint/empirical_study.json
}

# ---------------------------------------------------------------- crosscheck (stage crosscheck)
stage_crosscheck() {
    local study=$RESULTS_DIR/lint/empirical_study.json
    local -a cmd=(bin/crosscheck -study "$study" -dockle dockle -engine "$ENGINE" -platform "$PLATFORM"
        -out-dir "$RESULTS_DIR/crosscheck")
    cd "$SRC_DIR"
    stage_guard crosscheck || return 0
    if [ ! -s "$study" ]; then
        stage_missing_input crosscheck "$study" "the lint study (stage lint has to run first)"
        return 0
    fi
    mkdir -p "$RESULTS_DIR/crosscheck"
    run_stage crosscheck engine_user "${cmd[@]}"
    stage_finish crosscheck crosscheck crosscheck/crosscheck.json
}

# ---------------------------------------------------------------- attribute, ablate (one out-dir)
# attribute, the truth run and ablate share $RESULTS_DIR/attribution, so that the table and the
# macros of the attribution come from one place. The order is: study run, truth run, ablation.
SEEDED_TRUTH=fixtures/rq1/tier3_truth.json

seeded_prefix() { jq -r '.image_prefix // "localhost/conunit-rq1"' "$SRC_DIR/$SEEDED_TRUTH"; }
seeded_case_ids() { jq -r '.cases[].case' "$SRC_DIR/$SEEDED_TRUTH"; }
# The image of a case is <image_prefix>/<case>:rq1 (interface contract, section 4).
seeded_images() { jq -r '(.image_prefix // "localhost/conunit-rq1") as $p | .cases[].case | "\($p)/\(.):rq1"' "$SRC_DIR/$SEEDED_TRUTH"; }

# The seeded images that the engine store does not have, one per line.
seeded_missing() {
    local ref
    while IFS= read -r ref; do
        pm image exists "$ref" < /dev/null > /dev/null 2>&1 || printf '%s\n' "$ref"
    done < <(seeded_images)
}

# Make sure the seeded images are in the store. Run B has no rq1 stage, so they are built here with
# the RQ1 builder (only ConUnit runs on them, to get them built). The outcome goes to SEEDED_STATE:
# present, built, no-truth-file or unavailable. Returns 1 when they are not there afterwards.
prepare_seeded_images() {
    local missing prefix cases rc=0
    SEEDED_STATE=unavailable
    if [ ! -s "$SRC_DIR/$SEEDED_TRUTH" ]; then
        SEEDED_STATE=no-truth-file
        return 1
    fi
    missing=$(seeded_missing) || missing=unknown
    if [ -z "$missing" ]; then
        SEEDED_STATE=present
        return 0
    fi
    prefix=$(seeded_prefix)
    cases=$(seeded_case_ids | paste -sd, -)
    info "seeded images absent ($(tr '\n' ' ' <<< "$missing")), building them with bin/rq1"
    engine_user bin/rq1 -oracle fixtures/rq1/oracle.json -out-dir "$RESULTS_DIR/attribution/seeded_build" \
        -conunit "$SRC_DIR/bin/con-unit" -engine "$ENGINE" -tools conunit -cases "$cases" \
        -image-prefix "$prefix" -keep-images || rc=$?
    missing=$(seeded_missing) || missing=unknown
    if [ -z "$missing" ]; then
        SEEDED_STATE=built
        return 0
    fi
    err "seeded images still absent after the build (rq1 exit code $rc): $(tr '\n' ' ' <<< "$missing")"
    return 1
}

attribute_runs() {
    local rc=0 rc_truth=0
    local -a base=(bin/attribute_exec -engine "$ENGINE" -out-dir "$RESULTS_DIR/attribution")
    info "attribution of the real failures in the study"
    engine_user "${base[@]}" -study "$RESULTS_DIR/empirical_study.json" || rc=$?
    if prepare_seeded_images; then
        info "attribution of the seeded images (state: $SEEDED_STATE)"
        engine_user "${base[@]}" -truth "$SEEDED_TRUTH" -image-prefix "$(seeded_prefix)" || rc_truth=$?
    else
        warn "seeded images unavailable (state: $SEEDED_STATE): no truth run, the stage ends incomplete"
        rc_truth=3
    fi
    status_write --arg s "$SEEDED_STATE" --argjson rc "$rc_truth" '.stages.attribute.seeded = {state: $s, truth_run_exit_code: $rc}'
    return "$(combine_rc "$rc" "$rc_truth")"
}

stage_attribute() {
    local study=$RESULTS_DIR/empirical_study.json
    cd "$SRC_DIR"
    stage_guard attribute || return 0
    if [ ! -s "$study" ]; then
        stage_missing_input attribute "$study" "the study (stage eval has to run first)"
        return 0
    fi
    mkdir -p "$RESULTS_DIR/attribution"
    run_stage attribute attribute_runs
    stage_finish attribute attribution attribution/attribution.json
}

stage_ablate() {
    local study=$RESULTS_DIR/empirical_study.json
    local -a cmd=(bin/attribute_exec -ablation -study "$study" -engine "$ENGINE" -out-dir "$RESULTS_DIR/attribution")
    cd "$SRC_DIR"
    stage_guard ablate || return 0
    if [ ! -s "$study" ]; then
        stage_missing_input ablate "$study" "the study (stage eval has to run first)"
        return 0
    fi
    mkdir -p "$RESULTS_DIR/attribution"
    run_stage ablate engine_user "${cmd[@]}"
    stage_finish ablate attribution attribution/ablation.json
}

# ---------------------------------------------------------------- reliability (stage reliability)
# Three repeats of the 10 image eval at the short window, one run each at the mid and long window.
# The images stay in the store for all five runs: nothing here removes an image, and every image is
# in the store before the first run, so no repeat differs from another by its pull path.
ensure_images_local() { # dataset-file
    local ref rc=0
    while IFS= read -r ref; do
        if pm image exists "$ref" < /dev/null > /dev/null 2>&1; then continue; fi
        info "pulling $ref into the store"
        pm pull --quiet --platform "$PLATFORM" "$ref" < /dev/null > /dev/null || { err "cannot pull $ref"; rc=1; }
    done < <(image_lines "$1")
    return "$rc"
}

reliability_runs() {
    local dir=$RESULTS_DIR/reliability name window spec rc worst=0 missing=''
    local -a cmd
    : > "$dir/run_exit_codes.tsv"
    ensure_images_local "$RELIABILITY_DATASET_PATH" || return 1
    for spec in "r1 $REL_W_SHORT" "r2 $REL_W_SHORT" "r3 $REL_W_SHORT" "w10 $REL_W_MID" "w30 $REL_W_LONG"; do
        read -r name window <<< "$spec"
        cmd=(bin/con-unit eval --images "$RELIABILITY_DATASET_PATH" --pack "$PACK" --out-dir "$dir/$name"
            --engine "$ENGINE" --platform "$PLATFORM" --image-source "$IMAGE_SOURCE" --probe-window "$window")
        if [ "$RESUME" = 1 ]; then cmd+=(--resume); fi
        info "reliability run $name: window $window"
        rc=0
        engine_user "${cmd[@]}" || rc=$?
        printf '%s\t%s\t%s\n' "$name" "$window" "$rc" >> "$dir/run_exit_codes.tsv"
        worst=$(combine_rc "$worst" "$rc")
    done
    for name in r1 r2 r3 w10 w30; do
        [ -s "$dir/$name/empirical_study.json" ] || missing="$missing $name"
    done
    if [ -n "$missing" ]; then
        err "no study for:$missing, the summary is not computed"
        return "$(combine_rc "$worst" 1)"
    fi
    fix_ownership
    rc=0
    bin/reliability -runs "r1=$dir/r1,r2=$dir/r2,r3=$dir/r3" -windows "w3=$dir/r1,w10=$dir/w10,w30=$dir/w30" \
        -out-dir "$dir" || rc=$?
    return "$(combine_rc "$worst" "$rc")"
}

stage_reliability() {
    local dir=$RESULTS_DIR/reliability runs='{}'
    cd "$SRC_DIR"
    stage_guard reliability || return 0
    mkdir -p "$dir"
    run_stage reliability reliability_runs
    if [ -s "$dir/run_exit_codes.tsv" ]; then
        runs=$(jq -R -s '[split("\n")[] | select(length > 0) | split("\t") | {(.[0]): {window: .[1], exit_code: (.[2] | tonumber)}}] | add // {}' "$dir/run_exit_codes.tsv")
    fi
    status_write --argjson r "$runs" '.stages.reliability.runs = $r'
    stage_finish reliability reliability reliability/reliability.json
}

post_run_facts() {
    {
        echo "# podman images after the run"
        pm images --digests 2>&1 || true
        echo
        echo "# disk"
        df -hT "$BASE_DIR" 2>&1 || true
    } > "$RESULTS_DIR/host/after_run.txt"
}

# ---------------------------------------------------------------- finalize
finalize() {
    local result code
    status_write --arg t "$(now)" '
        .finished_at = $t
        | .result = (
            if ([.stages[] | select(.state == "failed")] | length) > 0 then "failed"
            elif ([.stages_requested[] as $s | select((.stages[$s].state // "missing") == "missing")] | length) > 0 then "failed"
            elif ([.stages[] | select(.state == "incomplete")] | length) > 0 then "incomplete"
            else "complete" end)'
    result=$(jq -r .result "$STATUS_FILE")
    case "$result" in
        complete) code=0 ;;
        incomplete) code=3 ;;
        *) code=1 ;;
    esac
    status_write --argjson c "$code" '.exit_code = $c'
    FINALIZED=1
    fix_ownership
    (
        cd "$RESULTS_DIR"
        find . -type f ! -name REMOTE_SHA256SUMS ! -name BENCHMARK_COMPLETE ! -name remote_eval.log -print0 |
            LC_ALL=C sort -z | xargs -0 sha256sum > REMOTE_SHA256SUMS
    )
    cp "$STATUS_FILE" "$RESULTS_DIR/BENCHMARK_COMPLETE"
    fix_ownership
    section "RESULT: $result"
    jq -r '.stages | to_entries[] | "  \(.key | . + "                    " | .[0:18]) \(.value.state)  exit=\(.value.exit_code)"' "$STATUS_FILE"
    info "status file:      $STATUS_FILE"
    info "completion marker: $RESULTS_DIR/BENCHMARK_COMPLETE (written after all requested stages ran)"
    return "$code"
}

# ---------------------------------------------------------------- main
main() {
    local code=0
    exec < /dev/null
    parse_args "$@"
    validate_args

    # Survive a dropped SSH connection: the log goes to a file and tee -p ignores a closed
    # stdout, so losing the connection never kills the run.
    trap '' HUP
    command -v jq > /dev/null || {
        echo "jq is required (installed by user_data.sh)" >&2
        exit 2
    }

    RESULTS_DIR=$BASE_DIR/results/$RUN_ID
    STATUS_FILE=$RESULTS_DIR/status.json
    if [ -e "$STATUS_FILE" ] && [ "$RESUME" != 1 ]; then
        echo "results directory $RESULTS_DIR already has a status file. Use --resume or a new run id." >&2
        exit 2
    fi
    mkdir -p "$RESULTS_DIR/host" "$RESULTS_DIR/stage_logs"
    exec > >(tee -p -a "$RESULTS_DIR/remote_eval.log") 2>&1

    section "ConUnit remote evaluation, run $RUN_ID"
    info "commit $COMMIT, tag ${TAG:-none}, bundle $BUNDLE_KIND, tainted $TAINTED"
    info "mode $MODE, stages $STAGES, pack $PACK, platform $PLATFORM, image-source $IMAGE_SOURCE, window $PROBE_WINDOW"

    status_init
    trap on_exit EXIT
    trap 'on_err "$LINENO" "$BASH_COMMAND"' ERR

    prereq host check_host
    prereq bundle verify_bundle
    prereq go install_go
    prereq packages install_packages
    prereq tools install_tools
    prereq registry configure_registry
    prereq docker_hub_block block_docker_hub
    prereq mode prepare_mode
    prereq datasets derive_datasets
    prereq mirror_proof mirror_proof
    prereq host_info collect_host_info
    prereq build build_tools

    if stage_requested eval; then
        stage_eval
        stage_run_block
    fi
    # Fixed order, whatever the order of --stages: crosscheck reads the lint study, attribute reads
    # the eval study and leaves the out-dir that ablate then adds to.
    stage_requested export && stage_export
    stage_requested rq3 && stage_rq3
    stage_requested rq1 && stage_rq1
    stage_requested lint && stage_lint
    stage_requested crosscheck && stage_crosscheck
    stage_requested attribute && stage_attribute
    stage_requested ablate && stage_ablate
    stage_requested reliability && stage_reliability
    post_run_facts

    finalize || code=$?
    return "$code"
}

main "$@"; exit $?
