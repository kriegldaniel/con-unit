#!/usr/bin/env bash
# ConUnit AWS evaluation orchestrator (runs on the operator machine).
#
#   run_eval.sh [options]                 provision, evaluate, collect, destroy
#   run_eval.sh --canary                  same with the first 3 dataset lines (pipeline check)
#   run_eval.sh --preflight-only          run every pre-flight check, provision nothing
#   run_eval.sh --destroy-run RUN_ID      tear down and verify a run that was interrupted
#
# Safety model
#   * Every exit path (success, failure, Ctrl-C, SIGTERM) runs the trap that collects whatever
#     results exist and then destroys all resources, unless --keep was given.
#   * Destruction is verified: the run's OpenTofu state must be empty and no instance, volume,
#     key pair or security group tagged with the run id may remain.
#   * The instance also carries its own watchdog (see user_data.sh) that terminates it.
#
# Exit codes: 0 complete, 1 error, 2 usage, 3 evaluation incomplete (partial results kept),
#             4 teardown could not be verified (resources may still be running).
#
# Needs bash 4 or newer, tofu, aws, jq, git, ssh, ssh-keygen, rsync, curl, tar, gzip.
# Only AWS credentials are required. No registry credentials are used anywhere.
#
# shellcheck disable=SC2329 # cleanup, on_err and friends are invoked through traps
set -Eeuo pipefail
umask 077

if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "run_eval.sh needs bash 4 or newer (found $BASH_VERSION). Enter the dev shell: direnv allow, or nix develop ./eval-infra" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$SCRIPT_DIR"
SUBMISSION_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

EXIT_OK=0
EXIT_ERROR=1
EXIT_USAGE=2
EXIT_INCOMPLETE=3
EXIT_TEARDOWN=4

# ------------------------------------------------------------------ defaults
TAG="eval-v1"
RUN_ID=""
CANARY=0
CANARY_N=3
KEEP=0
ALLOW_DIRTY=0
PREFLIGHT_ONLY=0
DESTROY_RUN=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-central-1}}"
INSTANCE_TYPE="c6i.2xlarge"
VOLUME_GB=150
SSH_KEY="${CONUNIT_SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_CIDR=""
CON_UNIT_DIR="${CON_UNIT_DIR:-$SUBMISSION_ROOT/../con-unit}"
DATASET="fixtures/evaluation_dataset_pinned.txt"
RQ3_DATASET="fixtures/evaluation_dataset_top10_pinned.txt"
MODE="rootful"
STAGES="eval,export,rq3"
STAGES_SET=0
# Every stage of remote_eval.sh, in the order in which it runs. The canary runs all of them.
ALL_STAGES="eval,export,rq3,rq1,lint,crosscheck,attribute,ablate,reliability"
RQ1_CASES=""
CANARY_RQ1_CASES=4
PACK="cis"
PLATFORM="linux/amd64"
IMAGE_SOURCE="auto"
PROBE_WINDOW="3s"
ITERATIONS=""
WARMUP=1
WATCHDOG_MIN=""
AMI_ID=""
BLOCK_HUB="true"
MIRROR_DELAY="1.1"
# Waits are bounded. The environment variables exist for slow networks and for the offline tests.
SSH_WAIT_ATTEMPTS="${CONUNIT_SSH_WAIT_ATTEMPTS:-60}"
SSH_WAIT_INTERVAL="${CONUNIT_SSH_WAIT_INTERVAL:-10}"
RETRY_SLEEP="${CONUNIT_RETRY_SLEEP:-15}"
VERIFY_SLEEP="${CONUNIT_VERIFY_SLEEP:-10}"
HOSTKEY_SLEEP="${CONUNIT_HOSTKEY_SLEEP:-10}"

# ------------------------------------------------------------------ run state
RUN_DIR=""
RESULTS_DIR=""
PREFLIGHT_DIR=""
TRANSCRIPT=""
TF_STATE=""
TFVARS=""
SSH_CFG=""
KNOWN_HOSTS=""
SSH_HOST="conunit-eval"
BUNDLE=""
TOOLS_LOCK="$INFRA_DIR/tools.lock"
TOOLS_LOCK_SHA=""
BUNDLE_KIND="tag"
BUNDLE_SHA=""
COMMIT=""
HEAD_SHA=""
TREE_SHA=""
TAG_EXISTS=0
WORKTREE_DIRTY=false
TAINTED=false
AMI_NAME=""
AMI_CREATED=""
AMI_DEPRECATED=""
INSTANCE_ID=""
INSTANCE_IP=""
INSTANCE_AZ=""
AWS_ACCOUNT_ID="" # held in memory to redact it from the bundle, never printed
HOST_KEY_CHECK="skipped"
DATASET_SHA=""
DATASET_ENTRIES=0
RQ3_DATASET_SHA=""
RQ3_DATASET_ENTRIES=0
EVAL_DATASET_USED=""
RQ3_DATASET_USED=""
MIRROR_CHECKED="false"
RESOURCES_MAYBE=0
SSH_READY=0
COLLECTED=0
REMOTE_RC=-1
REMOTE_RESULT="not-run"
FINAL_RC=0
TEARDOWN_OK=0
TEARDOWN_NOTE=""
TD_STATE_RESOURCES="unknown"
TD_INSTANCES="unknown"
TD_VOLUMES="unknown"
TD_SECURITY_GROUPS="unknown"
TD_KEY_PAIRS="unknown"
T_STARTED=""
T_PROVISIONED=""
T_SSH_READY=""
T_REMOTE_START=""
T_REMOTE_END=""
T_COLLECTED=""
T_DESTROYED=""
SHA_CMD=()

export AWS_PAGER=""
export TF_IN_AUTOMATION=1

# ------------------------------------------------------------------ logging
# Colored lines go to the terminal (fd 3) and plain lines to the transcript. Output of child
# processes passes through tee and is plain in both.
USE_COLOR=0
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    USE_COLOR=1
fi
exec 3>&1

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
epoch() { date +%s; }

ESC=$'\033'
emit() { # level color text
    local plain colored
    plain="$(date +%H:%M:%S) [$1] $3"
    if [ "$USE_COLOR" = 1 ]; then
        colored="$(date +%H:%M:%S) ${ESC}[$2m[$1]${ESC}[0m $3"
    else
        colored="$plain"
    fi
    if [ -n "$TRANSCRIPT" ]; then
        printf '%s\n' "$plain" >> "$TRANSCRIPT"
    fi
    printf '%s\n' "$colored" >&3
}
info() { emit "INFO    " "36" "$*"; }
progress() { emit "PROGRESS" "34" "$*"; }
success() { emit "SUCCESS " "32" "$*"; }
warning() { emit "WARNING " "33" "$*"; }
error() { emit "ERROR   " "31;1" "$*"; }
heading() {
    local line
    line="$(printf '%.0s=' {1..72})"
    if [ -n "$TRANSCRIPT" ]; then
        printf '\n%s\n  %s\n%s\n' "$line" "$*" "$line" >> "$TRANSCRIPT"
    fi
    if [ "$USE_COLOR" = 1 ]; then
        printf '\n%s[1m%s\n  %s\n%s%s[0m\n' "$ESC" "$line" "$*" "$line" "$ESC" >&3
    else
        printf '\n%s\n  %s\n%s\n' "$line" "$*" "$line" >&3
    fi
}
die() {
    error "$*"
    exit "$EXIT_ERROR"
}
usage_error() {
    echo "usage error: $*" >&2
    echo "run with --help for the option list" >&2
    exit "$EXIT_USAGE"
}

usage() {
    cat <<'EOF'
Usage: run_eval.sh [options]

Modes
  (default)               full evaluation: provision, run, collect, destroy
  --canary                every stage on the first 3 dataset lines, 4 RQ1 cases, a 3 image reliability
                          subset and 3 RQ3 trials, short watchdog (pipeline check)
  --preflight-only        run all pre-flight checks and stop before provisioning anything
  --destroy-run RUN_ID    destroy and verify the resources of an interrupted run

Run control
  --tag TAG               con-unit release tag to evaluate (default eval-v1)
  --allow-dirty           archive the working tree instead of the tag and mark the run tainted
  --run-id ID             run identifier, letters digits . _ - (default <utc time>-<tag>[-canary])
  --keep                  do not destroy on exit (the instance watchdog still terminates it)

Evaluation
  --dataset PATH          eval dataset relative to the con-unit root (default fixtures/evaluation_dataset_pinned.txt)
  --rq3-dataset PATH      the 10 image dataset of rq3 and reliability (default fixtures/evaluation_dataset_top10_pinned.txt)
  --stages LIST           comma list of eval,export,rq3,rq1,lint,crosscheck,attribute,ablate,reliability
                          (default eval,export,rq3, canary default: all stages)
  --rq1-cases N           run only the first N cases of the RQ1 oracle (default all, canary 4)
  --mode rootful|rootless Podman mode (default rootful, rootless is the sensitivity run)
  --pack NAME             rule pack (default cis)
  --platform OS/ARCH      default linux/amd64
  --image-source POLICY   auto|local|registry (default auto)
  --probe-window DUR      Tier 3 window W (default 3s)
  --iterations N          RQ3 timed trials (default 10, canary 3)
  --warmup N              RQ3 discarded warm-up iterations (default 1)
  --allow-docker-hub      do not block Docker Hub on the instance (default: blocked, so a fallback fails loudly)

Infrastructure
  --region REGION         AWS region (default $AWS_REGION, else eu-central-1)
  --instance-type TYPE    default c6i.2xlarge (c6i.metal for the RQ3 timing run)
  --volume-gb N           root volume size, default 150
  --ami-id ID             override the pinned AMI of amis.json
  --ssh-key PATH          private key, public key must sit next to it (default ~/.ssh/id_ed25519)
  --ssh-cidr CIDR         SSH source network (default: your public address as /32)
  --watchdog-min N        minutes until the instance terminates itself (default 360, canary 90)
  --con-unit-dir DIR      con-unit checkout (default ../con-unit next to the submission repo)
  --mirror-delay SEC      pause between mirror requests, at least 1 (default 1.1)
EOF
}

# ------------------------------------------------------------------ argument parsing
parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --canary) CANARY=1; shift ;;
            --keep) KEEP=1; shift ;;
            --allow-dirty) ALLOW_DIRTY=1; shift ;;
            --preflight-only) PREFLIGHT_ONLY=1; shift ;;
            --allow-docker-hub) BLOCK_HUB="false"; shift ;;
            --tag) TAG="${2:?--tag needs a value}"; shift 2 ;;
            --run-id) RUN_ID="${2:?--run-id needs a value}"; shift 2 ;;
            --destroy-run) DESTROY_RUN="${2:?--destroy-run needs a value}"; shift 2 ;;
            --dataset) DATASET="${2:?--dataset needs a value}"; shift 2 ;;
            --rq3-dataset) RQ3_DATASET="${2:?--rq3-dataset needs a value}"; shift 2 ;;
            --stages) STAGES="${2:?--stages needs a value}"; STAGES_SET=1; shift 2 ;;
            --rq1-cases) RQ1_CASES="${2:?--rq1-cases needs a value}"; shift 2 ;;
            --mode) MODE="${2:?--mode needs a value}"; shift 2 ;;
            --pack) PACK="${2:?--pack needs a value}"; shift 2 ;;
            --platform) PLATFORM="${2:?--platform needs a value}"; shift 2 ;;
            --image-source) IMAGE_SOURCE="${2:?--image-source needs a value}"; shift 2 ;;
            --probe-window) PROBE_WINDOW="${2:?--probe-window needs a value}"; shift 2 ;;
            --iterations) ITERATIONS="${2:?--iterations needs a value}"; shift 2 ;;
            --warmup) WARMUP="${2:?--warmup needs a value}"; shift 2 ;;
            --region) REGION="${2:?--region needs a value}"; shift 2 ;;
            --instance-type) INSTANCE_TYPE="${2:?--instance-type needs a value}"; shift 2 ;;
            --volume-gb) VOLUME_GB="${2:?--volume-gb needs a value}"; shift 2 ;;
            --ami-id) AMI_ID="${2:?--ami-id needs a value}"; shift 2 ;;
            --ssh-key) SSH_KEY="${2:?--ssh-key needs a value}"; shift 2 ;;
            --ssh-cidr) SSH_CIDR="${2:?--ssh-cidr needs a value}"; shift 2 ;;
            --watchdog-min) WATCHDOG_MIN="${2:?--watchdog-min needs a value}"; shift 2 ;;
            --con-unit-dir) CON_UNIT_DIR="${2:?--con-unit-dir needs a value}"; shift 2 ;;
            --mirror-delay) MIRROR_DELAY="${2:?--mirror-delay needs a value}"; shift 2 ;;
            -h | --help) usage; exit 0 ;;
            *) usage_error "unknown option: $1" ;;
        esac
    done
}

validate_args() {
    local s
    [[ "$TAG" =~ ^[A-Za-z0-9._/-]+$ ]] || usage_error "--tag contains unsupported characters"
    [[ "$MODE" =~ ^(rootful|rootless)$ ]] || usage_error "--mode must be rootful or rootless"
    [[ "$IMAGE_SOURCE" =~ ^(auto|local|registry)$ ]] || usage_error "--image-source must be auto, local or registry"
    [[ "$REGION" =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]] || usage_error "--region looks malformed: $REGION"
    [[ "$VOLUME_GB" =~ ^[0-9]+$ ]] || usage_error "--volume-gb must be an integer"
    [[ "$WARMUP" =~ ^[0-9]+$ ]] || usage_error "--warmup must be an integer"
    [[ "$MIRROR_DELAY" =~ ^[0-9]+(\.[0-9]+)?$ ]] || usage_error "--mirror-delay must be a number"
    awk -v d="$MIRROR_DELAY" 'BEGIN { exit !(d >= 1) }' || usage_error "--mirror-delay must be at least 1 second (ECR Public off-AWS limit is 1 request per second)"
    [[ "$DATASET" =~ ^[A-Za-z0-9._/-]+$ ]] && [[ "$DATASET" != /* ]] && [[ "$DATASET" != *..* ]] || usage_error "--dataset must be a safe relative path"
    [[ "$RQ3_DATASET" =~ ^[A-Za-z0-9._/-]+$ ]] && [[ "$RQ3_DATASET" != /* ]] && [[ "$RQ3_DATASET" != *..* ]] || usage_error "--rq3-dataset must be a safe relative path"
    if [ "$CANARY" = 1 ] && [ "$STAGES_SET" = 0 ]; then STAGES="$ALL_STAGES"; fi
    [ -n "$STAGES" ] || usage_error "--stages is empty"
    # shellcheck disable=SC2086 # word splitting of the comma list is intended
    for s in ${STAGES//,/ }; do
        case ",$ALL_STAGES," in
            *",$s,"*) ;;
            *) usage_error "unknown stage '$s'" ;;
        esac
    done
    if [ -z "$RQ1_CASES" ]; then
        if [ "$CANARY" = 1 ]; then RQ1_CASES="$CANARY_RQ1_CASES"; else RQ1_CASES=0; fi
    fi
    [[ "$RQ1_CASES" =~ ^[0-9]+$ ]] || usage_error "--rq1-cases must be a non-negative integer"
    if [ -n "$SSH_CIDR" ]; then
        [[ "$SSH_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || usage_error "--ssh-cidr must be an IPv4 CIDR"
        [ "${SSH_CIDR#*/}" -ge 16 ] || usage_error "--ssh-cidr is wider than /16. Refusing: SSH must not be open to the internet"
    fi

    if [ "$CANARY" = 1 ]; then
        : "${ITERATIONS:=3}"
        : "${WATCHDOG_MIN:=90}"
    else
        : "${ITERATIONS:=10}"
        : "${WATCHDOG_MIN:=360}"
    fi
    [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || usage_error "--iterations must be an integer"
    [[ "$WATCHDOG_MIN" =~ ^[0-9]+$ ]] || usage_error "--watchdog-min must be an integer"

    if [ -z "$RUN_ID" ]; then
        RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${TAG//\//-}"
        [ "$CANARY" = 1 ] && RUN_ID="$RUN_ID-canary"
        [ "$MODE" = rootless ] && RUN_ID="$RUN_ID-rootless"
    fi
    [[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$ ]] || usage_error "run id '$RUN_ID' must be 1 to 48 characters of letters, digits, . _ - and start alphanumeric"
    if [ "$KEEP" = 1 ] && [ "$WATCHDOG_MIN" -lt 30 ]; then
        usage_error "--watchdog-min must be at least 30"
    fi
}

# ------------------------------------------------------------------ small helpers
setup_hash_tool() {
    if command -v sha256sum > /dev/null 2>&1; then
        SHA_CMD=(sha256sum)
    elif command -v shasum > /dev/null 2>&1; then
        SHA_CMD=(shasum -a 256)
    else
        die "neither sha256sum nor shasum found"
    fi
}
sha256_of() { "${SHA_CMD[@]}" "$1" | awk '{print $1}'; }

# True when the stage is part of --stages.
needs_stage() { [[ ",$STAGES," == *",$1,"* ]]; }
# True when the 10 image dataset is read: by the rq3 benchmark and by the reliability repeats.
needs_top10() { needs_stage rq3 || needs_stage reliability; }

# Non-comment, non-blank lines. awk keeps the exit status 0 for files without image lines.
image_lines() { awk '!/^[[:space:]]*(#|$)/' "$1"; }
count_images() { awk 'BEGIN { n = 0 } !/^[[:space:]]*(#|$)/ { n++ } END { print n }' "$1"; }

require_cmd() {
    local c
    for c in "$@"; do
        command -v "$c" > /dev/null 2>&1 || die "required command not found: $c (enter the dev shell: direnv allow, or nix develop ./eval-infra)"
    done
}

tf() { tofu -chdir="$INFRA_DIR" "$@"; }

# -n keeps ssh from reading the terminal. The streamed remote script uses its own ssh call.
ssh_remote() { ssh -n -F "$SSH_CFG" "$SSH_HOST" "$@"; }

setup_run_paths() {
    local id=$1
    RUN_DIR="$INFRA_DIR/.runs/$id"
    PREFLIGHT_DIR="$RUN_DIR/preflight"
    RESULTS_DIR="$SUBMISSION_ROOT/results/$id"
    TF_STATE="$RUN_DIR/terraform.tfstate"
    TFVARS="$RUN_DIR/run.tfvars.json"
    SSH_CFG="$RUN_DIR/ssh_config"
    KNOWN_HOSTS="$RUN_DIR/known_hosts"
    case "$RUN_DIR$RESULTS_DIR" in
        *[[:space:]]*) die "paths containing whitespace are not supported: $RUN_DIR" ;;
    esac
}

# ------------------------------------------------------------------ exit handling
on_err() {
    error "line $1: command failed (exit $3): $2"
}

collect_results() {
    local rc=0
    heading "COLLECT RESULTS"
    mkdir -p "$RESULTS_DIR"
    progress "rsync $SSH_HOST:/opt/con-unit/results/$RUN_ID/ -> $RESULTS_DIR/"
    rsync -a --partial -e "ssh -F $SSH_CFG" "$SSH_HOST:/opt/con-unit/results/$RUN_ID/" "$RESULTS_DIR/" || rc=$?
    if [ "$rc" -ne 0 ]; then
        error "rsync of results failed with exit code $rc"
        return 1
    fi
    COLLECTED=1
    T_COLLECTED="$(now)"
    if [ -f "$RESULTS_DIR/REMOTE_SHA256SUMS" ]; then
        if (cd "$RESULTS_DIR" && "${SHA_CMD[@]}" -c REMOTE_SHA256SUMS > "$RUN_DIR/remote_checksum_verify.txt" 2>&1); then
            success "all downloaded files match the checksums computed on the instance"
        else
            error "downloaded files do NOT match REMOTE_SHA256SUMS, see $RUN_DIR/remote_checksum_verify.txt"
            return 1
        fi
    else
        warning "no REMOTE_SHA256SUMS on the instance: the remote run ended before finalization, results are partial"
    fi
    success "results downloaded to $RESULTS_DIR"
}

verify_destroyed() {
    local attempt aws_ok=1 state_file_resources=0 filter
    heading "VERIFY TEARDOWN"
    TD_STATE_RESOURCES="unknown"
    TD_INSTANCES="unknown"
    TD_VOLUMES="unknown"
    TD_SECURITY_GROUPS="unknown"
    TD_KEY_PAIRS="unknown"

    if [ -f "$TF_STATE" ]; then
        if state_file_resources=$(tf state list "-state=$TF_STATE" 2> /dev/null | wc -l | tr -d ' '); then
            TD_STATE_RESOURCES="$state_file_resources"
        fi
    else
        TD_STATE_RESOURCES=0
    fi
    info "OpenTofu state resources remaining: $TD_STATE_RESOURCES"

    filter="Name=tag:RunId,Values=$RUN_ID"
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
        aws_ok=1
        TD_INSTANCES=$(aws ec2 describe-instances --region "$REGION" --filters "$filter" \
            "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down" \
            --query 'length(Reservations[].Instances[])' --output text 2> /dev/null) || aws_ok=0
        TD_VOLUMES=$(aws ec2 describe-volumes --region "$REGION" --filters "$filter" \
            --query 'length(Volumes[])' --output text 2> /dev/null) || aws_ok=0
        TD_SECURITY_GROUPS=$(aws ec2 describe-security-groups --region "$REGION" --filters "$filter" \
            --query 'length(SecurityGroups[])' --output text 2> /dev/null) || aws_ok=0
        TD_KEY_PAIRS=$(aws ec2 describe-key-pairs --region "$REGION" --filters "$filter" \
            --query 'length(KeyPairs[])' --output text 2> /dev/null) || aws_ok=0
        if [ "$aws_ok" = 0 ]; then
            warning "AWS describe calls failed (attempt $attempt/12), credentials may have expired"
        elif [ "$TD_INSTANCES" = 0 ] && [ "$TD_VOLUMES" = 0 ] && [ "$TD_SECURITY_GROUPS" = 0 ] && [ "$TD_KEY_PAIRS" = 0 ]; then
            break
        else
            info "waiting for AWS to finish deleting: instances=$TD_INSTANCES volumes=$TD_VOLUMES security_groups=$TD_SECURITY_GROUPS key_pairs=$TD_KEY_PAIRS (attempt $attempt/12)"
        fi
        sleep "$VERIFY_SLEEP"
    done

    info "tagged resources remaining: instances=$TD_INSTANCES volumes=$TD_VOLUMES security_groups=$TD_SECURITY_GROUPS key_pairs=$TD_KEY_PAIRS"
    if [ "$TD_STATE_RESOURCES" = 0 ] && [ "$TD_INSTANCES" = 0 ] && [ "$TD_VOLUMES" = 0 ] && [ "$TD_SECURITY_GROUPS" = 0 ] && [ "$TD_KEY_PAIRS" = 0 ]; then
        TEARDOWN_OK=1
        T_DESTROYED="$(now)"
        TEARDOWN_NOTE="destroyed and verified"
        success "teardown verified: no resource tagged RunId=$RUN_ID remains"
    else
        TEARDOWN_OK=0
        TEARDOWN_NOTE="teardown NOT verified"
        error "teardown could not be verified. Resources of run $RUN_ID may still be running and billing."
        error "Retry:  ./run_eval.sh --destroy-run $RUN_ID   (or: just destroy $RUN_ID)"
        error "Check:  aws ec2 describe-instances --region $REGION --filters Name=tag:RunId,Values=$RUN_ID"
    fi
}

teardown() {
    local attempt destroyed=0
    if [ "$RESOURCES_MAYBE" != 1 ]; then
        TEARDOWN_OK=1
        TEARDOWN_NOTE="nothing was provisioned"
        return 0
    fi
    if [ "$KEEP" = 1 ]; then
        TEARDOWN_OK=1
        TEARDOWN_NOTE="kept by --keep"
        heading "RESOURCES KEPT (--keep)"
        warning "instance $INSTANCE_ID at $INSTANCE_IP is still running and billing"
        warning "its watchdog terminates it $WATCHDOG_MIN minutes after boot at the latest"
        info "ssh:      ssh -F $SSH_CFG $SSH_HOST"
        info "destroy:  ./run_eval.sh --destroy-run $RUN_ID   (or: just destroy $RUN_ID)"
        return 0
    fi
    heading "TEARDOWN"
    info "if this is interrupted, finish it with: ./run_eval.sh --destroy-run $RUN_ID"
    for attempt in 1 2 3; do
        progress "tofu destroy (attempt $attempt/3)"
        if tf destroy -auto-approve -input=false -no-color "-state=$TF_STATE" "-var-file=$TFVARS"; then
            destroyed=1
            break
        fi
        warning "destroy attempt $attempt failed, retrying in $RETRY_SLEEP seconds"
        sleep "$RETRY_SLEEP"
    done
    [ "$destroyed" = 1 ] || error "tofu destroy did not succeed after 3 attempts"
    verify_destroyed
}

write_manifest() {
    local outcome=$1 remote_status="{}" remote_versions="{}" remote_tools="{}" remote_dataset="{}" mirror_files="{}"
    if [ -f "$RESULTS_DIR/status.json" ]; then remote_status=$(cat "$RESULTS_DIR/status.json"); fi
    if [ -f "$RESULTS_DIR/host/versions.json" ]; then remote_versions=$(cat "$RESULTS_DIR/host/versions.json"); fi
    # host/tool_versions.json: what the instance installed from tools.lock, with url and hashes
    if [ -f "$RESULTS_DIR/host/tool_versions.json" ]; then remote_tools=$(cat "$RESULTS_DIR/host/tool_versions.json"); fi
    remote_dataset=$(printf '%s' "$remote_status" | jq -c '{eval: (.dataset_used // null), rq3: (.rq3_dataset_used // null), reliability: (.reliability_dataset_used // null)}')
    # The per-digest mirror results stay in preflight/, the manifest only points at them.
    mirror_files=$(jq -n --arg e "$([ -f "$PREFLIGHT_DIR/mirror_check_eval.json" ] && echo preflight/mirror_check_eval.json)" \
        --arg r "$([ -f "$PREFLIGHT_DIR/mirror_check_rq3.json" ] && echo preflight/mirror_check_rq3.json)" \
        '{eval: (if $e == "" then null else $e end), rq3: (if $r == "" then null else $r end)}')
    jq -n \
        --arg run_id "$RUN_ID" --arg outcome "$outcome" --arg tag "$TAG" --argjson tag_exists "$([ "$TAG_EXISTS" = 1 ] && echo true || echo false)" \
        --arg commit "$COMMIT" --arg head "$HEAD_SHA" --arg tree "$TREE_SHA" --arg kind "$BUNDLE_KIND" \
        --argjson tainted "$TAINTED" --argjson dirty "$WORKTREE_DIRTY" --arg bundle_sha "$BUNDLE_SHA" \
        --arg ds_path "$EVAL_DATASET_USED" --arg ds_sha "$DATASET_SHA" --argjson ds_n "${DATASET_ENTRIES:-0}" \
        --arg rq_path "$RQ3_DATASET_USED" --arg rq_sha "$RQ3_DATASET_SHA" --argjson rq_n "${RQ3_DATASET_ENTRIES:-0}" \
        --argjson canary "$([ "$CANARY" = 1 ] && echo true || echo false)" --argjson mirror_checked "$MIRROR_CHECKED" \
        --arg region "$REGION" --arg itype "$INSTANCE_TYPE" --arg iid "$INSTANCE_ID" --arg az "$INSTANCE_AZ" \
        --arg ami "$AMI_ID" --arg ami_name "$AMI_NAME" --arg ami_created "$AMI_CREATED" --arg ami_dep "$AMI_DEPRECATED" \
        --argjson vol "$VOLUME_GB" --argjson wd "$WATCHDOG_MIN" \
        --arg mode "$MODE" --arg stages "$STAGES" --arg pack "$PACK" --arg platform "$PLATFORM" \
        --arg source "$IMAGE_SOURCE" --arg window "$PROBE_WINDOW" --argjson iters "$ITERATIONS" --argjson warm "$WARMUP" \
        --argjson hub_blocked "$BLOCK_HUB" --arg hostkey "$HOST_KEY_CHECK" \
        --arg t0 "$T_STARTED" --arg t1 "$T_PROVISIONED" --arg t2 "$T_SSH_READY" --arg t3 "$T_REMOTE_START" \
        --arg t4 "$T_REMOTE_END" --arg t5 "$T_COLLECTED" --arg t6 "$T_DESTROYED" --arg t7 "$(now)" \
        --argjson remote_rc "$REMOTE_RC" --arg remote_result "$REMOTE_RESULT" --argjson final_rc "$FINAL_RC" \
        --argjson remote_status "$remote_status" --argjson remote_versions "$remote_versions" \
        --argjson remote_tools "$remote_tools" --arg lock_sha "$TOOLS_LOCK_SHA" \
        --argjson rel_used "$(needs_stage reliability && echo true || echo false)" --argjson rq1_cases "${RQ1_CASES:-0}" \
        --argjson remote_dataset "$remote_dataset" --argjson mirror_files "$mirror_files" \
        --argjson td_ok "$([ "$TEARDOWN_OK" = 1 ] && echo true || echo false)" --arg td_note "$TEARDOWN_NOTE" --argjson keep "$([ "$KEEP" = 1 ] && echo true || echo false)" \
        --arg td_state "$TD_STATE_RESOURCES" --arg td_inst "$TD_INSTANCES" --arg td_vol "$TD_VOLUMES" \
        --arg td_sg "$TD_SECURITY_GROUPS" --arg td_key "$TD_KEY_PAIRS" \
        --arg v_tofu "$(tofu version 2> /dev/null | head -n 1)" --arg v_aws "$(aws --version 2>&1 | head -n 1)" \
        --arg v_jq "$(jq --version 2>&1)" --arg v_git "$(git --version 2>&1)" --arg v_rsync "$(rsync --version 2>&1 | head -n 1)" \
        --arg v_ssh "$(ssh -V 2>&1 | head -n 1)" --arg v_bash "$BASH_VERSION" \
        '
        def nn: if . == "" then null else . end;
        {
          schema: "conunit-run-manifest/1",
          run_id: $run_id,
          outcome: $outcome,
          exit_code: $final_rc,
          source: {
            requested_tag: $tag, tag_exists: $tag_exists, bundle_kind: $kind,
            commit: $commit, head_commit: $head, tree: ($tree | nn),
            tainted: $tainted, working_tree_dirty: $dirty, bundle_sha256: $bundle_sha
          },
          dataset: {
            canary: $canary,
            eval: {path: $ds_path, sha256: $ds_sha, entries: $ds_n},
            rq3: {path: ($rq_path | nn), sha256: ($rq_sha | nn), entries: $rq_n},
            reliability: (if $rel_used then {path: ($rq_path | nn), sha256: ($rq_sha | nn), entries: $rq_n} else null end),
            remote_reported: $remote_dataset,
            mirror_check_performed: $mirror_checked,
            mirror_check_results: $mirror_files
          },
          infrastructure: {
            region: $region, instance_type: $itype, instance_id: ($iid | nn), availability_zone: ($az | nn),
            ami: {id: $ami, name: ($ami_name | nn), creation_date: ($ami_created | nn), deprecation_time: ($ami_dep | nn)},
            root_volume_gb: $vol, watchdog_minutes: $wd, ssh_host_key_check: $hostkey
          },
          execution: {
            engine_mode: $mode, stages: ($stages | split(",")), pack: $pack, platform: $platform,
            image_source_policy: $source, probe_window: $window, rq1_cases: $rq1_cases,
            rq3_iterations: $iters, rq3_warmup: $warm, docker_hub_blocked: $hub_blocked,
            registry_remap: ($remote_status.registry_remap // null)
          },
          timestamps: {
            started: ($t0 | nn), provisioned: ($t1 | nn), ssh_ready: ($t2 | nn), remote_started: ($t3 | nn),
            remote_finished: ($t4 | nn), results_collected: ($t5 | nn), destroyed: ($t6 | nn), manifest_written: $t7
          },
          exit_codes: {
            remote_script: $remote_rc, remote_result: $remote_result,
            remote_stages: ($remote_status.stages // {} | with_entries(.value = .value.exit_code))
          },
          tool_versions: {
            local: {opentofu: $v_tofu, aws_cli: $v_aws, jq: $v_jq, git: $v_git, rsync: $v_rsync, ssh: $v_ssh, bash: $v_bash},
            remote: $remote_versions,
            installed: $remote_tools,
            lock_sha256_shipped: ($lock_sha | nn)
          },
          teardown: {
            kept: $keep, verified: $td_ok, note: $td_note,
            remaining: {state_resources: $td_state, instances: $td_inst, volumes: $td_vol, security_groups: $td_sg, key_pairs: $td_key}
          }
        }' > "$RESULTS_DIR/run_manifest.json"
}

write_checksums() {
    # shellcheck disable=SC2094 # SHA256SUMS is excluded from its own file list
    (
        cd "$RESULTS_DIR"
        find . -type f ! -name SHA256SUMS ! -name run_eval.log -print0 | LC_ALL=C sort -z | xargs -0 "${SHA_CMD[@]}" > SHA256SUMS
    )
}

# ------------------------------------------------------------------ redaction
# The transcript and the pre-flight notes are written on the operator machine. They carry values
# that identify the operator, not the experiment: the home directory (SSH key path, con-unit
# checkout), the SSH source address and the AWS account id, which OpenTofu prints in its plan and
# destroy output. The copies that go into the bundle get fixed placeholders instead. This runs
# before the checksums are computed. The originals stay in .runs/<RUN_ID>/, which is git-ignored.
# Files that came from the instance are never touched, REMOTE_SHA256SUMS covers them.
sed_literal() { printf '%s' "$1" | sed -e 's/[][\.*^$|&]/\\&/g'; }

redact_file() {
    local file=$1 tmp ip comment
    local -a expr=()
    [ -f "$file" ] || return 0
    if [ -n "${HOME:-}" ] && [ "${HOME%/}" != "" ]; then
        expr+=(-e "s|$(sed_literal "${HOME%/}")|~|g")
    fi
    ip="${SSH_CIDR%%/*}"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        expr+=(-e "s|$(sed_literal "$ip")|<operator-ip>|g")
    fi
    if [[ "$AWS_ACCOUNT_ID" =~ ^[0-9]{12}$ ]]; then
        expr+=(-e "s|$AWS_ACCOUNT_ID|<aws-account-id>|g")
    fi
    # ssh-keygen writes user@host as the default comment, and OpenTofu prints the public key.
    comment="$(awk 'NR == 1 {print $3}' "$SSH_KEY.pub" 2> /dev/null || true)"
    if [[ "$comment" == *@* ]]; then
        expr+=(-e "s|$(sed_literal "$comment")|<key-comment>|g")
    fi
    [ "${#expr[@]}" -gt 0 ] || return 0
    tmp="$file.redacted"
    if sed "${expr[@]}" "$file" > "$tmp"; then
        mv "$tmp" "$file"
    else
        rm -f "$tmp"
        warning "could not redact $file"
    fi
}

redact_bundle() {
    local f
    if [ -f "$RESULTS_DIR/run_eval.log" ]; then
        redact_file "$RESULTS_DIR/run_eval.log"
    fi
    if [ -d "$RESULTS_DIR/preflight" ]; then
        # worktree.diff is a patch of the tool source (tainted runs only), it stays byte for byte
        while IFS= read -r -d '' f; do
            redact_file "$f"
        done < <(find "$RESULTS_DIR/preflight" -type f ! -name worktree.diff -print0)
    fi
    cat > "$RESULTS_DIR/REDACTION.txt" <<'EOF'
run_eval.log and the files under preflight/ were written on the operator machine. Before the
checksums were computed, three kinds of values were replaced in them:

  the operator's home directory      ->  ~
  the SSH source address             ->  <operator-ip>
  the AWS account id                 ->  <aws-account-id>

A user@host comment on the SSH public key is replaced by <key-comment>. Nothing else was changed.
preflight/worktree.diff (tainted runs only) is a patch of the tool source and is left as it is.
Files that came from the instance are not modified, REMOTE_SHA256SUMS covers them.
EOF
}

finalize_bundle() {
    local outcome=$1
    [ "$RESOURCES_MAYBE" = 1 ] || return 0
    mkdir -p "$RESULTS_DIR"
    if [ -d "$PREFLIGHT_DIR" ]; then
        mkdir -p "$RESULTS_DIR/preflight"
        rsync -a "$PREFLIGHT_DIR/" "$RESULTS_DIR/preflight/"
    fi
    write_manifest "$outcome"
    if [ -n "$TRANSCRIPT" ] && [ -f "$TRANSCRIPT" ]; then
        cp "$TRANSCRIPT" "$RESULTS_DIR/run_eval.log"
    fi
    redact_bundle
    write_checksums
    info "manifest:  $RESULTS_DIR/run_manifest.json"
    info "checksums: $RESULTS_DIR/SHA256SUMS (the local transcript run_eval.log is excluded, it is still being written)"
}

cleanup() {
    local rc=$? outcome
    trap - EXIT INT TERM HUP ERR
    trap '' INT TERM HUP PIPE
    set +e
    FINAL_RC=$rc

    if [ -n "$DESTROY_RUN" ]; then
        teardown
        [ "$TEARDOWN_OK" = 1 ] && exit "$EXIT_OK"
        exit "$EXIT_TEARDOWN"
    fi

    if [ "$RESOURCES_MAYBE" = 1 ] && [ "$COLLECTED" != 1 ] && [ "$SSH_READY" = 1 ]; then
        warning "exiting before results were collected: trying a last download"
        collect_results
    fi

    teardown

    case "$FINAL_RC" in
        0) outcome="complete" ;;
        3) outcome="incomplete" ;;
        *) outcome="failed" ;;
    esac
    [ "$TEARDOWN_OK" = 1 ] || outcome="$outcome-teardown-unverified"
    if [ "$RESOURCES_MAYBE" = 1 ]; then
        if [ "$FINAL_RC" -ne 0 ] && [ "$REMOTE_RESULT" = "not-run" ]; then
            outcome="aborted-before-remote-run"
        fi
        finalize_bundle "$outcome"
    fi

    [ "$PREFLIGHT_ONLY" = 1 ] && [ "$FINAL_RC" -eq 0 ] && outcome="preflight-passed"
    heading "SUMMARY"
    info "run id:     $RUN_ID"
    info "outcome:    $outcome"
    if [ "$RESOURCES_MAYBE" = 1 ]; then info "results:    $RESULTS_DIR"; fi
    info "teardown:   $TEARDOWN_NOTE"
    if [ "$TEARDOWN_OK" != 1 ]; then
        exit "$EXIT_TEARDOWN"
    fi
    exit "$FINAL_RC"
}

# ------------------------------------------------------------------ pre-flight
preflight_tools() {
    require_cmd tofu aws jq git ssh ssh-keygen rsync curl tar gzip awk sed find sort xargs
    setup_hash_tool
    info "tools: $(tofu version 2> /dev/null | head -n 1), $(aws --version 2>&1 | awk '{print $1}'), $(jq --version)"
}

preflight_ssh_key() {
    [ -r "$SSH_KEY" ] || die "SSH private key not readable: $SSH_KEY (use --ssh-key)"
    [ -r "$SSH_KEY.pub" ] || die "SSH public key not found next to the private key: $SSH_KEY.pub"
    if [ -n "$(find "$SSH_KEY" -perm -077 2> /dev/null)" ]; then
        die "SSH private key $SSH_KEY is accessible by group or others. chmod 600 it."
    fi
    if ssh-keygen -y -P '' -f "$SSH_KEY" > /dev/null 2>&1; then
        info "SSH key: $SSH_KEY (unencrypted)"
    else
        ssh-add -L > /dev/null 2>&1 || die "SSH key $SSH_KEY is passphrase protected and no ssh-agent holds it. Run ssh-add $SSH_KEY first."
        info "SSH key: $SSH_KEY (passphrase protected, using ssh-agent)"
    fi
}

preflight_git() {
    git -C "$CON_UNIT_DIR" rev-parse --git-dir > /dev/null 2>&1 || die "not a git checkout: $CON_UNIT_DIR (use --con-unit-dir or CON_UNIT_DIR)"
    CON_UNIT_DIR="$(cd "$CON_UNIT_DIR" && pwd)"
    HEAD_SHA="$(git -C "$CON_UNIT_DIR" rev-parse HEAD)"
    if [ -n "$(git -C "$CON_UNIT_DIR" status --porcelain)" ]; then
        WORKTREE_DIRTY=true
    fi
    if git -C "$CON_UNIT_DIR" rev-parse --verify --quiet "refs/tags/$TAG^{commit}" > /dev/null; then
        TAG_EXISTS=1
    fi
    mkdir -p "$PREFLIGHT_DIR"
    {
        echo "con_unit_dir=$CON_UNIT_DIR"
        echo "head=$HEAD_SHA"
        echo "branch=$(git -C "$CON_UNIT_DIR" rev-parse --abbrev-ref HEAD)"
        echo "requested_tag=$TAG"
        echo "tag_exists=$TAG_EXISTS"
        echo "working_tree_dirty=$WORKTREE_DIRTY"
        [ "$TAG_EXISTS" = 1 ] && echo "tag_commit=$(git -C "$CON_UNIT_DIR" rev-parse "refs/tags/$TAG^{commit}")"
        echo "--- git status --porcelain"
        git -C "$CON_UNIT_DIR" status --porcelain
    } > "$PREFLIGHT_DIR/git.txt"

    if [ "$ALLOW_DIRTY" = 1 ]; then
        BUNDLE_KIND="worktree"
        TAINTED=true
        warning "--allow-dirty: the working tree of $CON_UNIT_DIR is archived instead of tag $TAG. The run is marked TAINTED."
    else
        [ "$TAG_EXISTS" = 1 ] || die "tag '$TAG' does not exist in $CON_UNIT_DIR. Create it (git tag $TAG) or pass --allow-dirty for a tainted run."
        BUNDLE_KIND="tag"
        COMMIT="$(git -C "$CON_UNIT_DIR" rev-parse "refs/tags/$TAG^{commit}")"
        if [ "$HEAD_SHA" != "$COMMIT" ]; then
            warning "HEAD ($HEAD_SHA) is not tag $TAG ($COMMIT). The bundle is built from the tag, not from HEAD."
        fi
        if [ "$WORKTREE_DIRTY" = true ]; then
            warning "the working tree has uncommitted changes. They are NOT part of the bundle (tag $TAG is archived)."
        fi
    fi
}

preflight_aws() {
    local identity
    identity="$(aws sts get-caller-identity --region "$REGION" --output json 2> /dev/null)" || die "aws sts get-caller-identity failed. Export AWS credentials (AWS_PROFILE or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY) first."
    # Kept in memory only, so that redact_bundle can remove it from the bundle. Never printed.
    AWS_ACCOUNT_ID="$(jq -r '.Account // empty' <<< "$identity" 2> /dev/null || true)"
    success "AWS credentials are valid for region $REGION"
}

# tools.lock pins the external tools (dockle, hadolint, trivy, container-structure-test). It is shipped
# next to the bundle and its hash goes to the instance, which installs from it and refuses a file that
# differs. It is checked here as well, so that a placeholder or a malformed line stops the run before
# anything is provisioned. The full check, including the url shape, is validate_tools_lock in
# remote_eval.sh.
preflight_tools_lock() {
    local problems
    [ -f "$TOOLS_LOCK" ] || die "tools lock file missing: $TOOLS_LOCK"
    problems="$(awk '
        /^[[:space:]]*(#|$)/ { next }
        NF != 4 { printf "  line %d: expected 4 fields (name version url sha256)\n", NR; next }
        length($4) != 64 || $4 !~ /^[0-9a-f]+$/ { printf "  line %d: %s sha256 is not 64 lowercase hex characters, a placeholder has to be replaced by a verified value\n", NR, $1 }
        $3 !~ /^https:\/\/github\.com\// { printf "  line %d: %s url is not a github.com url\n", NR, $1 }
        { seen[$1]++ }
        END {
            n = split("dockle hadolint trivy container-structure-test", want, " ")
            for (i = 1; i <= n; i++) if (seen[want[i]] != 1) printf "  tool %s is pinned %d times, expected once\n", want[i], seen[want[i]] + 0
        }' "$TOOLS_LOCK")"
    if [ -n "$problems" ]; then
        error "tools.lock is not usable:"
        printf '%s\n' "$problems" >&2
        die "fix eval-infra/tools.lock before the run"
    fi
    TOOLS_LOCK_SHA="$(sha256_of "$TOOLS_LOCK")"
    info "tools.lock: $(awk '!/^[[:space:]]*(#|$)/ { n++ } END { print n + 0 }' "$TOOLS_LOCK") pins, sha256 $TOOLS_LOCK_SHA"
}

preflight_ami() {
    local desc owner arch state
    if [ -z "$AMI_ID" ]; then
        AMI_ID="$(jq -r --arg r "$REGION" '.pins[$r].ami_id // empty' "$INFRA_DIR/amis.json")"
        [ -n "$AMI_ID" ] || die "no AMI is pinned for region $REGION in eval-infra/amis.json. Run: just pin-ami $REGION   and commit the result (or pass --ami-id)."
    fi
    [[ "$AMI_ID" =~ ^ami-[0-9a-f]{8,17}$ ]] || die "malformed AMI id: $AMI_ID"
    desc="$(aws ec2 describe-images --region "$REGION" --image-ids "$AMI_ID" --output json \
        --query 'Images[0].{id:ImageId,name:Name,creation_date:CreationDate,owner:OwnerId,arch:Architecture,state:State,deprecation_time:DeprecationTime,root_device:RootDeviceType,virtualization:VirtualizationType}' 2> /dev/null)" ||
        die "AMI $AMI_ID not found in $REGION (deregistered or wrong region). Re-pin with: just pin-ami $REGION"
    printf '%s\n' "$desc" > "$PREFLIGHT_DIR/ami.json"
    owner="$(jq -r .owner <<< "$desc")"
    arch="$(jq -r .arch <<< "$desc")"
    state="$(jq -r .state <<< "$desc")"
    AMI_NAME="$(jq -r .name <<< "$desc")"
    AMI_CREATED="$(jq -r .creation_date <<< "$desc")"
    AMI_DEPRECATED="$(jq -r '.deprecation_time // ""' <<< "$desc")"
    [ "$owner" = "$(jq -r .owner "$INFRA_DIR/amis.json")" ] || die "AMI $AMI_ID is owned by $owner, not Canonical"
    [ "$arch" = x86_64 ] || die "AMI $AMI_ID has architecture $arch, expected x86_64"
    [ "$state" = available ] || die "AMI $AMI_ID is in state $state"
    info "AMI: $AMI_ID  $AMI_NAME  (created $AMI_CREATED)"
    if [ -n "$AMI_DEPRECATED" ]; then
        warning "AMI is marked deprecated since $AMI_DEPRECATED. It still launches, consider re-pinning for a new release."
    fi
}

preflight_cidr() {
    local ip=""
    if [ -z "$SSH_CIDR" ]; then
        ip="$(curl -4 -fsS --max-time 10 https://checkip.amazonaws.com 2> /dev/null | tr -d '[:space:]')" ||
            ip=""
        if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            ip="$(curl -4 -fsS --max-time 10 https://api.ipify.org 2> /dev/null | tr -d '[:space:]')" || ip=""
        fi
        [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "could not determine your public IPv4 address. Pass --ssh-cidr <address>/32."
        SSH_CIDR="$ip/32"
        info "SSH will be allowed from your public address only (/32, address not logged)"
    else
        info "SSH will be allowed from the network given with --ssh-cidr (address not logged)"
    fi
}

write_run_files() {
    mkdir -p "$RUN_DIR"
    jq -n \
        --arg region "$REGION" --arg run_id "$RUN_ID" --arg itype "$INSTANCE_TYPE" --argjson vol "$VOLUME_GB" \
        --arg ami "$AMI_ID" --arg cidr "$SSH_CIDR" --arg pub "$(cat "$SSH_KEY.pub")" --arg priv "$SSH_KEY" \
        --argjson iters "$ITERATIONS" --argjson wd "$WATCHDOG_MIN" \
        '{aws_region: $region, run_id: $run_id, instance_type: $itype, volume_size_gb: $vol, ami_id: $ami,
          allowed_ssh_cidr: $cidr, ssh_public_key: $pub, ssh_private_key_path: $priv,
          benchmark_iterations: $iters, auto_shutdown: true, auto_shutdown_timeout_minutes: $wd}' > "$TFVARS"
}

preflight_tofu() {
    progress "tofu init (lock file is read-only: provider versions cannot drift)"
    tf init -input=false -no-color -lockfile=readonly > "$PREFLIGHT_DIR/tofu_init.log" 2>&1 || {
        cat "$PREFLIGHT_DIR/tofu_init.log" >&2
        die "tofu init failed"
    }
    progress "tofu validate"
    tf validate -no-color || die "tofu validate failed"
    if ! tf fmt -check -no-color > /dev/null 2>&1; then
        warning "tofu fmt -check reports unformatted files (not fatal)"
    fi
    success "OpenTofu configuration is valid"
}

build_bundle() {
    local tree_index="$RUN_DIR/tmp_index" tree
    BUNDLE="$RUN_DIR/con-unit-bundle.tar.gz"
    progress "building the source bundle with git archive"
    if [ "$BUNDLE_KIND" = tag ]; then
        git -C "$CON_UNIT_DIR" archive --format=tar --prefix=con-unit/ "$COMMIT" | gzip -n > "$BUNDLE"
    else
        rm -f "$tree_index"
        GIT_INDEX_FILE="$tree_index" git -C "$CON_UNIT_DIR" add -A . > /dev/null
        tree="$(GIT_INDEX_FILE="$tree_index" git -C "$CON_UNIT_DIR" write-tree)"
        rm -f "$tree_index"
        TREE_SHA="$tree"
        COMMIT="$HEAD_SHA"
        git -C "$CON_UNIT_DIR" archive --format=tar --prefix=con-unit/ "$tree" | gzip -n > "$BUNDLE"
        git -C "$CON_UNIT_DIR" diff HEAD --binary > "$PREFLIGHT_DIR/worktree.diff" || true
        git -C "$CON_UNIT_DIR" ls-files --others --exclude-standard > "$PREFLIGHT_DIR/worktree_untracked.txt" || true
    fi
    BUNDLE_SHA="$(sha256_of "$BUNDLE")"
    printf '%s  con-unit-bundle.tar.gz\n' "$BUNDLE_SHA" > "$BUNDLE.sha256"
    {
        echo "commit=$COMMIT"
        echo "tag=$TAG"
        echo "kind=$BUNDLE_KIND"
        echo "tainted=$TAINTED"
        echo "tree=$TREE_SHA"
        echo "bundle_sha256=$BUNDLE_SHA"
    } > "$RUN_DIR/COMMIT"
    cp "$RUN_DIR/COMMIT" "$PREFLIGHT_DIR/COMMIT"
    success "bundle $(basename "$BUNDLE"): $(wc -c < "$BUNDLE" | tr -d ' ') bytes, sha256 $BUNDLE_SHA, commit $COMMIT, kind $BUNDLE_KIND"
}

# Extract the bundle that will be shipped and run its own tools/check_mirror.sh on the dataset
# the run will use. Any pinned digest missing on the mirror aborts the run.
preflight_mirror() {
    local src="$RUN_DIR/bundle-src" eval_file rq3_file sub
    rm -rf "$src"
    mkdir -p "$src"
    tar -xzf "$BUNDLE" -C "$src" --strip-components=1
    [ -f "$src/go.mod" ] || die "bundle has no go.mod at its root"
    [ -f "$src/tools/check_mirror.sh" ] || die "the bundle has no tools/check_mirror.sh (tag $TAG predates the mirror check). Cannot prove the images exist on the mirror."
    [ -f "$src/$DATASET" ] || die "dataset not in bundle: $DATASET"

    EVAL_DATASET_USED="$DATASET"
    eval_file="$src/$DATASET"
    if [ "$CANARY" = 1 ]; then
        EVAL_DATASET_USED="fixtures/evaluation_dataset_canary.txt"
        eval_file="$src/$EVAL_DATASET_USED"
        image_lines "$src/$DATASET" | awk -v n="$CANARY_N" 'NR <= n' > "$eval_file"
    fi
    DATASET_SHA="$(sha256_of "$eval_file")"
    DATASET_ENTRIES="$(count_images "$eval_file")"
    [ "$DATASET_ENTRIES" -gt 0 ] || die "dataset has no image lines: $EVAL_DATASET_USED"
    info "eval dataset: $EVAL_DATASET_USED, $DATASET_ENTRIES images, sha256 $DATASET_SHA"

    if needs_top10; then
        [ -f "$src/$RQ3_DATASET" ] || die "10 image dataset not in bundle: $RQ3_DATASET"
        RQ3_DATASET_USED="$RQ3_DATASET"
        rq3_file="$src/$RQ3_DATASET"
        if [ "$CANARY" = 1 ]; then
            RQ3_DATASET_USED="fixtures/evaluation_dataset_top10_canary.txt"
            rq3_file="$src/$RQ3_DATASET_USED"
            image_lines "$src/$RQ3_DATASET" | awk -v n="$CANARY_N" 'NR <= n' > "$rq3_file"
        fi
        RQ3_DATASET_SHA="$(sha256_of "$rq3_file")"
        RQ3_DATASET_ENTRIES="$(count_images "$rq3_file")"
        info "10 image dataset (rq3, reliability): $RQ3_DATASET_USED, $RQ3_DATASET_ENTRIES images, sha256 $RQ3_DATASET_SHA"
    fi

    if [[ ",$STAGES," == *,eval,* ]]; then
        sub="$PREFLIGHT_DIR/mirror-eval"
        mkdir -p "$sub"
        progress "mirror check of the eval dataset (about $DATASET_ENTRIES requests, 1 per $MIRROR_DELAY s)"
        OUT_DIR="$sub" MIRROR_DELAY="$MIRROR_DELAY" bash "$src/tools/check_mirror.sh" "$eval_file" ||
            die "mirror check failed: at least one pinned digest is missing or differs on public.ecr.aws. Fix the dataset (tools/pin_dataset) before running."
        [ -f "$sub/mirror_check.json" ] && cp "$sub/mirror_check.json" "$PREFLIGHT_DIR/mirror_check_eval.json"
        MIRROR_CHECKED="true"
    fi
    if needs_top10; then
        sub="$PREFLIGHT_DIR/mirror-rq3"
        mkdir -p "$sub"
        progress "mirror check of the 10 image dataset ($RQ3_DATASET_ENTRIES requests)"
        OUT_DIR="$sub" MIRROR_DELAY="$MIRROR_DELAY" bash "$src/tools/check_mirror.sh" "$rq3_file" ||
            die "mirror check of the 10 image dataset failed"
        [ -f "$sub/mirror_check.json" ] && cp "$sub/mirror_check.json" "$PREFLIGHT_DIR/mirror_check_rq3.json"
        MIRROR_CHECKED="true"
    fi
    success "mirror check passed: every pinned digest resolves on public.ecr.aws with a matching digest"
    rm -rf "$src"
}

# ------------------------------------------------------------------ provisioning and remote run
provision() {
    local outputs
    heading "PROVISION"
    RESOURCES_MAYBE=1
    T_PROVISIONED=""
    progress "tofu apply (run $RUN_ID, $INSTANCE_TYPE in $REGION)"
    tf apply -auto-approve -input=false -no-color "-state=$TF_STATE" "-var-file=$TFVARS" || die "tofu apply failed"
    outputs="$RUN_DIR/tf_outputs.json"
    tf output -json "-state=$TF_STATE" > "$outputs" || die "cannot read tofu outputs"
    INSTANCE_ID="$(jq -r .instance_id.value "$outputs")"
    INSTANCE_IP="$(jq -r .public_ip.value "$outputs")"
    INSTANCE_AZ="$(jq -r .availability_zone.value "$outputs")"
    local out_ami out_name
    out_ami="$(jq -r .ami_id.value "$outputs")"
    out_name="$(jq -r '.ami_name.value // ""' "$outputs")"
    [ "$out_ami" = "$AMI_ID" ] || die "tofu launched $out_ami but pre-flight checked $AMI_ID"
    [ -z "$out_name" ] || [ "$out_name" = "$AMI_NAME" ] || warning "AMI name differs between describe-images and tofu: '$out_name' vs '$AMI_NAME'"
    T_PROVISIONED="$(now)"
    success "instance $INSTANCE_ID is up at $INSTANCE_IP ($INSTANCE_AZ)"
    info "$(jq -r .estimated_cost.value "$outputs")"
}

write_ssh_config() {
    cat > "$SSH_CFG" <<EOF
Host $SSH_HOST
    HostName $INSTANCE_IP
    User ubuntu
    IdentityFile $SSH_KEY
    IdentitiesOnly yes
    UserKnownHostsFile $KNOWN_HOSTS
    StrictHostKeyChecking accept-new
    HashKnownHosts no
    BatchMode yes
    ConnectTimeout 10
    ServerAliveInterval 30
    ServerAliveCountMax 10
    ForwardAgent no
    ForwardX11 no
    ControlMaster no
    LogLevel ERROR
EOF
    chmod 600 "$SSH_CFG"
    : > "$KNOWN_HOSTS"
}

wait_for_ssh() {
    local attempt denied=0 err_file="$RUN_DIR/ssh_wait.err"
    heading "WAIT FOR SSH AND CLOUD-INIT"
    for attempt in $(seq 1 "$SSH_WAIT_ATTEMPTS"); do
        if ssh -F "$SSH_CFG" -o ConnectTimeout=5 "$SSH_HOST" true 2> "$err_file"; then
            SSH_READY=1
            T_SSH_READY="$(now)"
            success "SSH is reachable (attempt $attempt/$SSH_WAIT_ATTEMPTS)"
            break
        fi
        if grep -q 'Permission denied' "$err_file"; then
            denied=$((denied + 1))
            [ "$denied" -lt 6 ] || die "SSH rejects the key repeatedly: $(tail -n 1 "$err_file")"
        fi
        info "waiting for SSH, attempt $attempt/$SSH_WAIT_ATTEMPTS"
        sleep "$SSH_WAIT_INTERVAL"
    done
    [ "$SSH_READY" = 1 ] || die "SSH did not become reachable after $SSH_WAIT_ATTEMPTS attempts of $SSH_WAIT_INTERVAL s"

    progress "waiting for cloud-init to finish (user_data bootstrap)"
    if ! ssh_remote 'timeout 900 cloud-init status --wait --long'; then
        ssh_remote 'tail -n 40 /var/log/con-unit-userdata.log' 2>&1 || true
        die "cloud-init did not finish cleanly. Last user_data log lines are shown above."
    fi
    ssh_remote 'test -f /var/lib/con-unit/ready' || die "instance is not ready: /var/lib/con-unit/ready is missing, a smoke check failed in user_data.sh"
    success "cloud-init finished and the readiness marker is present"
}

# Compare the host keys that SSH recorded on first contact with the keys cloud-init printed to
# the console. A mismatch aborts. Missing console output is only a warning.
verify_host_key() {
    local attempt console="" keys="" known
    progress "cross-checking the SSH host key against the instance console output"
    for attempt in 1 2 3 4 5 6; do
        console="$(aws ec2 get-console-output --region "$REGION" --instance-id "$INSTANCE_ID" --latest --query Output --output text 2> /dev/null)" || console=""
        keys="$(printf '%s\n' "$console" | awk '/-----BEGIN SSH HOST KEY KEYS-----/ {f = 1; next} /-----END SSH HOST KEY KEYS-----/ {f = 0} f {print $1 " " $2}')"
        [ -z "$keys" ] || break
        sleep "$HOSTKEY_SLEEP"
    done
    if [ -z "$keys" ]; then
        HOST_KEY_CHECK="unavailable"
        warning "console output has no host key block yet. The first-contact key (accept-new, SSH limited to your address) is used unverified."
        return 0
    fi
    known="$(awk '{print $2 " " $3}' "$KNOWN_HOSTS")"
    if [ -z "$known" ]; then
        HOST_KEY_CHECK="no-known-host-entry"
        warning "no host key was recorded in $KNOWN_HOSTS"
        return 0
    fi
    if printf '%s\n' "$known" | grep -Fxq -f <(printf '%s\n' "$keys"); then
        HOST_KEY_CHECK="verified-against-console"
        success "SSH host key matches the console output"
    else
        HOST_KEY_CHECK="MISMATCH"
        die "SSH host key does NOT match the instance console output. Aborting, possible interception."
    fi
}

upload_bundle() {
    heading "UPLOAD BUNDLE"
    progress "rsync bundle, checksum, commit file and tools.lock to the instance"
    rsync -a --partial -e "ssh -F $SSH_CFG" "$BUNDLE" "$BUNDLE.sha256" "$RUN_DIR/COMMIT" "$TOOLS_LOCK" "$SSH_HOST:/opt/con-unit/incoming/" || die "rsync upload failed"
    ssh_remote "cd /opt/con-unit/incoming && sha256sum -c con-unit-bundle.tar.gz.sha256" || die "bundle checksum verification on the instance failed"
    ssh_remote "cd /opt/con-unit/incoming && echo '$TOOLS_LOCK_SHA  tools.lock' | sha256sum -c -" || die "tools.lock checksum verification on the instance failed"
    success "bundle and tools.lock uploaded and verified on the instance"
}

reattach_wait() {
    local deadline misses=0 state path="/opt/con-unit/results/$RUN_ID"
    warning "SSH connection to the instance was lost during the remote run. The run continues on the instance. Re-attaching."
    deadline=$(($(epoch) + (WATCHDOG_MIN + 10) * 60))
    while [ "$(epoch)" -lt "$deadline" ]; do
        sleep 30
        if state="$(ssh_remote "jq -r .result $path/status.json" 2> /dev/null)"; then
            misses=0
            if [ "$state" != running ]; then
                REMOTE_RC="$(ssh_remote "jq -r .exit_code $path/status.json" 2> /dev/null || echo 1)"
                success "remote run finished with result '$state' (exit code $REMOTE_RC)"
                return 0
            fi
            info "remote still running: $(ssh_remote "tail -n 1 $path/remote_eval.log" 2> /dev/null | cut -c1-120)"
        else
            misses=$((misses + 1))
            warning "cannot reach the instance ($misses/20)"
            if [ "$misses" -ge 20 ]; then
                error "the instance stayed unreachable. It was probably terminated by the watchdog."
                REMOTE_RC=255
                return 0
            fi
        fi
    done
    error "remote run did not finish within the watchdog window"
    REMOTE_RC=255
}

run_remote() {
    local -a args
    local quoted
    heading "REMOTE EVALUATION"
    args=(--run-id "$RUN_ID" --commit "$COMMIT" --tag "$TAG" --bundle-kind "$BUNDLE_KIND" --tainted "$TAINTED"
        --bundle-sha256 "$BUNDLE_SHA" --dataset "$DATASET" --rq3-dataset "$RQ3_DATASET" --mode "$MODE"
        --stages "$STAGES" --pack "$PACK" --platform "$PLATFORM" --image-source "$IMAGE_SOURCE"
        --probe-window "$PROBE_WINDOW" --rq3-iterations "$ITERATIONS" --rq3-warmup "$WARMUP"
        --block-docker-hub "$BLOCK_HUB" --rq1-cases "$RQ1_CASES" --tools-lock-sha256 "$TOOLS_LOCK_SHA")
    [ "$CANARY" = 1 ] && args+=(--canary "$CANARY_N")
    quoted="$(printf '%q ' "${args[@]}")"
    T_REMOTE_START="$(now)"
    progress "streaming remote_eval.sh over ssh (bash -s), arguments: $quoted"
    REMOTE_RC=0
    # shellcheck disable=SC2029 # the arguments are quoted on purpose and expanded locally
    ssh -F "$SSH_CFG" "$SSH_HOST" "bash -s -- $quoted" < "$SCRIPT_DIR/remote_eval.sh" || REMOTE_RC=$?
    if [ "$REMOTE_RC" -eq 255 ]; then
        reattach_wait
    fi
    T_REMOTE_END="$(now)"
    info "remote script exit code: $REMOTE_RC"
}

interpret_remote() {
    local remote_ds
    if [ -f "$RESULTS_DIR/status.json" ]; then
        REMOTE_RESULT="$(jq -r '.result // "unknown"' "$RESULTS_DIR/status.json")"
        remote_ds="$(jq -r '.dataset_used.sha256 // ""' "$RESULTS_DIR/status.json")"
        if [ -n "$remote_ds" ] && [ "$remote_ds" != "$DATASET_SHA" ]; then
            warning "dataset sha256 on the instance ($remote_ds) differs from the local one ($DATASET_SHA)"
        fi
    else
        REMOTE_RESULT="no-status-file"
    fi
    case "$REMOTE_RESULT" in
        complete) FINAL_RC=$EXIT_OK ;;
        incomplete) FINAL_RC=$EXIT_INCOMPLETE ;;
        *) FINAL_RC=$EXIT_ERROR ;;
    esac
    if [ ! -f "$RESULTS_DIR/BENCHMARK_COMPLETE" ] && [ "$FINAL_RC" -eq 0 ]; then
        warning "no BENCHMARK_COMPLETE marker although the status says complete"
        FINAL_RC=$EXIT_ERROR
    fi
    case "$REMOTE_RESULT" in
        complete) success "remote result: complete" ;;
        incomplete) warning "remote result: incomplete (some images did not complete). Partial results were exported." ;;
        *) error "remote result: $REMOTE_RESULT" ;;
    esac
}

# ------------------------------------------------------------------ modes
mode_destroy_run() {
    setup_run_paths "$DESTROY_RUN"
    RUN_ID="$DESTROY_RUN"
    [ -d "$RUN_DIR" ] || die "no run directory for $RUN_ID at $RUN_DIR"
    [ -f "$TFVARS" ] || die "missing $TFVARS, cannot destroy with OpenTofu. Use the AWS console or CLI and the RunId=$RUN_ID tag."
    TRANSCRIPT="$RUN_DIR/destroy.log"
    require_cmd tofu aws jq
    REGION="$(jq -r .aws_region "$TFVARS")"
    RESOURCES_MAYBE=1
    KEEP=0
    heading "DESTROY RUN $RUN_ID"
    preflight_aws
    tf init -input=false -no-color -lockfile=readonly > /dev/null 2>&1 || die "tofu init failed"
    # run_eval.sh must not try to collect results or write a bundle in this mode
    trap cleanup EXIT
    exit 0
}

main() {
    parse_args "$@"
    if [ -n "$DESTROY_RUN" ]; then
        [[ "$DESTROY_RUN" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$ ]] || usage_error "malformed run id for --destroy-run"
        mode_destroy_run
    fi
    validate_args

    setup_run_paths "$RUN_ID"
    [ ! -e "$RUN_DIR" ] || die "run directory already exists: $RUN_DIR (choose another --run-id, or use --destroy-run $RUN_ID)"
    [ ! -e "$RESULTS_DIR" ] || die "results directory already exists: $RESULTS_DIR (choose another --run-id)"
    mkdir -p "$PREFLIGHT_DIR"
    TRANSCRIPT="$RUN_DIR/run_eval.log"
    # The terminal sends Ctrl-C to every process of the foreground group, including this tee.
    # It must outlive the signal, otherwise the teardown would die of SIGPIPE half way through.
    exec > >(
        trap '' INT TERM HUP
        exec tee -a "$TRANSCRIPT" >&3
    ) 2>&1
    T_STARTED="$(now)"

    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    trap 'on_err "$LINENO" "$BASH_COMMAND" "$?"' ERR

    heading "ConUnit AWS evaluation, run $RUN_ID"
    info "tag $TAG, mode $MODE, stages $STAGES, region $REGION, instance $INSTANCE_TYPE"
    [ "$CANARY" = 1 ] && warning "CANARY: $CANARY_N images, $RQ1_CASES RQ1 cases, $ITERATIONS RQ3 trials. This is a pipeline check, not a study result."
    [ "$KEEP" = 1 ] && warning "--keep: resources will NOT be destroyed by this script"

    heading "PRE-FLIGHT"
    preflight_tools
    preflight_ssh_key
    preflight_git
    preflight_tools_lock
    preflight_aws
    preflight_ami
    preflight_cidr
    write_run_files
    preflight_tofu
    build_bundle
    preflight_mirror
    success "pre-flight passed"

    if [ "$PREFLIGHT_ONLY" = 1 ]; then
        info "--preflight-only: stopping before provisioning. Nothing was created in AWS."
        exit 0
    fi

    provision
    write_ssh_config
    wait_for_ssh
    verify_host_key
    upload_bundle
    run_remote
    collect_results || die "could not collect results from the instance"
    interpret_remote
    exit "$FINAL_RC"
}

main "$@"
