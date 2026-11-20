#!/usr/bin/env bash
# Offline integration test of run_eval.sh. aws, tofu, ssh and rsync are replaced by stubs, the
# con-unit repository is a tiny throwaway git repo with an eval-v1 tag. Nothing touches AWS.
#
# The point is the safety model: whatever happens after resources exist, they must be destroyed
# and the exit code and manifest must say what happened.
#
# Usage: bash eval-infra/tests/test_run_eval.sh   (needs bash 4+, jq, git, ssh-keygen, tar, gzip)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_SRC="$(cd "$HERE/.." && pwd)"
TMP="$(mktemp -d)"
if [ -n "${KEEP_TMP:-}" ]; then
    echo "keeping $TMP"
else
    trap 'rm -rf "$TMP"' EXIT
fi

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

sha() { if command -v sha256sum > /dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
# Number of lines of a file that match a fixed string, 0 when the file does not exist.
count_in() { { cat "$2" 2> /dev/null || true; } | grep -cF -- "$1"; }

SUB="$TMP/submission"
mkdir -p "$SUB/eval-infra" "$SUB/results" "$TMP/bin"
cp "$INFRA_SRC/run_eval.sh" "$INFRA_SRC/remote_eval.sh" "$INFRA_SRC/amis.json" "$INFRA_SRC/tools.lock" "$SUB/eval-infra/"

# ------------------------------------------------------------ throwaway con-unit repo
CU="$TMP/con-unit"
mkdir -p "$CU/fixtures" "$CU/tools"
printf 'module example.com/fake\n\ngo 1.26.10\n' > "$CU/go.mod"
{
    echo "# pinned dataset"
    for n in nginx memcached busybox alpine redis; do echo "index.docker.io/library/$n@sha256:$(printf '%064d' 1)"; done
} > "$CU/fixtures/evaluation_dataset_pinned.txt"
{
    echo "# top 10"
    for n in alpine ubuntu nginx postgres; do echo "index.docker.io/library/$n@sha256:$(printf '%064d' 2)"; done
} > "$CU/fixtures/evaluation_dataset_top10_pinned.txt"
cat > "$CU/tools/check_mirror.sh" <<'EOF'
#!/usr/bin/env bash
# stub: records how it was called, fails when FAKE_MIRROR_RC is set
mkdir -p "$OUT_DIR"
echo "{\"dataset\": \"$1\", \"delay\": \"$MIRROR_DELAY\"}" > "$OUT_DIR/mirror_check.json"
exit "${FAKE_MIRROR_RC:-0}"
EOF
chmod +x "$CU/tools/check_mirror.sh"
git -C "$CU" init -q
git -C "$CU" add -A
git -C "$CU" -c user.name=test -c user.email=test@example.invalid commit -q -m init
git -C "$CU" tag eval-v1

ssh-keygen -q -t ed25519 -N '' -f "$TMP/key"

# ------------------------------------------------------------ stubs
cat > "$TMP/bin/aws" <<'EOF'
#!/usr/bin/env bash
case "$*" in
    *"sts get-caller-identity"*) echo '{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/fake"}' ;;
    *"describe-images"*) echo '{"id":"ami-0123456789abcdef0","name":"ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20261108","creation_date":"2026-11-08T00:00:00.000Z","owner":"099720109477","arch":"x86_64","state":"available","deprecation_time":null,"root_device":"ebs","virtualization":"hvm"}' ;;
    *"describe-instances"* | *"describe-volumes"* | *"describe-security-groups"* | *"describe-key-pairs"*)
        if [ -e "$FAKE_DIR/alive" ]; then echo 1; else echo 0; fi ;;
    *"get-console-output"*) echo "" ;;
    *"--version"*) echo "aws-cli/2.0.0-fake" ;;
    *) echo "unexpected aws call: $*" >&2; exit 99 ;;
esac
EOF
cat > "$TMP/bin/tofu" <<'EOF'
#!/usr/bin/env bash
sub=""; state=""
for a in "$@"; do
    case "$a" in
        -chdir=*) ;;
        -state=*) state="${a#-state=}" ;;
        -*) ;;
        *) [ -z "$sub" ] && sub="$a" ;;
    esac
done
echo "$sub" >> "$FAKE_DIR/tofu_calls.log"
# What the real plan and destroy output prints: the SSH source address, the account id inside an
# ARN, the public key with its comment and the key path from an output.
plan_like() {
    echo '  + cidr_blocks = ["203.0.113.7/32"]'
    echo '  + arn         = "arn:aws:ec2:eu-central-1:123456789012:security-group/sg-0fake"'
    echo "  + public_key  = \"$(cat "${FAKE_PUBKEY:-/dev/null}")\""
    echo "  ssh_command = ssh -i $HOME/.ssh/conunit_eval ubuntu@198.51.100.10"
}
case "$sub" in
    version) echo "OpenTofu v0.0.0-fake" ;;
    init | validate | fmt) exit 0 ;;
    apply)
        echo resources > "$state"; touch "$FAKE_DIR/alive"
        plan_like
        [ "${FAKE_APPLY_FAIL:-0}" = 1 ] && exit 1
        exit 0 ;;
    output) echo '{"instance_id":{"value":"i-0fake"},"public_ip":{"value":"198.51.100.10"},"availability_zone":{"value":"eu-central-1a"},"ami_id":{"value":"ami-0123456789abcdef0"},"ami_name":{"value":"ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20261108"},"estimated_cost":{"value":"approx. fake"}}' ;;
    destroy)
        plan_like
        [ "${FAKE_DESTROY_FAIL:-0}" = 1 ] && exit 1
        : > "$state"; rm -f "$FAKE_DIR/alive" ;;
    state) [ -s "$state" ] && echo aws_instance.eval_node; exit 0 ;;
esac
EOF
cat > "$TMP/bin/ssh" <<'EOF'
#!/usr/bin/env bash
# skip options, find host, treat the rest as the remote command
while [ "$#" -gt 0 ]; do
    case "$1" in
        -n) shift ;;
        -F | -o) shift 2 ;;
        -V) echo "OpenSSH_fake"; exit 0 ;;
        *) break ;;
    esac
done
shift # host
cmd="$*"
printf '%s\n' "$cmd" >> "$FAKE_DIR/ssh_calls.log"
case "$cmd" in
    true)
        [ "${FAKE_SSH_DOWN:-0}" = 1 ] && { echo "ssh: connect to host: Connection refused" >&2; exit 255; }
        exit 0 ;;
    "bash -s -- "*)
        cat > "$FAKE_DIR/streamed_remote_script.sh"
        printf '%s\n' "$cmd" > "$FAKE_DIR/remote_args.txt"
        touch "$FAKE_DIR/remote_started"
        [ -n "${FAKE_REMOTE_SLEEP:-}" ] && exec sleep "$FAKE_REMOTE_SLEEP"
        run_id="$(printf '%s' "$cmd" | sed -n 's/.*--run-id \([^ ]*\).*/\1/p')"
        d="$FAKE_DIR/remote/results/$run_id"
        mkdir -p "$d/host"
        result="${FAKE_REMOTE_RESULT:-complete}"
        case "$result" in complete) rc=0 ;; incomplete) rc=3 ;; *) rc=1 ;; esac
        echo '{"run":{"engine_version":"4.9.3"}}' > "$d/empirical_study.json"
        echo '{"podman":"podman version 4.9.3","go":"go version go1.26.10 linux/amd64"}' > "$d/host/versions.json"
        echo '{"schema":"conunit-tool-versions/1","lock_sha256":"fake","locked":{},"tools":{"dockle":{"version":"0.4.15"}}}' > "$d/host/tool_versions.json"
        jq -n --arg r "$result" --argjson rc "$rc" '{result: $r, exit_code: $rc, registry_remap: "docker.io/library -> public.ecr.aws/docker/library", stages: {eval: {state: "ok", exit_code: 0}}}' > "$d/status.json"
        cp "$d/status.json" "$d/BENCHMARK_COMPLETE"
        ( cd "$d" && if command -v sha256sum > /dev/null; then sha256sum empirical_study.json host/versions.json host/tool_versions.json status.json; else shasum -a 256 empirical_study.json host/versions.json host/tool_versions.json status.json; fi > REMOTE_SHA256SUMS )
        echo "remote: finished with $result"
        exit "$rc" ;;
    *) exit 0 ;;
esac
EOF
cat > "$TMP/bin/rsync" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$FAKE_DIR/rsync_calls.log"
args=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        -a | --partial) shift ;;
        -e) shift 2 ;;
        *) args+=("$1"); shift ;;
    esac
done
dest="${args[${#args[@]}-1]}"
src="${args[0]}"
case "$src" in
    conunit-eval:*)
        path="${src#conunit-eval:}"
        run_id="$(basename "$path")"
        [ -d "$FAKE_DIR/remote/results/$run_id" ] || exit 23
        mkdir -p "$dest"
        cp -R "$FAKE_DIR/remote/results/$run_id/." "$dest/" ;;
    *)
        case "$dest" in
            conunit-eval:*) exit 0 ;;
            *) mkdir -p "$dest"; cp -R "$src". "$dest" 2> /dev/null || cp -R "$src" "$dest" ;;
        esac ;;
esac
EOF
chmod +x "$TMP/bin/aws" "$TMP/bin/tofu" "$TMP/bin/ssh" "$TMP/bin/rsync"

# ------------------------------------------------------------ driver
export CONUNIT_SSH_WAIT_ATTEMPTS=2 CONUNIT_SSH_WAIT_INTERVAL=0 CONUNIT_RETRY_SLEEP=0 CONUNIT_VERIFY_SLEEP=0 CONUNIT_HOSTKEY_SLEEP=0
export NO_COLOR=1
export FAKE_PUBKEY="$TMP/key.pub"

# run_case <name> <ENV=VALUE>... -- <run_eval args>
# Sets RC, FAKE_DIR, RUN_ID and the result paths.
run_case() {
    local name=$1
    shift
    local -a envs=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
        envs+=("$1")
        shift
    done
    shift
    RUN_ID="t-$name"
    FAKE_DIR="$TMP/fake-$name"
    mkdir -p "$FAKE_DIR"
    RESULTS="$SUB/results/$RUN_ID"
    env "${envs[@]}" PATH="$TMP/bin:$PATH" FAKE_DIR="$FAKE_DIR" \
        bash "$SUB/eval-infra/run_eval.sh" --con-unit-dir "$CU" --ssh-key "$TMP/key" --ssh-cidr 203.0.113.7/32 \
        --ami-id ami-0123456789abcdef0 --region eu-central-1 --run-id "$RUN_ID" "$@" > "$TMP/out-$name.log" 2>&1
    RC=$?
}
alive() { [ -e "$FAKE_DIR/alive" ] && echo yes || echo no; }
mj() { jq -r "$1" "$RESULTS/run_manifest.json"; }

echo "== A. canary success"
run_case a -- --canary
check "exit code 0" 0 "$RC"
check "resources destroyed" no "$(alive)"
check "manifest outcome" complete "$(mj .outcome)"
check "manifest teardown verified" true "$(mj .teardown.verified)"
check "manifest canary dataset has 3 entries" 3 "$(mj .dataset.eval.entries)"
check "manifest canary dataset path" fixtures/evaluation_dataset_canary.txt "$(mj .dataset.eval.path)"
check "manifest not tainted" false "$(mj .source.tainted)"
check "manifest bundle kind" tag "$(mj .source.bundle_kind)"
check "manifest commit equals the tag commit" "$(git -C "$CU" rev-parse eval-v1)" "$(mj .source.commit)"
check "manifest AMI id" ami-0123456789abcdef0 "$(mj .infrastructure.ami.id)"
check "manifest AMI name from describe-images" "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20261108" "$(mj .infrastructure.ami.name)"
check "manifest remote tool versions merged" "podman version 4.9.3" "$(mj .tool_versions.remote.podman)"
check "manifest carries the installed external tools" "0.4.15" "$(mj '.tool_versions.installed.tools.dockle.version')"
check "manifest records the hash of the shipped tools.lock" "$(sha "$INFRA_SRC/tools.lock")" "$(mj '.tool_versions.lock_sha256_shipped')"
check "the canary runs every stage" "eval,export,rq3,rq1,lint,crosscheck,attribute,ablate,reliability" "$(mj '.execution.stages | join(",")')"
check "the canary runs 4 RQ1 cases" 4 "$(mj .execution.rq1_cases)"
check "remote script gets --rq1-cases 4" 1 "$(count_in '--rq1-cases 4' "$FAKE_DIR/remote_args.txt")"
check "remote script gets the hash of tools.lock" 1 "$(count_in "--tools-lock-sha256 $(sha "$INFRA_SRC/tools.lock")" "$FAKE_DIR/remote_args.txt")"
check "remote script gets all stages" "eval,export,rq3,rq1,lint,crosscheck,attribute,ablate,reliability" "$(sed -n 's/.*--stages \([^ ]*\).*/\1/p' "$FAKE_DIR/remote_args.txt" | tr -d '\134')"
check "tools.lock is uploaded next to the bundle" 1 "$(count_in 'tools.lock' "$FAKE_DIR/rsync_calls.log" | awk '{print ($1 > 0)}')"
check "the hash of tools.lock is verified on the instance" 1 "$(count_in "$(sha "$INFRA_SRC/tools.lock")  tools.lock" "$FAKE_DIR/ssh_calls.log")"
check "the manifest lists the 10 image dataset for reliability" 3 "$(mj '.dataset.reliability.entries')"
check "the 10 image dataset is checked on the mirror" yes "$([ -f "$RESULTS/preflight/mirror_check_rq3.json" ] && echo yes || echo no)"
check "the installed tools file is part of the bundle checksums" 1 "$(count_in 'host/tool_versions.json' "$RESULTS/SHA256SUMS")"
check "manifest registry remap recorded" "docker.io/library -> public.ecr.aws/docker/library" "$(mj .execution.registry_remap)"
check "manifest rq3 iterations default for canary" 3 "$(mj .execution.rq3_iterations)"
check "manifest does not contain the operator address" 0 "$(grep -c '203.0.113.7' "$RESULTS/run_manifest.json")"
check "BENCHMARK_COMPLETE downloaded" yes "$([ -f "$RESULTS/BENCHMARK_COMPLETE" ] && echo yes || echo no)"
check "SHA256SUMS written" yes "$([ -s "$RESULTS/SHA256SUMS" ] && echo yes || echo no)"
check "SHA256SUMS verifies" 0 "$(cd "$RESULTS" && { sha256sum -c SHA256SUMS > /dev/null 2>&1 || shasum -a 256 -c SHA256SUMS > /dev/null 2>&1; }; echo $?)"
check "SHA256SUMS lists the manifest" 1 "$(grep -c 'run_manifest.json' "$RESULTS/SHA256SUMS")"
check "preflight mirror check copied into the bundle" yes "$([ -f "$RESULTS/preflight/mirror_check_eval.json" ] && echo yes || echo no)"
check "mirror check was run with at least 1 s delay" 1.1 "$(jq -r .delay "$RESULTS/preflight/mirror_check_eval.json")"
check "streamed remote script is the checked-in file" 0 "$(cmp -s "$FAKE_DIR/streamed_remote_script.sh" "$INFRA_SRC/remote_eval.sh"; echo $?)"
check "tofu destroy was called" 1 "$(grep -c '^destroy$' "$FAKE_DIR/tofu_calls.log")"
check "run directory holds state, ssh config and known_hosts" 3 "$(find "$SUB/eval-infra/.runs/$RUN_ID" -maxdepth 1 -type f \( -name terraform.tfstate -o -name ssh_config -o -name known_hosts \) | wc -l | tr -d ' ')"
check "ssh config disables agent forwarding and uses accept-new" 2 "$(grep -cE 'ForwardAgent no|StrictHostKeyChecking accept-new' "$SUB/eval-infra/.runs/$RUN_ID/ssh_config")"

echo "== B. remote reports incomplete"
run_case b FAKE_REMOTE_RESULT=incomplete --
check "exit code 3" 3 "$RC"
check "a plain run keeps the default stages" "eval,export,rq3" "$(mj '.execution.stages | join(",")')"
check "a plain run takes all RQ1 cases" 0 "$(mj .execution.rq1_cases)"
check "a plain run has no reliability dataset" null "$(mj '.dataset.reliability')"
check "resources destroyed" no "$(alive)"
check "manifest outcome" incomplete "$(mj .outcome)"
check "results were still downloaded" yes "$([ -f "$RESULTS/empirical_study.json" ] && echo yes || echo no)"

echo "== C. remote reports failed"
run_case c FAKE_REMOTE_RESULT=failed --
check "exit code 1" 1 "$RC"
check "resources destroyed" no "$(alive)"
check "manifest outcome" failed "$(mj .outcome)"

echo "== D. SSH never becomes reachable"
run_case d FAKE_SSH_DOWN=1 --
check "exit code 1" 1 "$RC"
check "resources destroyed" no "$(alive)"
check "manifest outcome" aborted-before-remote-run "$(mj .outcome)"
check "remote script was never streamed" no "$([ -f "$FAKE_DIR/streamed_remote_script.sh" ] && echo yes || echo no)"

echo "== E. tofu apply fails after creating something"
run_case e FAKE_APPLY_FAIL=1 --
check "exit code 1" 1 "$RC"
check "partially created resources destroyed" no "$(alive)"

echo "== F. destroy fails, then recovery with --destroy-run"
run_case f FAKE_DESTROY_FAIL=1 --
check "exit code 4 (teardown not verified)" 4 "$RC"
check "resources still alive" yes "$(alive)"
check "manifest says teardown not verified" false "$(mj .teardown.verified)"
check "output tells how to recover" 1 "$(grep -c -- '--destroy-run t-f' "$TMP/out-f.log" | awk '{print ($1 > 0)}')"
env PATH="$TMP/bin:$PATH" FAKE_DIR="$FAKE_DIR" bash "$SUB/eval-infra/run_eval.sh" --destroy-run t-f > "$TMP/out-f2.log" 2>&1
check "--destroy-run exits 0" 0 "$?"
check "--destroy-run destroyed the resources" no "$(alive)"

echo "== G. --keep leaves resources and --destroy-run cleans them"
run_case g -- --keep
check "exit code 0" 0 "$RC"
check "resources kept" yes "$(alive)"
check "manifest records keep" true "$(mj .teardown.kept)"
env PATH="$TMP/bin:$PATH" FAKE_DIR="$FAKE_DIR" bash "$SUB/eval-infra/run_eval.sh" --destroy-run t-g > "$TMP/out-g2.log" 2>&1
check "--destroy-run exits 0" 0 "$?"
check "resources destroyed afterwards" no "$(alive)"

echo "== H. mirror check failure stops before provisioning"
run_case h FAKE_MIRROR_RC=1 --
check "exit code 1" 1 "$RC"
check "tofu apply never called" 0 "$(grep -c '^apply$' "$FAKE_DIR/tofu_calls.log")"
check "no results directory" no "$([ -d "$RESULTS" ] && echo yes || echo no)"

echo "== I. tag handling and --allow-dirty"
run_case i1 -- --tag does-not-exist
check "missing tag aborts" 1 "$RC"
check "missing tag message" 1 "$(grep -c "tag 'does-not-exist' does not exist" "$TMP/out-i1.log" | awk '{print ($1 > 0)}')"
echo "uncommitted change" >> "$CU/fixtures/evaluation_dataset_top10_pinned.txt"
run_case i2 -- --allow-dirty --canary
check "allow-dirty run succeeds" 0 "$RC"
check "manifest tainted" true "$(mj .source.tainted)"
check "manifest bundle kind worktree" worktree "$(mj .source.bundle_kind)"
check "manifest working tree dirty" true "$(mj .source.working_tree_dirty)"
check "worktree diff recorded" yes "$([ -s "$RESULTS/preflight/worktree.diff" ] && echo yes || echo no)"
git -C "$CU" checkout -q -- fixtures/evaluation_dataset_top10_pinned.txt

echo "== J. SIGTERM during the remote run still destroys"
FAKE_DIR="$TMP/fake-j"
mkdir -p "$FAKE_DIR"
env PATH="$TMP/bin:$PATH" FAKE_DIR="$FAKE_DIR" FAKE_REMOTE_SLEEP=60 \
    bash "$SUB/eval-infra/run_eval.sh" --con-unit-dir "$CU" --ssh-key "$TMP/key" --ssh-cidr 203.0.113.7/32 \
    --ami-id ami-0123456789abcdef0 --region eu-central-1 --run-id t-j --canary > "$TMP/out-j.log" 2>&1 &
pid=$!
for _ in $(seq 1 100); do
    [ -e "$FAKE_DIR/remote_started" ] && break
    sleep 0.2
done
check "remote run had started" yes "$([ -e "$FAKE_DIR/remote_started" ] && echo yes || echo no)"
check "instance existed" yes "$([ -e "$FAKE_DIR/alive" ] && echo yes || echo no)"
kill -TERM "$pid" 2> /dev/null
pkill -TERM -P "$pid" 2> /dev/null
wait "$pid"
RC=$?
check "exit code 143" 143 "$RC"
check "resources destroyed after SIGTERM" no "$([ -e "$FAKE_DIR/alive" ] && echo yes || echo no)"

echo "== K. usage errors"
run_case k1 -- --ssh-cidr 0.0.0.0/0
check "open SSH CIDR rejected" 2 "$RC"
run_case k2 -- --mirror-delay 0.5
check "mirror delay below 1 s rejected" 2 "$RC"
run_case k3 -- --stages eval,bogus
check "unknown stage rejected" 2 "$RC"
run_case k4 -- --run-id 'bad/id'
check "malformed run id rejected" 2 "$RC"
run_case k5 -- --rq1-cases abc
check "--rq1-cases that is not a number rejected" 2 "$RC"
run_case k6 -- --rq1-cases -1
check "--rq1-cases below zero rejected" 2 "$RC"
run_case k7 -- --stages eval,rq
check "a stage name that is only a prefix rejected" 2 "$RC"

remote_stages() { sed -n 's/.*--stages \([^ ]*\).*/\1/p' "$FAKE_DIR/remote_args.txt" | tr -d '\134'; }
remote_value() { sed -n "s/.*$1 \\([^ ]*\\).*/\\1/p" "$FAKE_DIR/remote_args.txt"; }

echo "== N. stage selection"
run_case n1 -- --stages eval,export,attribute,ablate,reliability
check "run B stages: exit code 0" 0 "$RC"
check "run B stages: all of them reach the instance" "eval,export,attribute,ablate,reliability" "$(remote_stages)"
check "run B stages: the 10 image dataset is checked on the mirror (reliability reads it)" yes "$([ -f "$RESULTS/preflight/mirror_check_rq3.json" ] && echo yes || echo no)"
check "run B stages: the manifest lists the reliability dataset" fixtures/evaluation_dataset_top10_pinned.txt "$(mj '.dataset.reliability.path')"
check "run B stages: RQ1 runs all cases when it runs" 0 "$(remote_value --rq1-cases)"
run_case n2 -- --stages eval,export,rq3,rq1,lint,crosscheck
check "run A stages: exit code 0" 0 "$RC"
check "run A stages: all of them reach the instance" "eval,export,rq3,rq1,lint,crosscheck" "$(remote_stages)"
check "run A stages: the reliability dataset is not listed" null "$(mj '.dataset.reliability')"
run_case n3 -- --stages eval,export
check "eval and export only: no 10 image dataset is checked" no "$([ -f "$RESULTS/preflight/mirror_check_rq3.json" ] && echo yes || echo no)"
check "eval and export only: the manifest has no 10 image dataset" null "$(mj '.dataset.rq3.path')"
run_case n4 -- --canary --stages eval,export
check "a canary with explicit stages keeps them" "eval,export" "$(remote_stages)"
check "a canary with explicit stages still runs 4 RQ1 cases by default" 4 "$(remote_value --rq1-cases)"
run_case n5 -- --canary --rq1-cases 2
check "--rq1-cases overrides the canary default" 2 "$(remote_value --rq1-cases)"
check "the manifest records the override" 2 "$(mj .execution.rq1_cases)"

echo "== O. a tools.lock that is not usable stops the pre-flight before anything is provisioned"
cp "$SUB/eval-infra/tools.lock" "$TMP/tools.lock.good"
lock_run() { # name sed-expression
    cp "$TMP/tools.lock.good" "$SUB/eval-infra/tools.lock"
    sed -i.bak "$2" "$SUB/eval-infra/tools.lock"
    rm -f "$SUB/eval-infra/tools.lock.bak"
    run_case "$1" --
}
tofu_apply_calls() { { cat "$FAKE_DIR/tofu_calls.log" 2> /dev/null || true; } | grep -c '^apply$'; }
lock_run o1 's/^trivy \(.*\) [0-9a-f]\{64\}$/trivy \1 UNVERIFIED-no-release-checksum/'
check "a placeholder hash: exit code 1" 1 "$RC"
check "a placeholder hash: tofu apply never called" 0 "$(tofu_apply_calls)"
check "a placeholder hash: the message says placeholder" 1 "$(count_in 'placeholder' "$TMP/out-o1.log" | awk '{print ($1 > 0)}')"
check "a placeholder hash: no results directory" no "$([ -d "$RESULTS" ] && echo yes || echo no)"
lock_run o2 '/^dockle /d'
check "a tool that is not pinned: exit code 1" 1 "$RC"
check "a tool that is not pinned: the message names it" 1 "$(count_in 'tool dockle is pinned 0 times' "$TMP/out-o2.log" | awk '{print ($1 > 0)}')"
lock_run o3 's/^hadolint \([^ ]*\) https:/hadolint \1 http:/'
check "a url that is not a github.com url: exit code 1" 1 "$RC"
lock_run o4 's/^trivy \([^ ]*\) \([^ ]*\) .*/trivy \1 \2/'
check "a line with three fields: exit code 1" 1 "$RC"
rm -f "$SUB/eval-infra/tools.lock"
run_case o5 --
check "no tools.lock at all: exit code 1" 1 "$RC"
check "no tools.lock at all: tofu apply never called" 0 "$(tofu_apply_calls)"
cp "$TMP/tools.lock.good" "$SUB/eval-infra/tools.lock"
run_case o6 --
check "the committed tools.lock passes the pre-flight" 0 "$RC"

echo "== L. pre-flight only"
run_case l -- --preflight-only
check "exit code 0" 0 "$RC"
check "tofu apply never called" 0 "$(grep -c '^apply$' "$FAKE_DIR/tofu_calls.log")"
check "outcome line" 1 "$(grep -c 'preflight-passed' "$TMP/out-l.log" | awk '{print ($1 > 0)}')"

echo "== M. the bundle is redacted, the local originals are not"
# HOME is pointed at the temp directory so that every path of this run counts as a home path.
run_case m HOME="$TMP" -- --canary
key_comment="$(awk 'NR == 1 {print $3}' "$TMP/key.pub")"
local_log="$SUB/eval-infra/.runs/$RUN_ID/run_eval.log"
has() { grep -cF -- "$1" "$2" | awk '{print ($1 > 0) ? "yes" : "no"}'; }
check "exit code 0" 0 "$RC"
check "the test key carries a user@host comment" yes "$([[ "$key_comment" == *@* ]] && echo yes || echo no)"
check "local transcript still has the operator address" yes "$(has 203.0.113.7 "$local_log")"
check "local transcript still has the account id" yes "$(has 123456789012 "$local_log")"
check "bundle transcript has no operator address" no "$(has 203.0.113.7 "$RESULTS/run_eval.log")"
check "bundle transcript has no account id" no "$(has 123456789012 "$RESULTS/run_eval.log")"
check "bundle transcript has no home directory" no "$(has "$TMP" "$RESULTS/run_eval.log")"
check "bundle transcript has no key comment" no "$(has "$key_comment" "$RESULTS/run_eval.log")"
check "bundle transcript shows the address placeholder" yes "$(has '<operator-ip>' "$RESULTS/run_eval.log")"
check "bundle transcript shows the account placeholder" yes "$(has '<aws-account-id>' "$RESULTS/run_eval.log")"
check "bundle transcript shows the key comment placeholder" yes "$(has '<key-comment>' "$RESULTS/run_eval.log")"
# shellcheck disable=SC2088 # a literal tilde is exactly what the redaction writes
check "bundle transcript shows the home placeholder" yes "$(has '~/.ssh/conunit_eval' "$RESULTS/run_eval.log")"
check "instance address is kept, it is gone after teardown" yes "$(has 198.51.100.10 "$RESULTS/run_eval.log")"
check "preflight git.txt has no home directory" no "$(has "$TMP" "$RESULTS/preflight/git.txt")"
check "preflight git.txt shows the checkout under ~" yes "$(has 'con_unit_dir=~/con-unit' "$RESULTS/preflight/git.txt")"
check "REDACTION.txt is in the bundle" yes "$([ -s "$RESULTS/REDACTION.txt" ] && echo yes || echo no)"
check "REDACTION.txt is covered by SHA256SUMS" 1 "$(grep -c 'REDACTION.txt' "$RESULTS/SHA256SUMS")"
check "SHA256SUMS still verifies" 0 "$(cd "$RESULTS" && { sha256sum -c SHA256SUMS > /dev/null 2>&1 || shasum -a 256 -c SHA256SUMS > /dev/null 2>&1; }; echo $?)"
check "files from the instance are byte for byte as the instance wrote them" 0 "$(cmp -s "$FAKE_DIR/remote/results/$RUN_ID/status.json" "$RESULTS/status.json"; echo $?)"

echo "== P. the redacted bundle, with the new outputs, passes the identifier scan"
# aws and curl are replaced so that the scanner knows the account id and the address of the test run.
mkdir -p "$TMP/scanstubs"
printf '#!/bin/sh\nprintf "123456789012\\tarn:aws:iam::123456789012:user/Test.User\\n"\n' > "$TMP/scanstubs/aws"
printf '#!/bin/sh\necho 203.0.113.7\n' > "$TMP/scanstubs/curl"
chmod +x "$TMP/scanstubs/aws" "$TMP/scanstubs/curl"
scan_out="$(PATH="$TMP/scanstubs:$PATH" bash "$INFRA_SRC/scan_secrets.sh" --identifiers "$RESULTS" 2>&1)"
check "the redacted bundle is clean" 0 "$(PATH="$TMP/scanstubs:$PATH" bash "$INFRA_SRC/scan_secrets.sh" --identifiers "$RESULTS" > /dev/null 2>&1; echo $?)"
check "the scan says CLEAN" 1 "$(printf '%s\n' "$scan_out" | grep -c CLEAN)"
check "the bundle holds the file with the installed tools" yes "$([ -s "$RESULTS/host/tool_versions.json" ] && echo yes || echo no)"
# The same scanner finds the identifiers in the local original, so the clean result above means something.
check "the unredacted local transcript is flagged" 1 "$(PATH="$TMP/scanstubs:$PATH" bash "$INFRA_SRC/scan_secrets.sh" --identifiers "$local_log" > /dev/null 2>&1; echo $?)"

echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
