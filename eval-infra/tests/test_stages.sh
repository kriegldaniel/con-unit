#!/usr/bin/env bash
# Offline test of the stages that remote_eval.sh runs after eval: export, rq3, rq1, lint,
# crosscheck, attribute, ablate and reliability. The real binaries are replaced by one fake that
# records its command line and writes the main output of its stage, the engine by a function. The
# test pins the exact commands, the order, the guard that fails a stage early when a tool or binary
# is missing, the mapping of exit codes to stage states, the seeded images of the attribution, the
# reliability runs, the per stage output checksum, the canary subsets and the run block tool check.
#
# Usage: bash eval-infra/tests/test_stages.sh   (needs bash 4+, jq, awk, sha256sum or shasum)
#
# shellcheck disable=SC2016 # the snippets are single quoted on purpose, they expand inside the harness
# shellcheck source-path=SCRIPTDIR
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.sh
. "$HERE/harness.sh"

sha() { if command -v sha256sum > /dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
has() { case "$1" in *"$2"*) echo yes ;; *) echo no ;; esac; }

SRC="$WORK/base/src"
RES="$WORK/base/results/t"
CALLS="$WORK/calls.log"
STORE="$WORK/store.txt"
export CALLS STORE

# ------------------------------------------------------------------ fakes
# One fake for every binary of the bundle. It logs "<name> <arguments>" to CALLS, writes the output
# file that its stage waits for into -out-dir or --out-dir (only when it succeeds, a failed run
# leaves nothing), and exits with FAKE_RC_<key>, else FAKE_RC, else 0. The key of con-unit is
# con_unit_<out-dir name> and the keys of attribute_exec are attribute_exec, attribute_exec_truth
# and attribute_exec_ablation. The fake rq1 puts the images of -cases into the fake store, like the
# builder does, unless FAKE_NO_BUILD is 1.
cat > "$WORK/fakebin" << 'EOF'
#!/bin/sh
name=$(basename "$0")
echo "$name $*" >> "$CALLS"
out=''; cases=''; prefix=localhost/conunit-rq1; prev=''; mode=''
for a in "$@"; do
    case "$prev" in
        -out-dir | --out-dir) out=$a ;;
        -cases) cases=$a ;;
        -image-prefix) prefix=$a ;;
    esac
    case "$a" in
        -truth) mode=_truth ;;
        -ablation) mode=_ablation ;;
    esac
    prev=$a
done
key=$(echo "$name" | tr - _)
case "$name" in
    con-unit) key="con_unit_$(basename "$out")" ;;
    attribute_exec) key="attribute_exec$mode" ;;
esac
eval "rc=\${FAKE_RC_$key:-\${FAKE_RC:-0}}"
[ "$name" = rq1 ] && env | grep '^TRIVY_' | sort | tr '\n' ' ' > "$CALLS.rq1env"
if [ "$name" = rq1 ] && [ -n "$cases" ] && [ "${FAKE_NO_BUILD:-0}" != 1 ]; then
    for c in $(echo "$cases" | tr , ' '); do echo "$prefix/$c:rq1" >> "$STORE"; done
fi
if [ -n "$out" ] && { [ "$rc" = 0 ] || [ "$rc" = 3 ]; } && [ "${FAKE_NO_OUTPUT:-0}" != 1 ]; then
    mkdir -p "$out"
    case "$name" in
        con-unit) echo '{"images":[]}' > "$out/empirical_study.json" ;;
        rq1) echo '{}' > "$out/rq1_results.json" ;;
        crosscheck) echo '{}' > "$out/crosscheck.json" ;;
        attribute_exec) if [ "$mode" = _ablation ]; then echo '{}' > "$out/ablation.json"; else echo '{}' > "$out/attribution.json"; fi ;;
        reliability) echo '{}' > "$out/reliability.json" ;;
    esac
fi
exit "$rc"
EOF
chmod +x "$WORK/fakebin"

# The four external tools exist on PATH, as the installer leaves them.
mkdir -p "$WORK/toolbin"
for t in dockle hadolint trivy container-structure-test; do
    printf '#!/bin/sh\nexit 0\n' > "$WORK/toolbin/$t"
    chmod +x "$WORK/toolbin/$t"
done

# What every case runs first, inside the harness: the variables of a run, the engine as a function
# (it just runs the command), podman as a function over a store file, the tool versions the
# installer would have recorded, then CASE_PRE (variable overrides) and the status file.
cat > "$WORK/pre.sh" << 'EOF'
RUN_ID=t; COMMIT=abcdef1
STAGES=$CASE_STAGES
RESULTS_DIR=$CONUNIT_BASE_DIR/results/t; STATUS_FILE=$RESULTS_DIR/status.json
mkdir -p "$RESULTS_DIR/host" "$RESULTS_DIR/stage_logs"
engine_user() { "$@"; }
pm() {
    case "$1" in
        image) [ "$2" = exists ] && grep -qxF "$3" "$STORE" ;;
        pull)
            echo "pull ${*: -1}" >> "$CALLS"
            [ "${FAKE_PULL_FAIL:-0}" != 1 ] || return 1
            echo "${*: -1}" >> "$STORE"
            ;;
    esac
}
EVAL_DATASET_PATH=fixtures/evaluation_dataset_pinned.txt
RQ3_DATASET_PATH=fixtures/evaluation_dataset_top10_pinned.txt
RELIABILITY_DATASET_PATH=$RQ3_DATASET_PATH
ENV_ITERATIONS=3
if [ "$CASE_TOOLS" = yes ]; then
    PATH=$WORK_TOOLBIN:$PATH
    jq -n '{tools: {dockle: {version: "0.4.15"}, hadolint: {version: "2.14.0"}, trivy: {version: "0.76.1"}, "container-structure-test": {version: "1.22.1"}}}' > "$RESULTS_DIR/host/tool_versions.json"
fi
eval "${CASE_PRE:-}"
# the fake binaries are child processes, so every FAKE_ variable of the case has to be exported
for v in $(set | awk -F= '/^FAKE_[A-Za-z0-9_]*=/ { print $1 }'); do export "$v"; done
status_init
EOF

TOP10_A="index.docker.io/library/alpine@sha256:$(printf '%064d' 2)"
TOP10_B="index.docker.io/library/ubuntu@sha256:$(printf '%064d' 3)"
TOP10_C="index.docker.io/library/nginx@sha256:$(printf '%064d' 4)"
TOP10_D="index.docker.io/library/redis@sha256:$(printf '%064d' 4)"
SEEDED="localhost/conunit-rq1/needs-setuid-setgid-defect:rq1 localhost/conunit-rq1/writes-outside-tmp-defect:rq1 localhost/conunit-rq1/nonroot-privileged-port-defect:rq1"

write_fixtures() {
    local b
    rm -rf "${WORK:?}/base"
    mkdir -p "$SRC/bin" "$SRC/fixtures/rq1" "$WORK/base/incoming"
    for b in con-unit export_latex benchmark_rq3 rq1 crosscheck attribute_exec reliability; do
        cp "$WORK/fakebin" "$SRC/bin/$b"
    done
    printf '{"cases":[{"id":"root-user-implicit"},{"id":"root-user-explicit"},{"id":"root-user-clean"},{"id":"no-healthcheck-defect"},{"id":"no-healthcheck-clean"},{"id":"setuid-binary-defect"}]}\n' > "$SRC/fixtures/rq1/oracle.json"
    cat > "$SRC/fixtures/rq1/tier3_truth.json" << 'TRUTH'
{"schema_version": 1, "image_prefix": "localhost/conunit-rq1", "cases": [
  {"case": "needs-setuid-setgid-defect", "rule": "EXEC-02", "expected_minimal": ["CAP_SETGID", "CAP_SETUID"], "manifests": true},
  {"case": "writes-outside-tmp-defect", "rule": "EXEC-01", "expected_minimal": ["/var/lib"], "manifests": true},
  {"case": "nonroot-privileged-port-defect", "rule": "EXEC-02", "expected_minimal": ["CAP_NET_BIND_SERVICE"], "manifests": false}]}
TRUTH
    printf '# pinned\nindex.docker.io/library/nginx@sha256:%064d\nindex.docker.io/library/busybox@sha256:%064d\nindex.docker.io/library/alpine@sha256:%064d\nindex.docker.io/library/redis@sha256:%064d\n' 1 1 1 1 > "$SRC/fixtures/evaluation_dataset_pinned.txt"
    printf '# top 10\n%s\n%s\n%s\n%s\n' "$TOP10_A" "$TOP10_B" "$TOP10_C" "$TOP10_D" > "$SRC/fixtures/evaluation_dataset_top10_pinned.txt"
    echo '{}' > "$SRC/fixtures/evaluation_dataset_audit.json"
    echo '{}' > "$SRC/fixtures/evaluation_dataset_pinned.json"
    : > "$CALLS"
    : > "$STORE"
}

# case_run <requested stages> <tools yes|no> <snippet> [variable overrides]
# Sets OUT. The results directory is RES, the recorded calls are in CALLS.
case_run() {
    write_fixtures
    OUT=$(CASE_STAGES="$1" CASE_TOOLS="$2" CASE_PRE="${4:-}" WORK_TOOLBIN="$WORK/toolbin" run_in_harness ". '$WORK/pre.sh'; $3" 2>&1)
}
sj() { jq -r "$1" "$RES/status.json"; }
state_of() { sj ".stages[\"$1\"] | \"\(.state) \(.exit_code)\""; }
call() { sed -n "${1}p" "$CALLS"; }
ncalls() { grep -c . "$CALLS" || true; }
STUDY='mkdir -p "$RESULTS_DIR"; echo "{}" > "$RESULTS_DIR/empirical_study.json"'
LINT_STUDY='mkdir -p "$RESULTS_DIR/lint"; echo "{}" > "$RESULTS_DIR/lint/empirical_study.json"'
SEED_ALL='for i in '"$SEEDED"'; do echo "$i" >> "$STORE"; done'

echo "== the fixed order of the stages in main"
order=$(grep -o 'stage_requested [a-z0-9]* && stage_[a-z0-9]*' "$WORK/lib.sh" | awk '{print $2}' | paste -sd' ' -)
check "export, rq3, rq1, lint, crosscheck, attribute, ablate, reliability" "export rq3 rq1 lint crosscheck attribute ablate reliability" "$order"
prereqs=$(grep -o '^    prereq [a-z_]*' "$WORK/lib.sh" | awk '{print $2}' | paste -sd' ' -)
check "the tools are installed after the packages and before anything is built or run" "host bundle go packages tools registry docker_hub_block mode datasets mirror_proof host_info build" "$prereqs"

echo "== export passes the pinned dataset"
case_run export no 'cd "$SRC_DIR"; '"$STUDY"'; stage_export'
check "the call" "export_latex -out $RES -audit fixtures/evaluation_dataset_audit.json -pinned fixtures/evaluation_dataset_pinned.json $RES/empirical_study.json" "$(call 1)"
check "the stage is ok" "ok 0" "$(state_of export)"
case_run export no 'cd "$SRC_DIR"; '"$STUDY"'; rm -f fixtures/evaluation_dataset_pinned.json; stage_export'
check "the pinned file is missing: the stage fails with 66" "failed 66" "$(state_of export)"
check "the pinned file is missing: nothing was exported" 0 "$(ncalls)"
case_run export no 'cd "$SRC_DIR"; stage_export'
check "no study: the stage fails with 66" "failed 66" "$(state_of export)"

echo "== rq3 passes the Dockle binary"
case_run rq3 yes 'cd "$SRC_DIR"; stage_rq3'
check "the call ends with -dockle dockle" "benchmark_rq3 -file fixtures/evaluation_dataset_top10_pinned.txt -pack cis -out-dir $RES/rq3 -iterations 3 -warmup 1 -platform linux/amd64 -probe-window 3s -engine podman -image-source auto -dockle dockle" "$(call 1)"
check "the stage is ok" "ok 0" "$(state_of rq3)"
case_run rq3 no 'cd "$SRC_DIR"; stage_rq3'
check "dockle is missing: the stage fails early with 127" "failed 127" "$(state_of rq3)"
check "dockle is missing: the benchmark did not start" 0 "$(ncalls)"
check "dockle is missing: the log names the tool" yes "$(has "$(cat "$RES/stage_logs/rq3.log")" "tool:dockle")"

echo "== rq1"
case_run rq1 yes 'cd "$SRC_DIR"; stage_rq1'
check "the call, all cases" "rq1 -oracle fixtures/rq1/oracle.json -out-dir $RES/rq1 -conunit $SRC/bin/con-unit -engine podman -keep-images -require-all" "$(call 1)"
check "trivy runs with the offline environment only" "TRIVY_DISABLE_TELEMETRY=true TRIVY_NO_PROGRESS=true TRIVY_OFFLINE_SCAN=true TRIVY_SKIP_CHECK_UPDATE=true TRIVY_SKIP_DB_UPDATE=true TRIVY_SKIP_JAVA_DB_UPDATE=true TRIVY_SKIP_VERSION_CHECK=true " "$(cat "$CALLS.rq1env")"
check "the stage is ok" "ok 0" "$(state_of rq1)"
check "the case selection is recorded" "all" "$(sj '.rq1_case_selection')"
case_run rq1 yes 'cd "$SRC_DIR"; stage_rq1' 'RQ1_CASES=4'
check "four cases: the first four of the oracle" "rq1 -oracle fixtures/rq1/oracle.json -out-dir $RES/rq1 -conunit $SRC/bin/con-unit -engine podman -keep-images -cases root-user-implicit,root-user-explicit,root-user-clean,no-healthcheck-defect" "$(call 1)"
check "four cases: -require-all is not passed, the other cases are NOT_RUN by design" "no" "$(has "$(call 1)" "-require-all")"
check "four cases: the stage is ok" "ok 0" "$(state_of rq1)"
check "four cases: the selection is recorded" "root-user-implicit,root-user-explicit,root-user-clean,no-healthcheck-defect" "$(sj '.rq1_case_selection')"
case_run rq1 yes 'cd "$SRC_DIR"; stage_rq1' 'RQ1_CASES=1'
check "one case" "yes" "$(has "$(call 1)" "-cases root-user-implicit")"
check "one case: no second case" "no" "$(has "$(call 1)" "root-user-explicit")"
case_run rq1 yes 'cd "$SRC_DIR"; stage_rq1' 'RQ1_CASES=99'
check "more cases than the oracle has: all six" "root-user-implicit,root-user-explicit,root-user-clean,no-healthcheck-defect,no-healthcheck-clean,setuid-binary-defect" "$(call 1 | sed 's/.*-cases //')"
case_run rq1 yes 'cd "$SRC_DIR"; rm fixtures/rq1/oracle.json; stage_rq1'
check "no oracle: the stage fails with 66" "failed 66" "$(state_of rq1)"
case_run rq1 yes 'cd "$SRC_DIR"; echo "{\"cases\":[]}" > fixtures/rq1/oracle.json; stage_rq1' 'RQ1_CASES=4'
check "an oracle without cases and --rq1-cases: the stage fails with 65" "failed 65" "$(state_of rq1)"
case_run rq1 no 'cd "$SRC_DIR"; stage_rq1'
check "tools missing: the stage fails early with 127" "failed 127" "$(state_of rq1)"
check "tools missing: all four are named" "tool:dockle tool:hadolint tool:trivy tool:container-structure-test" "$(grep -o 'tool:[a-z-]*' "$RES/stage_logs/rq1.log" | paste -sd' ' -)"
check "tools missing: nothing ran" 0 "$(ncalls)"
case_run rq1 yes 'cd "$SRC_DIR"; rm bin/rq1; stage_rq1'
check "binary missing: the stage fails early with 127" "failed 127" "$(state_of rq1)"
case_run rq1 yes 'cd "$SRC_DIR"; stage_rq1' 'FAKE_NO_OUTPUT=1'
check "exit 0 without rq1_results.json: the stage fails with 66" "failed 66" "$(state_of rq1)"
check "exit 0 without rq1_results.json: the outputs hold no file" "0" "$(sj '.stages.rq1.outputs.files')"
case_run rq1 yes 'cd "$SRC_DIR"; stage_rq1'
check "the outputs are recorded with a file count" "1 rq1" "$(sj '.stages.rq1.outputs | "\(.files) \(.dir)"')"

echo "== lint"
case_run lint no 'cd "$SRC_DIR"; stage_lint'
check "the call" "con-unit eval --images fixtures/evaluation_dataset_pinned.txt --pack lint --out-dir $RES/lint --engine podman --platform linux/amd64 --image-source auto" "$(call 1)"
check "the stage is ok" "ok 0" "$(state_of lint)"
case_run lint no 'cd "$SRC_DIR"; stage_lint' 'RESUME=1'
check "resume is passed on" "yes" "$(has "$(call 1)" " --resume")"
case_run lint no 'cd "$SRC_DIR"; stage_lint' 'IMAGE_SOURCE=local'
check "the image source of the run is used" "yes" "$(has "$(call 1)" "--image-source local")"
case_run lint no 'cd "$SRC_DIR"; stage_lint' 'FAKE_NO_OUTPUT=1'
check "exit 0 without a study: the stage fails with 66" "failed 66" "$(state_of lint)"

echo "== crosscheck"
case_run crosscheck yes 'cd "$SRC_DIR"; '"$LINT_STUDY"'; stage_crosscheck'
check "the call" "crosscheck -study $RES/lint/empirical_study.json -dockle dockle -engine podman -platform linux/amd64 -out-dir $RES/crosscheck" "$(call 1)"
check "the stage is ok" "ok 0" "$(state_of crosscheck)"
case_run crosscheck yes 'cd "$SRC_DIR"; stage_crosscheck'
check "no lint study: the stage fails with 66" "failed 66" "$(state_of crosscheck)"
check "no lint study: the message names the lint stage" yes "$(has "$(cat "$RES/stage_logs/crosscheck.log")" "stage lint has to run first")"
case_run crosscheck no 'cd "$SRC_DIR"; '"$LINT_STUDY"'; stage_crosscheck'
check "dockle missing: the stage fails early with 127" "failed 127" "$(state_of crosscheck)"
case_run crosscheck yes 'cd "$SRC_DIR"; '"$LINT_STUDY"'; rm bin/crosscheck; stage_crosscheck'
check "binary missing: the stage fails early with 127" "failed 127" "$(state_of crosscheck)"

echo "== attribute"
case_run attribute no 'cd "$SRC_DIR"; '"$STUDY"'; '"$SEED_ALL"'; stage_attribute'
check "seeded images present: two calls" 2 "$(ncalls)"
check "the study run comes first" "attribute_exec -engine podman -out-dir $RES/attribution -study $RES/empirical_study.json" "$(call 1)"
check "the truth run follows" "attribute_exec -engine podman -out-dir $RES/attribution -truth fixtures/rq1/tier3_truth.json -image-prefix localhost/conunit-rq1" "$(call 2)"
check "the stage is ok" "ok 0" "$(state_of attribute)"
check "the seeded images were present" "present" "$(sj '.stages.attribute.seeded.state')"
check "the outputs of the stage are recorded" "attribution" "$(sj '.stages.attribute.outputs.dir')"

case_run attribute no 'cd "$SRC_DIR"; '"$STUDY"'; stage_attribute'
check "seeded images absent: study run, builder, truth run" 3 "$(ncalls)"
check "the builder only runs ConUnit on the seeded cases and keeps the images" "rq1 -oracle fixtures/rq1/oracle.json -out-dir $RES/attribution/seeded_build -conunit $SRC/bin/con-unit -engine podman -tools conunit -cases needs-setuid-setgid-defect,writes-outside-tmp-defect,nonroot-privileged-port-defect -image-prefix localhost/conunit-rq1 -keep-images" "$(call 2)"
check "then the truth run" "attribute_exec -engine podman -out-dir $RES/attribution -truth fixtures/rq1/tier3_truth.json -image-prefix localhost/conunit-rq1" "$(call 3)"
check "the stage is ok" "ok 0" "$(state_of attribute)"
check "the seeded images were built" "built" "$(sj '.stages.attribute.seeded.state')"

case_run attribute no 'cd "$SRC_DIR"; '"$STUDY"'; stage_attribute' 'FAKE_NO_BUILD=1'
check "the build leaves the images missing: no truth run" 2 "$(ncalls)"
check "the stage ends incomplete, never a silent skip" "incomplete 3" "$(state_of attribute)"
check "the seeded state says unavailable" "unavailable" "$(sj '.stages.attribute.seeded.state')"
check "the log names the missing images" yes "$(has "$(cat "$RES/stage_logs/attribute.log")" "seeded images still absent")"

case_run attribute no 'cd "$SRC_DIR"; '"$STUDY"'; rm fixtures/rq1/tier3_truth.json; stage_attribute'
check "no truth file: only the study run" 1 "$(ncalls)"
check "no truth file: incomplete" "incomplete 3" "$(state_of attribute)"
check "no truth file: the state says so" "no-truth-file" "$(sj '.stages.attribute.seeded.state')"

case_run attribute no 'cd "$SRC_DIR"; '"$STUDY"'; '"$SEED_ALL"'; stage_attribute' 'FAKE_RC_attribute_exec=3'
check "the study run exits 3: incomplete" "incomplete 3" "$(state_of attribute)"
check "the study run exits 3: the truth run still happens" 2 "$(ncalls)"
case_run attribute no 'cd "$SRC_DIR"; '"$STUDY"'; '"$SEED_ALL"'; stage_attribute' 'FAKE_RC_attribute_exec=1'
check "the study run fails: the stage fails" "failed 1" "$(state_of attribute)"
check "the study run fails: the truth run still happens" 2 "$(ncalls)"
case_run attribute no 'cd "$SRC_DIR"; '"$STUDY"'; '"$SEED_ALL"'; stage_attribute' 'FAKE_RC_attribute_exec_truth=1'
check "the truth run fails: the stage fails" "failed 1" "$(state_of attribute)"
case_run attribute no 'cd "$SRC_DIR"; '"$SEED_ALL"'; stage_attribute'
check "no study: the stage fails with 66" "failed 66" "$(state_of attribute)"
check "no study: nothing ran" 0 "$(ncalls)"
case_run attribute no 'cd "$SRC_DIR"; '"$STUDY"'; rm bin/rq1; stage_attribute'
check "the builder binary is missing: the stage fails early with 127" "failed 127" "$(state_of attribute)"

echo "== ablate"
case_run ablate no 'cd "$SRC_DIR"; '"$STUDY"'; stage_ablate'
check "the call" "attribute_exec -ablation -study $RES/empirical_study.json -engine podman -out-dir $RES/attribution" "$(call 1)"
check "the stage is ok" "ok 0" "$(state_of ablate)"
check "ablate writes into the out-dir of attribute" "attribution" "$(sj '.stages.ablate.outputs.dir')"
case_run ablate no 'cd "$SRC_DIR"; '"$STUDY"'; stage_ablate' 'FAKE_NO_OUTPUT=1'
check "exit 0 without ablation.json: the stage fails with 66" "failed 66" "$(state_of ablate)"
case_run ablate no 'cd "$SRC_DIR"; stage_ablate'
check "no study: the stage fails with 66" "failed 66" "$(state_of ablate)"
case_run attribute,ablate no 'cd "$SRC_DIR"; '"$STUDY"'; '"$SEED_ALL"'; stage_attribute; stage_ablate'
check "attribute and ablate share one directory" "$RES/attribution" "$(grep -o -- '-out-dir [^ ]*' "$CALLS" | sort -u | awk '{print $2}')"
check "both outputs are in it" "ablation.json attribution.json" "$(find "$RES/attribution" -type f | sed 's|.*/||' | sort | paste -sd' ' -)"

echo "== reliability"
RUNS="r1=$RES/reliability/r1,r2=$RES/reliability/r2,r3=$RES/reliability/r3"
WINS="w3=$RES/reliability/r1,w10=$RES/reliability/w10,w30=$RES/reliability/w30"
eval_call() { # run window
    echo "con-unit eval --images fixtures/evaluation_dataset_top10_pinned.txt --pack cis --out-dir $RES/reliability/$1 --engine podman --platform linux/amd64 --image-source auto --probe-window $2"
}
STORE_BOTH="printf '%s\\n' '$TOP10_A' '$TOP10_B' '$TOP10_C' '$TOP10_D' >> \"\$STORE\""
case_run reliability no 'cd "$SRC_DIR"; '"$STORE_BOTH"'; stage_reliability'
check "five evals and the summary, no pull when the images are in the store" 6 "$(ncalls)"
check "run r1 at 3 s" "$(eval_call r1 3s)" "$(call 1)"
check "run r2 at 3 s" "$(eval_call r2 3s)" "$(call 2)"
check "run r3 at 3 s" "$(eval_call r3 3s)" "$(call 3)"
check "run w10 at 10 s" "$(eval_call w10 10s)" "$(call 4)"
check "run w30 at 30 s" "$(eval_call w30 30s)" "$(call 5)"
check "the summary over the five studies" "reliability -runs $RUNS -windows $WINS -out-dir $RES/reliability" "$(call 6)"
check "the stage is ok" "ok 0" "$(state_of reliability)"
check "the exit codes of the runs are recorded" "r1:3s:0 r2:3s:0 r3:3s:0 w10:10s:0 w30:30s:0" "$(sj '.stages.reliability.runs | to_entries | map("\(.key):\(.value.window):\(.value.exit_code)") | join(" ")')"
check "the output checksum counts the five studies, the summary and the exit code table" "7" "$(sj '.stages.reliability.outputs.files')"

case_run reliability no 'cd "$SRC_DIR"; stage_reliability'
check "images absent: they are pulled first, in dataset order" "pull $TOP10_A" "$(call 1)"
check "images absent: the second pull" "pull $TOP10_B" "$(call 2)"
check "images absent: four pulls, five evals, one summary" 10 "$(ncalls)"
check "images absent: the first eval follows the pulls" "$(eval_call r1 3s)" "$(call 5)"
check "images absent: the stage is ok" "ok 0" "$(state_of reliability)"

case_run reliability no 'cd "$SRC_DIR"; stage_reliability' 'FAKE_PULL_FAIL=1'
check "a pull fails: the stage fails" "failed 1" "$(state_of reliability)"
check "a pull fails: no eval was started" 0 "$(grep -c 'con-unit eval' "$CALLS")"

case_run reliability no 'cd "$SRC_DIR"; '"$STORE_BOTH"'; stage_reliability' 'RESUME=1'
check "resume goes to every eval" 5 "$(grep -c -- '--resume' "$CALLS")"

case_run reliability no 'cd "$SRC_DIR"; '"$STORE_BOTH"'; stage_reliability' 'FAKE_RC_con_unit_r2=3'
check "a repeat exits 3: the stage is incomplete" "incomplete 3" "$(state_of reliability)"
check "a repeat exits 3: the summary is still computed" 6 "$(ncalls)"
check "a repeat exits 3: the exit code is recorded" "3" "$(sj '.stages.reliability.runs.r2.exit_code')"

case_run reliability no 'cd "$SRC_DIR"; '"$STORE_BOTH"'; stage_reliability' 'FAKE_RC_con_unit_w10=1'
check "a run fails and leaves no study: the stage fails" "failed 1" "$(state_of reliability)"
check "a run fails and leaves no study: no summary is computed" 5 "$(ncalls)"
check "a run fails and leaves no study: the exit code is recorded" "1" "$(sj '.stages.reliability.runs.w10.exit_code')"

case_run reliability no 'cd "$SRC_DIR"; '"$STORE_BOTH"'; stage_reliability' 'FAKE_RC_reliability=2'
check "the summary fails: the stage fails with its code" "failed 2" "$(state_of reliability)"
case_run reliability no 'cd "$SRC_DIR"; '"$STORE_BOTH"'; rm bin/reliability; stage_reliability'
check "binary missing: the stage fails early with 127" "failed 127" "$(state_of reliability)"
check "binary missing: no eval was started" 0 "$(ncalls)"
case_run reliability no 'cd "$SRC_DIR"; '"$STORE_BOTH"'; stage_reliability' 'PROBE_WINDOW=7s'
check "the windows of the repeats do not follow --probe-window" "3s 3s 3s 10s 30s" "$(grep -o -- '--probe-window [0-9a-z]*' "$CALLS" | awk '{print $2}' | paste -sd' ' -)"

echo "== exit codes of the stages end in the right state"
rc_table() { # stage function requested tools key setup
    local stage=$1 fn=$2 req=$3 tools=$4 key=$5 setup=$6 row rc state code
    for row in "0 ok 0" "3 incomplete 3" "1 failed 1" "2 failed 2"; do
        read -r rc state code <<< "$row"
        case_run "$req" "$tools" "cd \"\$SRC_DIR\"; $setup; $fn" "$key=$rc"
        check "$stage: exit code $rc ends $state" "$state $code" "$(state_of "$stage")"
    done
}
rc_table rq1 stage_rq1 rq1 yes FAKE_RC_rq1 true
rc_table lint stage_lint lint no FAKE_RC_con_unit_lint true
rc_table crosscheck stage_crosscheck crosscheck yes FAKE_RC_crosscheck "$LINT_STUDY"
rc_table ablate stage_ablate ablate no FAKE_RC_attribute_exec_ablation "$STUDY"
rc_table attribute stage_attribute attribute no FAKE_RC_attribute_exec "$STUDY; $SEED_ALL"
rc_table reliability stage_reliability reliability no FAKE_RC_reliability "$STORE_BOTH"

echo "== combining the exit codes of one stage"
rc_pair() { check "combine_rc $1 $2" "$3" "$(run_in_harness "combine_rc $1 $2")"; }
rc_pair 0 0 0
rc_pair 0 3 3
rc_pair 3 0 3
rc_pair 3 3 3
rc_pair 1 3 1
rc_pair 3 2 2
rc_pair 0 66 66
rc_pair 127 0 127
rc_pair 2 1 2

echo "== the checksum of a stage output"
sha_stdin() { if command -v sha256sum > /dev/null; then sha256sum | awk '{print $1}'; else shasum -a 256 | awk '{print $1}'; fi; }
write_fixtures
mkdir -p "$RES/out/sub" "$RES/empty"
printf 'one\n' > "$RES/out/b.json"
printf 'two\n' > "$RES/out/sub/a.json"
OUT=$(CASE_STAGES=eval CASE_TOOLS=no run_in_harness ". '$WORK/pre.sh'; stage_begin probe; stage_outputs probe out; stage_end probe ok 0; stage_begin e; stage_outputs e empty; stage_end e ok 0; stage_begin m; stage_outputs m does-not-exist; stage_end m ok 0; finalize" 2>&1)
listing() { (cd "$RES" && for f in out/b.json out/sub/a.json; do printf '%s  %s\n' "$(sha "$f")" "$f"; done); }
check "the file count" 2 "$(sj '.stages.probe.outputs.files')"
check "the digest is the sha256 of the sorted listing" "$(listing | sha_stdin)" "$(sj '.stages.probe.outputs.listing_sha256')"
check "the directory is recorded" "out" "$(sj '.stages.probe.outputs.dir')"
check "an empty directory has no files" 0 "$(sj '.stages.e.outputs.files')"
check "an empty directory has the digest of nothing" "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" "$(sj '.stages.e.outputs.listing_sha256')"
check "a missing directory counts like an empty one" "0 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" "$(sj '.stages.m.outputs | "\(.files) \(.listing_sha256)"')"
check "the files of a stage are in the bundle checksums" "1 1" "$(grep -c ' ./out/b.json$' "$RES/REMOTE_SHA256SUMS") $(grep -c ' ./out/sub/a.json$' "$RES/REMOTE_SHA256SUMS")"
check "the bundle checksums verify" 0 "$(cd "$RES" && { sha256sum -c REMOTE_SHA256SUMS > /dev/null 2>&1 || shasum -a 256 -c REMOTE_SHA256SUMS > /dev/null 2>&1; }; echo $?)"

echo "== the canary subsets"
canary_case() { # description stages canary expected-top10-lines (empty: no file)
    case_run "$2" no 'cd "$SRC_DIR"; derive_datasets; echo "top10=$([ -f "$SRC_DIR/fixtures/evaluation_dataset_top10_canary.txt" ] && grep -c . "$SRC_DIR/fixtures/evaluation_dataset_top10_canary.txt" || echo none)"; echo "rel=$RELIABILITY_DATASET_PATH"' "CANARY=$3"
    check "$1" "$4" "$(printf '%s\n' "$OUT" | grep -o '^top10=.*' | head -n 1)"
}
canary_case "reliability alone in a canary of 3 gets a 3 image subset" reliability 3 "top10=3"
canary_case "rq3 alone in a canary of 3 gets the same subset" rq3 3 "top10=3"
canary_case "no stage that reads the 10 image dataset: no subset file" eval,export 3 "top10=none"
canary_case "a canary of 2 takes two images" reliability,rq3 2 "top10=2"
canary_case "a canary larger than the dataset takes all four" reliability 99 "top10=4"
case_run reliability no 'derive_datasets; echo "rel=$RELIABILITY_DATASET_PATH"' 'CANARY=3'
check "the reliability dataset in a canary is the subset" "rel=fixtures/evaluation_dataset_top10_canary.txt" "$(printf '%s\n' "$OUT" | grep -o '^rel=.*')"
check "the subset is recorded in the status file" "3" "$(sj '.reliability_dataset_used.entries')"
case_run reliability no 'derive_datasets; echo "rel=$RELIABILITY_DATASET_PATH"'
check "a full run uses the whole 10 image dataset" "rel=fixtures/evaluation_dataset_top10_pinned.txt" "$(printf '%s\n' "$OUT" | grep -o '^rel=.*')"
check "a full run records all of its images" "4" "$(sj '.reliability_dataset_used.entries')"
case_run eval,export no 'derive_datasets'
check "without rq3 and reliability the 10 image dataset is not recorded" "null" "$(sj '.rq3_dataset_used')"
check "without reliability no reliability dataset is recorded" "null" "$(sj '.reliability_dataset_used')"

echo "== the run block names the tool versions of the requested stages"
LOCK_REAL="$HERE/../tools.lock"
pin() { awk -v n="$1" '$1 == n { print $2 }' "$LOCK_REAL"; }
tools_json() { # dockle hadolint trivy cst
    jq -cn --arg d "$1" --arg h "$2" --arg t "$3" --arg c "$4" '{dockle: $d, hadolint: $h, trivy: $t, "container-structure-test": $c} | with_entries(select(.value != "<none>"))'
}
D=$(pin dockle); H=$(pin hadolint); T=$(pin trivy); C=$(pin container-structure-test)
block_case() { # description stages tools-json expected-output
    write_fixtures
    cp "$LOCK_REAL" "$WORK/base/incoming/tools.lock"
    jq -n --argjson t "$3" '{run: {tools: $t}}' > "$WORK/study.json"
    OUT=$(run_in_harness "STAGES='$2'; run_block_missing_tools '$WORK/study.json'" 2>&1)
    check "$1" "$4" "$OUT"
}
block_case "all four tools at the pinned versions" rq1 "$(tools_json "$D" "$H" "$T" "$C")" ""
block_case "a v prefix on a version is ignored" rq1 "$(tools_json "$D" "$H" "$T" "v$C")" ""
block_case "a tool that is absent" rq1 "$(tools_json "$D" absent "$T" "$C")" "tools.hadolint(absent,pinned:$H) "
block_case "a tool of unknown version" rq1 "$(tools_json "$D" "$H" "present (version unknown)" "$C")" "tools.trivy(present (version unknown),pinned:$T) "
block_case "a tool of another version" rq1 "$(tools_json "0.4.14" "$H" "$T" "$C")" "tools.dockle(0.4.14,pinned:$D) "
block_case "a tool that is not in the run block at all" rq1 "$(tools_json "$D" "$H" "$T" "<none>")" "tools.container-structure-test "
block_case "no tools object at all" rq1 "null" "tools.dockle tools.hadolint tools.trivy tools.container-structure-test "
block_case "crosscheck needs only dockle" crosscheck "$(tools_json "$D" "<none>" "<none>" "<none>")" ""
block_case "crosscheck with another dockle" crosscheck "$(tools_json "9.9.9" "<none>" "<none>" "<none>")" "tools.dockle(9.9.9,pinned:$D) "
block_case "run B stages need no tool version" eval,export,attribute,ablate,reliability "null" ""

study_block() { # tools-json -> empirical_study.json with a complete run block
    jq -n --argjson t "$1" '{run: {engine_name: "podman", engine_version: "4.9.3", rootless: false, cgroup_version: "v2", storage_driver: "overlay", oci_runtime: "crun", virtualization: "kvm", execution_mode: "rootful", instance_type: "c6i.2xlarge", ami_id: "ami-0123456789abcdef0", commit: "abcdef1", registry_remap: "docker.io/library -> public.ecr.aws/docker/library", tools: $t}}'
}
block_stage() { # description stages tools-json expected-state
    write_fixtures
    cp "$LOCK_REAL" "$WORK/base/incoming/tools.lock"
    OUT=$(CASE_STAGES="$2" CASE_TOOLS=no run_in_harness ". '$WORK/pre.sh'; study_json='$(study_block "$3")'; printf '%s' \"\$study_json\" > \"\$RESULTS_DIR/empirical_study.json\"; stage_run_block" 2>&1)
    check "$1" "$4" "$(state_of run_block_check)"
}
block_stage "the run block check passes with the pinned tools" "eval,rq1" "$(tools_json "$D" "$H" "$T" "$C")" "ok 0"
block_stage "the run block check fails when a tool of a requested stage is absent" "eval,rq1" "$(tools_json "$D" absent "$T" "$C")" "failed 1"
block_stage "the run block check ignores tools that no requested stage needs" "eval,export" "$(tools_json absent absent absent absent)" "ok 0"
block_stage "the run block check fails on a tool of another version" "eval,crosscheck" "$(tools_json "0.4.14" "<none>" "<none>" "<none>")" "failed 1"

finish
