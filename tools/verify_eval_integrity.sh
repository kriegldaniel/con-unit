#!/usr/bin/env bash
# verify_eval_integrity.sh: scientific integrity checks for the evaluation
# dataset, the result bundle and the generated paper artifacts. Runs offline.
#
# Usage:
#   tools/verify_eval_integrity.sh [results-dir]
#
# Dataset checks (fixtures, always run)
#   - declared N equals the actual entry count for every dataset list
#   - the pinned JSON reconciles with the candidate and pinned lists
#   - pinned entries are unique and all digest-pinned, also for the top-10 list
#   - every top-10 entry is contained in the main pinned list
#   - the dataset audit agrees with the lists, including list sha256 values
#
# Result checks (when <results-dir>/empirical_study.json exists)
#   - envelope schema_version and run block are present
#   - every attempted image has exactly one record with a known status
#   - no image has two results for the same test ID
#   - FS-06 and FS-07 failures carry non-fixture evidence paths
#   - every image of the dataset the run used has a record
#
# Generated artifact checks
#   - every generated file exists and is not empty
#   - macros_study.tex belongs to this JSON (sha256) and its counts equal an
#     independent recount of the JSON
#   - the exporter reproduces every generated file byte for byte (-check)
#   - no two tools write the same file name
#
# Finally the offline Go test suite runs.
#
# Environment:
#   FIXTURES_DIR               dataset fixtures (default: <repo>/fixtures)
#   RESULTS_DIR                result bundle (default: <repo>/results)
#   PAPER_DIR                  paper directory; generated .tex files are read from <PAPER_DIR>/results
#   STUDY_JSON                 study file (default: <RESULTS_DIR>/empirical_study.json)
#   INTEGRITY_STRICT=1         treat warnings as failures (use for the final run)
#   REQUIRE_RESULTS=1          fail when the study file is missing
#   SKIP_GO_TESTS=1            skip the Go test suite
#   INTEGRITY_SKIP_EXPORT_CHECK=1  skip the byte-for-byte exporter check
#   EXPORT_CMD                 exporter executable instead of "go run ./tools/export_latex.go"
#   INTEGRITY_EXTRA_OUTPUTS    extra "tool:file" pairs for the file ownership check
#
# Exit status: 0 when every check passes, 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="${FIXTURES_DIR:-$ROOT_DIR/fixtures}"
RESULTS_DIR="${1:-${RESULTS_DIR:-$ROOT_DIR/results}}"
PAPER_DIR="${PAPER_DIR:-}"
STRICT="${INTEGRITY_STRICT:-0}"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
fi

# ---------------------------------------------------------------------------
# Output

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[1;31m'; C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'; C_CYAN=$'\033[1;36m'; C_BOLD=$'\033[1m'
else
    C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_BOLD=''
fi

n_pass=0; n_fail=0; n_warn=0
FAILURES=()

section() { printf '\n%s== %s ==%s\n' "$C_BOLD" "$*" "$C_RESET"; }
info()    { printf '%s[INFO]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
pass()    { n_pass=$((n_pass + 1)); printf '%s[PASS]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
fail()    { n_fail=$((n_fail + 1)); FAILURES+=("$*"); printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*"; }
warn()    {
    n_warn=$((n_warn + 1))
    printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"
    if [ "$STRICT" = "1" ]; then FAILURES+=("(strict) $*"); fi
}

# ---------------------------------------------------------------------------
# Helpers

if ! command -v jq >/dev/null 2>&1; then
    printf '[FAIL] jq is required for the JSON checks\n' >&2
    exit 1
fi

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

entries_of()  { grep -v -E '^[[:space:]]*(#|$)' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
count_of()    { entries_of "$1" | wc -l | tr -d ' '; }
declared_n()  { grep -E '^[[:space:]]*#.*\(N = [0-9]+\)' "$1" | head -n 1 | sed -E 's/.*\(N = ([0-9]+)\).*/\1/'; }

# id_key SPEC-01 -> SPECZeroOne (the macro key of docs/CONTRACT.md addendum 9)
id_key() {
    printf '%s' "$1" | sed -e 's/[^A-Za-z0-9]//g' -e 's/0/Zero/g' -e 's/1/One/g' -e 's/2/Two/g' \
        -e 's/3/Three/g' -e 's/4/Four/g' -e 's/5/Five/g' -e 's/6/Six/g' -e 's/7/Seven/g' -e 's/8/Eight/g' -e 's/9/Nine/g'
}

macro_value() { sed -n "s/^\\\\newcommand{\\\\$1}{\\(.*\\)}\$/\\1/p" "$2" | head -n 1; }

abspath() { (cd "$1" 2>/dev/null && pwd); }

PINNED_REF_RE='@sha256:[a-f0-9]{64}$'

# ---------------------------------------------------------------------------
# 1. Dataset lists

section "Dataset lists ($FIXTURES_DIR)"
FULL="$FIXTURES_DIR/evaluation_dataset_full.txt"
PINNED="$FIXTURES_DIR/evaluation_dataset_pinned.txt"
PINNED_JSON="$FIXTURES_DIR/evaluation_dataset_pinned.json"
TOP10="$FIXTURES_DIR/evaluation_dataset_top10.txt"
TOP10_PINNED="$FIXTURES_DIR/evaluation_dataset_top10_pinned.txt"
AUDIT="$FIXTURES_DIR/evaluation_dataset_audit.json"

if [ ! -f "$FULL" ]; then
    fail "missing candidate list $FULL"
fi

for list in "$FULL" "$PINNED" "$TOP10" "$TOP10_PINNED"; do
    [ -f "$list" ] || continue
    name="$(basename "$list")"
    declared="$(declared_n "$list")"
    actual="$(count_of "$list")"
    if [ -z "$declared" ]; then
        if [ "$list" = "$TOP10" ]; then
            info "$name declares no N; its entry count is checked separately"
        else
            warn "$name has no declared N in its header (actual entries: $actual)"
        fi
    elif [ "$declared" != "$actual" ]; then
        fail "$name: declared N = $declared but $actual entries"
    else
        pass "$name: declared N = $declared equals the $actual entries"
    fi
done

if [ -f "$TOP10" ]; then
    n_top="$(count_of "$TOP10")"
    if [ "$n_top" -eq 10 ]; then pass "top-10 candidate list has exactly 10 entries"; else fail "top-10 candidate list has $n_top entries instead of 10"; fi
fi

for list in "$PINNED" "$TOP10_PINNED"; do
    [ -f "$list" ] || continue
    name="$(basename "$list")"
    dup="$(entries_of "$list" | sort | uniq -d)"
    if [ -n "$dup" ]; then fail "$name has duplicate entries: $(printf '%s' "$dup" | tr '\n' ' ')"; else pass "$name entries are unique"; fi
    bad=0
    while IFS= read -r entry; do
        if ! printf '%s' "$entry" | grep -Eq "$PINNED_REF_RE"; then
            fail "$name entry is not an immutable sha256 reference: $entry"
            bad=1
        fi
    done < <(entries_of "$list")
    [ "$bad" -eq 0 ] && pass "$name: every entry is digest-pinned"
done

if [ -f "$PINNED" ] && [ -f "$TOP10_PINNED" ]; then
    missing="$(entries_of "$TOP10_PINNED" | sort -u | comm -23 - <(entries_of "$PINNED" | sort -u))"
    if [ -n "$missing" ]; then
        fail "top-10 entries missing from the main pinned list: $(printf '%s' "$missing" | tr '\n' ' ')"
    else
        pass "every top-10 pinned entry is contained in the main pinned list"
    fi
    if [ -f "$TOP10" ] && [ "$(count_of "$TOP10_PINNED")" != "$(count_of "$TOP10")" ]; then
        fail "top-10 pinned list has $(count_of "$TOP10_PINNED") entries for $(count_of "$TOP10") candidates"
    fi
fi

if [ -f "$PINNED_JSON" ] && [ -f "$FULL" ] && [ -f "$PINNED" ]; then
    if ! jq -e 'type == "array"' "$PINNED_JSON" >/dev/null 2>&1; then
        fail "$(basename "$PINNED_JSON") is not a JSON array"
    else
        total="$(jq 'length' "$PINNED_JSON")"
        npinned="$(jq '[.[] | select(.status == "PINNED")] | length' "$PINNED_JSON")"
        if [ "$total" -eq "$(count_of "$FULL")" ]; then pass "pinned JSON records ($total) equal the candidates"; else fail "pinned JSON has $total records for $(count_of "$FULL") candidates"; fi
        if [ "$npinned" -eq "$(count_of "$PINNED")" ]; then pass "pinned JSON PINNED records ($npinned) equal the pinned list"; else fail "pinned JSON has $npinned PINNED records, pinned list has $(count_of "$PINNED") entries"; fi
        if diff <(jq -r '.[] | select(.status == "PINNED") | .immutable_ref' "$PINNED_JSON" | sort) <(entries_of "$PINNED" | sort) >/dev/null; then
            pass "pinned JSON references equal the pinned list"
        else
            fail "pinned JSON references differ from the pinned list"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 2. Dataset audit

section "Dataset audit"
if [ ! -f "$AUDIT" ]; then
    warn "no dataset audit at $AUDIT (run tools/pin_dataset)"
elif ! jq -e 'type == "object"' "$AUDIT" >/dev/null 2>&1; then
    fail "dataset audit is not a JSON object"
else
    audit_ok=1
    audit_expect() { # description, actual, expected
        if [ "$2" != "$3" ]; then fail "audit: $1 is $2, expected $3"; audit_ok=0; fi
    }
    audit_expect "schema_version" "$(jq -r '.schema_version' "$AUDIT")" "1"
    [ -f "$FULL" ] && audit_expect "candidates" "$(jq -r '.counts.candidates' "$AUDIT")" "$(count_of "$FULL")"
    [ -f "$FULL" ] && audit_expect "input sha256" "$(jq -r '.input.sha256' "$AUDIT")" "$(sha256_of "$FULL")"
    [ -f "$PINNED" ] && audit_expect "pinned" "$(jq -r '.counts.pinned' "$AUDIT")" "$(count_of "$PINNED")"
    [ -f "$PINNED" ] && audit_expect "pinned list sha256" "$(jq -r '.outputs.pinned_txt.sha256' "$AUDIT")" "$(sha256_of "$PINNED")"
    [ -f "$PINNED_JSON" ] && audit_expect "pinned json sha256" "$(jq -r '.outputs.pinned_json.sha256' "$AUDIT")" "$(sha256_of "$PINNED_JSON")"
    audit_expect "counts reconcile" "$(jq -r '.counts.candidates - .counts.pinned - .counts.excluded - .counts.failed' "$AUDIT")" "0"
    audit_expect "exclusion log entries" "$(jq -r '.exclusion_log | length' "$AUDIT")" "$(jq -r '.counts.excluded + .counts.failed' "$AUDIT")"
    if [ -f "$TOP10_PINNED" ]; then
        audit_expect "top-10 pinned sha256" "$(jq -r '.outputs.top10.pinned.sha256 // ""' "$AUDIT")" "$(sha256_of "$TOP10_PINNED")"
        audit_expect "top-10 contained in the main list" "$(jq -r '.outputs.top10.all_in_main_pinned_list // false' "$AUDIT")" "true"
    fi
    [ "$audit_ok" -eq 1 ] && pass "dataset audit agrees with the lists (counts, sha256, exclusion log)"
    commit="$(jq -r '.sampling_frame.commit // ""' "$AUDIT")"
    date_f="$(jq -r '.sampling_frame.date // ""' "$AUDIT")"
    if [ -z "$commit" ] || [ "$commit" = "unrecorded" ] || [ -z "$date_f" ] || [ "$date_f" = "unrecorded" ]; then
        warn "the sampling frame (library commit and date) is not recorded in the audit"
    else
        pass "sampling frame recorded: commit $commit, $date_f"
    fi
    if [ -n "$(jq -r '.inclusion_rule // ""' "$AUDIT")" ]; then pass "inclusion rule recorded"; else fail "audit has no inclusion rule"; fi
fi

# ---------------------------------------------------------------------------
# 3. Result bundle

STUDY_JSON="${STUDY_JSON:-$RESULTS_DIR/empirical_study.json}"
if [ -n "$PAPER_DIR" ]; then
    TEX_DIR="$PAPER_DIR/results"
else
    TEX_DIR="${TEX_DIR:-$RESULTS_DIR}"
fi

# Names written by the exporter; tools/export_latex.go -list-outputs must
# print exactly these (checked by the Go tests).
EXPORT_TEX_FILES=(macros_study.tex table_rq2_prevalence.tex table_rq2_exploratory.tex table_unverified.tex
    table_attrition.tex table_strata.tex table_rq3_phases.tex fig_rq2_prevalence.tex fig_rq3_phase_breakdown.tex
    fig_rq3_memory_scaling.tex preview_paper.tex)
EXPORT_JSON_FILES=(study_stats.json)

if [ ! -f "$STUDY_JSON" ]; then
    section "Result bundle"
    if [ "${REQUIRE_RESULTS:-0}" = "1" ]; then
        fail "study file not found: $STUDY_JSON"
    else
        info "no study file at $STUDY_JSON; result and artifact checks skipped"
    fi
else
    section "Study file ($STUDY_JSON)"
    if ! jq -e . "$STUDY_JSON" >/dev/null 2>&1; then
        fail "study file is not valid JSON"
    else
        EXPECTED_SCHEMA="$(sed -n 's/^const SchemaVersion = "\(.*\)"$/\1/p' "$ROOT_DIR/pkg/spec/contract.go" 2>/dev/null | head -n 1)"
        EXPECTED_SCHEMA="${EXPECTED_SCHEMA:-2}"
        legacy=false
        if jq -e 'type == "array"' "$STUDY_JSON" >/dev/null; then
            legacy=true
            fail "study file uses the legacy array format; the run must write the envelope (schema_version $EXPECTED_SCHEMA)"
        else
            schema="$(jq -r '.schema_version // ""' "$STUDY_JSON")"
            if [ "$schema" = "$EXPECTED_SCHEMA" ]; then pass "schema_version is $schema"; else fail "schema_version is '${schema}', expected $EXPECTED_SCHEMA"; fi
            if jq -e '.run | type == "object"' "$STUDY_JSON" >/dev/null 2>&1; then
                pass "run metadata block present"
                for field in conunit_version started_at; do
                    [ -n "$(jq -r ".run.$field // \"\"" "$STUDY_JSON")" ] || fail "run.$field is missing"
                done
                for field in commit dataset_sha256 engine_name virtualization instance_type; do
                    [ -n "$(jq -r ".run.$field // \"\"" "$STUDY_JSON")" ] || warn "run.$field is empty"
                done
                if [ "$(jq -r '.run.tainted // false' "$STUDY_JSON")" = "true" ]; then
                    warn "run is tainted (dirty tree or --allow-dirty bundle)"
                fi
            else
                fail "run metadata block is missing"
            fi
            jq -e '.images | type == "array"' "$STUDY_JSON" >/dev/null 2>&1 || fail "images array is missing"
        fi

        IMAGES_EXPR='(if type == "array" then . else (.images // []) end)'
        # Exactly one record per attempted image.
        dups="$(jq -r "$IMAGES_EXPR | map(.requested_ref // .image_name) | group_by(.) | map(select(length > 1) | .[0]) | .[]" "$STUDY_JSON")"
        if [ -n "$dups" ]; then fail "images with more than one record: $(printf '%s' "$dups" | tr '\n' ' ')"; else pass "every attempted image has exactly one record"; fi
        # No duplicate test IDs per image.
        dupids="$(jq -r "$IMAGES_EXPR | .[] | select(((.results // []) | map(.test_id) | length) != ((.results // []) | map(.test_id) | unique | length)) | (.requested_ref // .image_name)" "$STUDY_JSON")"
        if [ -n "$dupids" ]; then fail "images with duplicate test IDs: $(printf '%s' "$dupids" | tr '\n' ' ')"; else pass "no image has two results for one test ID"; fi
        # Statuses.
        badstatus="$(jq -r "$IMAGES_EXPR | .[] | select((.status // \"\") as \$s | (\$s | IN(\"COMPLETED\",\"TIMEOUT\",\"UNAVAILABLE\",\"RATE_LIMITED\",\"INDEX_LIMIT\",\"EXECUTION_ERROR\",\"EXCLUDED\") | not) and (\$s != \"\" or $([ "$legacy" = true ] && echo false || echo true))) | \"\(.requested_ref // .image_name)=\(.status // \"none\")\"" "$STUDY_JSON")"
        if [ -n "$badstatus" ]; then fail "records without a valid status: $(printf '%s' "$badstatus" | tr '\n' ' ')"; else pass "every record has a known status"; fi
        noreason="$(jq -r "$IMAGES_EXPR | .[] | select((.status // \"COMPLETED\") != \"COMPLETED\" and ((.reason // \"\") == \"\")) | (.requested_ref // .image_name)" "$STUDY_JSON")"
        if [ -n "$noreason" ]; then warn "non-completed records without a reason code: $(printf '%s' "$noreason" | tr '\n' ' ')"; fi
        # Outcomes.
        badoutcome="$(jq -r "$IMAGES_EXPR | .[] | (.requested_ref // .image_name) as \$img | (.results // [])[] | select((.outcome // \"\") != \"\" and (.outcome | IN(\"PASS\",\"FAIL\",\"UNVERIFIED\") | not)) | \"\(\$img):\(.test_id)\"" "$STUDY_JSON")"
        if [ -n "$badoutcome" ]; then fail "results with an unknown outcome: $(printf '%s' "$badoutcome" | tr '\n' ' ')"; fi
        noreasonunv="$(jq -r "$IMAGES_EXPR | .[] | (.results // [])[] | select(.outcome == \"UNVERIFIED\" and ((.reason // \"\") == \"\")) | .test_id" "$STUDY_JSON" | sort -u)"
        if [ -n "$noreasonunv" ]; then warn "UNVERIFIED results without a reason code for: $(printf '%s' "$noreasonunv" | tr '\n' ' ')"; fi
        # Addendum 1: FS-06 and FS-07 fail only with non-fixture paths.
        fixfail="$(jq -r "$IMAGES_EXPR | .[] | (.requested_ref // .image_name) as \$img | (.results // [])[] | select((.test_id == \"FS-06\" or .test_id == \"FS-07\") and .outcome == \"FAIL\" and ((.evidence.paths // []) | length) == 0) | \"\(\$img):\(.test_id)\"" "$STUDY_JSON")"
        if [ -n "$fixfail" ]; then fail "FS-06 or FS-07 FAIL without non-fixture evidence paths: $(printf '%s' "$fixfail" | tr '\n' ' ')"; else pass "FS-06 and FS-07 failures carry non-fixture evidence paths"; fi
        # Completed records have results.
        noresults="$(jq -r "$IMAGES_EXPR | .[] | select(((.status // \"COMPLETED\") == \"COMPLETED\") and ((.results // []) | length) == 0) | (.requested_ref // .image_name)" "$STUDY_JSON")"
        if [ -n "$noresults" ]; then fail "COMPLETED records without results: $(printf '%s' "$noresults" | tr '\n' ' ')"; fi

        # Coverage of the dataset the run used.
        run_sha="$(jq -r '.run.dataset_sha256 // ""' "$STUDY_JSON" 2>/dev/null)"
        dataset_used=""
        if [ -n "$run_sha" ]; then
            for candidate in "$RESULTS_DIR/dataset.txt" "$PINNED" "$TOP10_PINNED" "$FIXTURES_DIR/sample_images.txt"; do
                if [ -f "$candidate" ] && [ "$(sha256_of "$candidate")" = "$run_sha" ]; then dataset_used="$candidate"; break; fi
            done
        fi
        if [ -n "$dataset_used" ]; then
            expected_refs="$(entries_of "$dataset_used" | sort -u)"
            recorded_refs="$(jq -r "$IMAGES_EXPR | .[] | (.requested_ref // .image_name)" "$STUDY_JSON" | sort -u)"
            absent="$(comm -23 <(printf '%s\n' "$expected_refs") <(printf '%s\n' "$recorded_refs"))"
            extra="$(comm -13 <(printf '%s\n' "$expected_refs") <(printf '%s\n' "$recorded_refs"))"
            if [ -n "$absent" ]; then fail "attempted images without a record: $(printf '%s' "$absent" | tr '\n' ' ')"; else pass "every image of $(basename "$dataset_used") has a record"; fi
            if [ -n "$extra" ]; then fail "records for images outside the dataset: $(printf '%s' "$extra" | tr '\n' ' ')"; fi
        else
            warn "run.dataset_sha256 does not identify a dataset list; record coverage was not checked"
        fi

        # Bundle files written by `con-unit eval`.
        for f in EMPIRICAL_SUMMARY.md ATTRITION_REPORT.md journal.jsonl; do
            if [ -s "$RESULTS_DIR/$f" ]; then pass "$f present"; else fail "missing or empty bundle file $RESULTS_DIR/$f"; fi
        done
        if [ -d "$RESULTS_DIR/logs" ] && [ -n "$(ls -A "$RESULTS_DIR/logs" 2>/dev/null)" ]; then pass "diagnostic logs present"; else fail "missing or empty diagnostic logs directory $RESULTS_DIR/logs"; fi
        if [ -f "$RESULTS_DIR/mirror_check.json" ]; then
            if jq -e '.summary.ok == .summary.total' "$RESULTS_DIR/mirror_check.json" >/dev/null 2>&1; then
                pass "mirror check: all digests resolve on the mirror"
            else
                fail "mirror_check.json reports entries that do not resolve with a matching digest"
            fi
        fi

        # -------------------------------------------------------------------
        section "Generated artifacts ($TEX_DIR)"
        for f in "${EXPORT_TEX_FILES[@]}"; do
            if [ -s "$TEX_DIR/$f" ]; then pass "$f present and not empty"; else fail "missing or empty generated file $TEX_DIR/$f"; fi
        done
        for f in "${EXPORT_JSON_FILES[@]}"; do
            if [ -s "$RESULTS_DIR/$f" ]; then pass "$f present and not empty"; else fail "missing or empty generated file $RESULTS_DIR/$f"; fi
        done

        MACROS="$TEX_DIR/macros_study.tex"
        if [ -s "$MACROS" ]; then
            # The macros must belong to this JSON.
            macro_sha="$(sed -n 's/^% Source: .* sha256 \([0-9a-f]\{64\}\)$/\1/p' "$MACROS" | head -n 1)"
            if [ "$macro_sha" = "$(sha256_of "$STUDY_JSON")" ]; then pass "macros_study.tex was generated from this study file"; else fail "macros_study.tex does not belong to this study file (source sha256 ${macro_sha:-none})"; fi
            # Letters-only, unique names.
            badnames="$(sed -n 's/^\\newcommand{\\\([^}]*\)}.*/\1/p' "$MACROS" | grep -v -E '^[A-Za-z]+$' | head -n 3)"
            if [ -n "$badnames" ]; then fail "macro names that are not letters only: $(printf '%s' "$badnames" | tr '\n' ' ')"; fi
            dupmacros="$(sed -n 's/^\\newcommand{\\\([^}]*\)}.*/\1/p' "$MACROS" | sort | uniq -d | head -n 3)"
            if [ -n "$dupmacros" ]; then fail "macros defined twice: $(printf '%s' "$dupmacros" | tr '\n' ' ')"; fi

            # Independent recount from the JSON.
            mismatch=0
            expect_macro() { # name expected
                actual="$(macro_value "$1" "$MACROS")"
                if [ -z "$actual" ]; then fail "macro \\$1 is missing"; mismatch=1
                elif [ "$actual" != "$2" ]; then fail "macro \\$1 is $actual but the JSON gives $2"; mismatch=1; fi
            }
            flow="$(jq -r --argjson legacy "$legacy" "
                def items: (if type == \"array\" then . else (.images // []) end);
                def records: reduce items[] as \$r ({}; .[(\$r.requested_ref // \$r.image_name)] = \$r) | [.[]];
                def completed: ((.status // \"\") as \$s | if \$s == \"\" then \$legacy else \$s == \"COMPLETED\" end);
                records | \"\\(length) \\([.[] | select(completed)] | length)\"" "$STUDY_JSON")"
            attempted="${flow% *}"; completed="${flow#* }"
            expect_macro ConUnitNAttempted "$attempted"
            expect_macro ConUnitNCompleted "$completed"
            expect_macro ConUnitNAttrition "$((attempted - completed))"
            if [ -f "$AUDIT" ] && jq -e '.counts' "$AUDIT" >/dev/null 2>&1; then
                if [ "$(macro_value ConUnitNCandidates "$MACROS")" != "n/a" ]; then
                    expect_macro ConUnitNCandidates "$(jq -r '.counts.candidates' "$AUDIT")"
                    expect_macro ConUnitNPinned "$(jq -r '.counts.pinned' "$AUDIT")"
                fi
            fi
            checks=0
            while read -r id p f u; do
                [ -n "$id" ] || continue
                checks=$((checks + 1))
                key="$(id_key "$id")"
                expect_macro "ConUnitPass$key" "$p"
                expect_macro "ConUnitFail$key" "$f"
                expect_macro "ConUnitVerified$key" "$((p + f))"
                expect_macro "ConUnitUnverified$key" "$u"
            done < <(jq -r --argjson legacy "$legacy" '
                def items: (if type == "array" then . else (.images // []) end);
                def records: reduce items[] as $r ({}; .[($r.requested_ref // $r.image_name)] = $r) | [.[]];
                def outcome: (.outcome // (if .passed then "PASS" else "FAIL" end));
                def completed: ((.status // "") as $s | if $s == "" then $legacy else $s == "COMPLETED" end);
                def firsts: reduce .[] as $r ({}; if has($r.test_id) then . else .[$r.test_id] = $r end) | [.[]];
                [ records[] | select(completed) | (.results // []) | firsts | .[] ]
                | group_by(.test_id)
                | map({id: .[0].test_id,
                       p: ([.[] | select(outcome == "PASS")] | length),
                       f: ([.[] | select(outcome == "FAIL")] | length),
                       u: ([.[] | select(outcome == "UNVERIFIED")] | length)})
                | .[] | "\(.id) \(.p) \(.f) \(.u)"' "$STUDY_JSON")
            if [ "$mismatch" -eq 0 ]; then pass "macros equal an independent recount of the JSON ($checks checks, flow counts)"; fi
        fi

        # No removed statistics anywhere in the generated text.
        stale="$(grep -l -i -E 'pass ?rate|fully ?compliant|ConUnitMeanPassRate|ConUnitStdDev}|tab:rq2_defect_prevalence|tab:rq3_performance' "$TEX_DIR"/*.tex 2>/dev/null | tr '\n' ' ')"
        if [ -n "$stale" ]; then fail "generated files contain removed statistics or obsolete labels: $stale"; else pass "no pass-rate statistics or obsolete labels in the generated LaTeX"; fi

        # Byte-for-byte reproduction by the exporter.
        if [ "${INTEGRITY_SKIP_EXPORT_CHECK:-0}" = "1" ]; then
            info "exporter reproduction check skipped"
        else
            abs_results="$(abspath "$RESULTS_DIR")"
            export_args=(-check -headline "$FIXTURES_DIR/headline_checks.json" -archetypes "$FIXTURES_DIR/archetypes.json" -out "$abs_results")
            [ -f "$AUDIT" ] && export_args+=(-audit "$AUDIT")
            # The pipeline exports with -pinned, so the alpine, slim and tag counts have values.
            # Without it the check would compare against n/a and report a stale file.
            [ -f "$PINNED_JSON" ] && export_args+=(-pinned "$PINNED_JSON")
            [ -n "$PAPER_DIR" ] && export_args+=(-paper-dir "$PAPER_DIR")
            export_args+=("$STUDY_JSON")
            if [ -n "${EXPORT_CMD:-}" ]; then
                export_out="$("$EXPORT_CMD" "${export_args[@]}" 2>&1)"; export_rc=$?
            elif command -v go >/dev/null 2>&1; then
                export_out="$(cd "$ROOT_DIR" && GOPROXY=off GOSUMDB=off go run ./tools/export_latex.go "${export_args[@]}" 2>&1)"; export_rc=$?
            else
                export_out=""; export_rc=-1
            fi
            if [ "$export_rc" -eq 0 ]; then
                pass "the exporter reproduces every generated file byte for byte"
            elif [ "$export_rc" -eq -1 ]; then
                warn "go is not available; exporter reproduction check skipped"
            else
                fail "generated files differ from a fresh export: $(printf '%s' "$export_out" | grep -E 'ERROR' | head -n 3 | tr '\n' ' ')"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 4. File ownership: no file name is written by two tools

section "File ownership"
OWNERS=(
    "con-unit-eval|empirical_study.json EMPIRICAL_SUMMARY.md ATTRITION_REPORT.md journal.jsonl"
    "export_latex|${EXPORT_TEX_FILES[*]} ${EXPORT_JSON_FILES[*]}"
    "benchmark_rq3|rq3_telemetry.json RQ3_PERFORMANCE.md table_rq3_trials.tex macros_rq3.tex"
    "rq1|rq1_results.json table_rq1_detection.tex"
    "check_mirror|mirror_check.json"
    "adjudication|adjudication_template.csv adjudication_summary.json"
    "agreement|agreement.json table_agreement.tex macros_agreement.tex"
    "crosscheck|crosscheck.json discordances.csv table_crosscheck.tex table_discordances.tex macros_crosscheck.tex table_coverage.tex"
    "attribute_exec|attribution.json attribution.csv ablation.json table_attribution.tex macros_attribution.tex"
    "reliability|reliability.json table_reliability.tex macros_reliability.tex"
    "pin_dataset|evaluation_dataset_pinned.txt evaluation_dataset_pinned.json evaluation_dataset_top10_pinned.txt evaluation_dataset_audit.json"
    "preview|preview.html"
)
ownership=""
for entry in "${OWNERS[@]}"; do
    tool="${entry%%|*}"
    for file in ${entry#*|}; do ownership="$ownership$tool $file"$'\n'; done
done
for pair in ${INTEGRITY_EXTRA_OUTPUTS:-}; do
    ownership="$ownership${pair%%:*} ${pair#*:}"$'\n'
done
collisions="$(printf '%s' "$ownership" | sort -u | awk '{ n[$2]++; t[$2] = t[$2] " " $1 } END { for (f in n) if (n[f] > 1) print f ":" t[f] }' | sort)"
if [ -n "$collisions" ]; then
    while IFS= read -r c; do fail "file written by more than one tool: $c"; done <<< "$collisions"
else
    pass "no file name is written by two tools"
fi
# The sources of the other tools must not mention the exporter's file names.
foreign_hits=""
for dir in tools/benchmark_rq3 tools/rq1 tools/attribute_exec tools/crosscheck tools/reliability tools/agreement cmd pkg; do
    [ -d "$ROOT_DIR/$dir" ] || continue
    for file in "${EXPORT_TEX_FILES[@]}" "${EXPORT_JSON_FILES[@]}"; do
        if grep -rlF --include='*.go' --include='*.sh' --exclude='*_test.go' "$file" "$ROOT_DIR/$dir" >/dev/null 2>&1; then
            foreign_hits="$foreign_hits $dir:$file"
        fi
    done
done
if [ -n "$foreign_hits" ]; then fail "sources of other tools mention exporter outputs:$foreign_hits"; else pass "no other tool's sources mention the exporter's output names"; fi

# ---------------------------------------------------------------------------
# 5. Go tests

section "Offline test suite"
if [ "${SKIP_GO_TESTS:-0}" = "1" ]; then
    info "Go tests skipped (SKIP_GO_TESTS=1)"
elif ! command -v go >/dev/null 2>&1; then
    warn "go is not available; the test suite was not run"
else
    if (cd "$ROOT_DIR" && GOPROXY=off GOSUMDB=off go test ./... >/dev/null 2>&1); then
        pass "offline test suite passed"
    else
        fail "offline test suite failed (run: GOPROXY=off GOSUMDB=off go test ./...)"
    fi
fi

# ---------------------------------------------------------------------------
# Summary

section "Summary"
printf '%s checks passed, %s warnings, %s failures%s\n' "$n_pass" "$n_warn" "${#FAILURES[@]}" "$([ "$STRICT" = "1" ] && echo ' (strict mode)')"
if [ "${#FAILURES[@]}" -gt 0 ]; then
    for f in "${FAILURES[@]}"; do printf '%s  - %s%s\n' "$C_RED" "$f" "$C_RESET"; done
    printf '%s[ERROR]%s evaluation integrity checks failed\n' "$C_RED" "$C_RESET" >&2
    exit 1
fi
printf '%s[SUCCESS]%s all scientific evaluation integrity guardrails passed\n' "$C_GREEN" "$C_RESET"
exit 0
