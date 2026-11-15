#!/usr/bin/env bash
# check_mirror.sh: verify that every digest-pinned entry of a dataset file
# resolves on the AWS ECR Public mirror of Docker Official Images with the
# same digest.
#
# Usage:
#   tools/check_mirror.sh <dataset-file>
#
# For each entry name@sha256:<digest> the script sends
#   HEAD $MIRROR_BASE/v2/docker/library/<name>/manifests/<digest>
# with an anonymous bearer token and the four manifest Accept headers, then
# compares the Docker-Content-Digest header with the pinned digest. A digest
# identifies content, so a matching digest means the mirror serves the same
# bytes as Docker Hub.
#
# Unauthenticated requests are throttled to about one per second and answer
# HTTP 429 above that. Requests are therefore spaced by MIRROR_DELAY and HTTP
# 429 is retried with exponential backoff.
#
# Environment:
#   OUT_DIR           directory that receives mirror_check.json (default: .)
#   MIRROR_DELAY      seconds between requests (default: 1.1)
#   MIRROR_BASE       registry base URL (default: https://public.ecr.aws)
#   TOKEN_URL         anonymous token endpoint (default: https://public.ecr.aws/token/)
#   MIRROR_NAMESPACE  repository path prefix on the mirror (default: docker/library)
#   MIRROR_RETRIES    retries after HTTP 429 per entry (default: 5)
#   MIRROR_BACKOFF    first backoff in seconds, doubled per retry (default: 2)
#   MIRROR_TIMEOUT    curl timeout per request in seconds (default: 20)
#
# Exit status: 0 when every entry is found with a matching digest, 1 when any
# entry is missing, differs, is throttled or errors, 2 on usage errors or when
# no token can be obtained.

set -u
set -o pipefail

MIRROR_BASE="${MIRROR_BASE:-https://public.ecr.aws}"
TOKEN_URL="${TOKEN_URL:-https://public.ecr.aws/token/}"
MIRROR_NAMESPACE="${MIRROR_NAMESPACE:-docker/library}"
MIRROR_DELAY="${MIRROR_DELAY:-1.1}"
MIRROR_RETRIES="${MIRROR_RETRIES:-5}"
MIRROR_BACKOFF="${MIRROR_BACKOFF:-2}"
MIRROR_TIMEOUT="${MIRROR_TIMEOUT:-20}"
OUT_DIR="${OUT_DIR:-.}"

ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

# ---------------------------------------------------------------------------
# Output helpers: fixed-width tags, colored only on a terminal.

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[1;31m'; C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'; C_CYAN=$'\033[1;36m'
else
    C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''
fi

log()  { printf '%s[%-7s]%s %s\n' "$C_CYAN" "INFO" "$C_RESET" "$*"; }
ok()   { printf '%s[%-7s]%s %s\n' "$C_GREEN" "SUCCESS" "$C_RESET" "$*"; }
warn() { printf '%s[%-7s]%s %s\n' "$C_YELLOW" "WARNING" "$C_RESET" "$*" >&2; }
err()  { printf '%s[%-7s]%s %s\n' "$C_RED" "ERROR" "$C_RESET" "$*" >&2; }

usage() {
    sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//' >&2
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

double() { awk -v d="$1" 'BEGIN { print d * 2 }'; }

# ---------------------------------------------------------------------------
# Arguments

if [ "$#" -ne 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    [ "$#" -eq 1 ] && exit 0
    exit 2
fi
DATASET="$1"
if [ ! -f "$DATASET" ]; then
    err "dataset file not found: $DATASET"
    exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
    err "curl is required"
    exit 2
fi
mkdir -p "$OUT_DIR" || { err "cannot create OUT_DIR $OUT_DIR"; exit 2; }

# ---------------------------------------------------------------------------
# Token

TOKEN=""
fetch_token() {
    local attempt=0 backoff="$MIRROR_BACKOFF" body
    while :; do
        if body="$(curl -sS -f --max-time "$MIRROR_TIMEOUT" "$TOKEN_URL" 2>/dev/null)"; then
            break
        fi
        attempt=$((attempt + 1))
        if [ "$attempt" -gt "$MIRROR_RETRIES" ]; then
            return 1
        fi
        sleep "$backoff"
        backoff="$(double "$backoff")"
    done
    TOKEN="$(printf '%s' "$body" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    [ -n "$TOKEN" ]
}

# ---------------------------------------------------------------------------
# One manifest HEAD request. Sets HTTP_CODE and RETURNED_DIGEST.

HTTP_CODE=0
RETURNED_DIGEST=""
head_manifest() {
    local repo="$1" digest="$2" url headers rc
    url="$MIRROR_BASE/v2/$MIRROR_NAMESPACE/$repo/manifests/$digest"
    headers="$(curl -sS -I --max-time "$MIRROR_TIMEOUT" \
        -H "Authorization: Bearer $TOKEN" -H "Accept: $ACCEPT" "$url" 2>/dev/null)"
    rc=$?
    headers="$(printf '%s' "$headers" | tr -d '\r')"
    if [ "$rc" -ne 0 ] || [ -z "$headers" ]; then
        HTTP_CODE=0
        RETURNED_DIGEST=""
        return
    fi
    HTTP_CODE="$(printf '%s\n' "$headers" | sed -n 's/^HTTP\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p' | tail -n 1)"
    HTTP_CODE="${HTTP_CODE:-0}"
    RETURNED_DIGEST="$(printf '%s\n' "$headers" | grep -i '^docker-content-digest:' | head -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '[:space:]')"
}

# Classify one entry, retrying HTTP 429 with backoff and refreshing the token
# once on 401 or 403. Sets STATUS and MATCH.
STATUS=""
MATCH=false
check_one() {
    local repo="$1" digest="$2" throttled=0 backoff="$MIRROR_BACKOFF" refreshed=0
    while :; do
        head_manifest "$repo" "$digest"
        case "$HTTP_CODE" in
            200)
                if [ "$RETURNED_DIGEST" = "$digest" ]; then
                    STATUS=OK; MATCH=true
                else
                    STATUS=MISMATCH; MATCH=false
                fi
                return ;;
            404)
                STATUS=MISSING; MATCH=false
                return ;;
            401|403)
                if [ "$refreshed" -eq 0 ]; then
                    refreshed=1
                    if fetch_token; then continue; fi
                fi
                STATUS=ERROR; MATCH=false
                return ;;
            429)
                throttled=$((throttled + 1))
                if [ "$throttled" -gt "$MIRROR_RETRIES" ]; then
                    STATUS=THROTTLED; MATCH=false
                    return
                fi
                warn "HTTP 429 for $repo, retry $throttled of $MIRROR_RETRIES after ${backoff}s"
                sleep "$backoff"
                backoff="$(double "$backoff")"
                continue ;;
            *)
                STATUS=ERROR; MATCH=false
                return ;;
        esac
    done
}

# Split name@sha256:<64 hex> into REPO and DIGEST. Only Docker Official Images
# (the library namespace) exist on the mirror path.
REPO=""
DIGEST=""
parse_ref() {
    local ref="$1" name hex
    REPO=""; DIGEST=""
    case "$ref" in *@sha256:*) ;; *) return 1 ;; esac
    hex="${ref##*@sha256:}"
    printf '%s' "$hex" | grep -Eq '^[0-9a-f]{64}$' || return 1
    DIGEST="sha256:$hex"
    name="${ref%@*}"
    case "$name" in
        library/*) REPO="${name#library/}" ;;
        */library/*) REPO="${name##*/library/}" ;;
        */*) return 1 ;;
        *) REPO="$name" ;;
    esac
    case "$REPO" in ""|*/*) return 1 ;; esac
    return 0
}

# ---------------------------------------------------------------------------
# Run

refs=()
while IFS= read -r line || [ -n "$line" ]; do
    line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    case "$line" in ""|"#"*) continue ;; esac
    refs+=("$line")
done < "$DATASET"

total="${#refs[@]}"
if [ "$total" -eq 0 ]; then
    err "no entries in $DATASET"
    exit 2
fi

log "dataset  $DATASET ($total entries)"
log "mirror   $MIRROR_BASE/v2/$MIRROR_NAMESPACE, delay ${MIRROR_DELAY}s between requests"
if ! fetch_token; then
    err "could not obtain an anonymous token from $TOKEN_URL"
    exit 2
fi

entries_file="$(mktemp "${TMPDIR:-/tmp}/mirror_entries.XXXXXX")"
trap 'rm -f "$entries_file"' EXIT

n_ok=0; n_missing=0; n_mismatch=0; n_throttled=0; n_error=0; n_invalid=0
index=0
for ref in "${refs[@]}"; do
    index=$((index + 1))
    if [ "$index" -gt 1 ]; then
        sleep "$MIRROR_DELAY"
    fi
    if parse_ref "$ref"; then
        check_one "$REPO" "$DIGEST"
        returned="$RETURNED_DIGEST"
        code="$HTTP_CODE"
    else
        STATUS=INVALID_REF; MATCH=false; returned=""; code=0
        REPO=""; DIGEST=""
    fi
    case "$STATUS" in
        OK) n_ok=$((n_ok + 1)) ;;
        MISSING) n_missing=$((n_missing + 1)) ;;
        MISMATCH) n_mismatch=$((n_mismatch + 1)) ;;
        THROTTLED) n_throttled=$((n_throttled + 1)) ;;
        INVALID_REF) n_invalid=$((n_invalid + 1)) ;;
        *) n_error=$((n_error + 1)) ;;
    esac
    printf '%s[%3d/%3d]%s %-11s http %-3s %s\n' "$C_CYAN" "$index" "$total" "$C_RESET" "$STATUS" "$code" "$ref"
    [ "$STATUS" = "OK" ] || err "$STATUS: $ref (http $code, returned digest: ${returned:-none})"
    if [ "$index" -gt 1 ]; then printf ',\n' >> "$entries_file"; fi
    printf '    {"ref": "%s", "repository": "%s", "digest": "%s", "status": "%s", "http_status": %s, "digest_match": %s, "returned_digest": "%s"}' \
        "$(json_escape "$ref")" "$(json_escape "$REPO")" "$(json_escape "$DIGEST")" "$STATUS" "$code" "$MATCH" "$(json_escape "$returned")" >> "$entries_file"
done

out="$OUT_DIR/mirror_check.json"
tmp_out="$out.tmp.$$"
{
    printf '{\n'
    printf '  "schema_version": "1",\n'
    printf '  "checked_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "mirror": "%s",\n' "$(json_escape "$MIRROR_BASE")"
    printf '  "namespace": "%s",\n' "$(json_escape "$MIRROR_NAMESPACE")"
    printf '  "request_delay_seconds": %s,\n' "$MIRROR_DELAY"
    printf '  "dataset": "%s",\n' "$(json_escape "$DATASET")"
    printf '  "dataset_sha256": "%s",\n' "$(sha256_of "$DATASET")"
    printf '  "entries": [\n'
    cat "$entries_file"
    printf '\n  ],\n'
    printf '  "summary": {"total": %d, "ok": %d, "missing": %d, "digest_mismatch": %d, "throttled": %d, "error": %d, "invalid_ref": %d}\n' \
        "$total" "$n_ok" "$n_missing" "$n_mismatch" "$n_throttled" "$n_error" "$n_invalid"
    printf '}\n'
} > "$tmp_out" && mv "$tmp_out" "$out"

log "result   $out"
if [ "$n_ok" -eq "$total" ]; then
    ok "all $total pinned digests resolve on the mirror with matching digests"
    exit 0
fi
err "$((total - n_ok)) of $total entries failed: missing $n_missing, digest mismatch $n_mismatch, throttled $n_throttled, error $n_error, invalid $n_invalid"
exit 1
