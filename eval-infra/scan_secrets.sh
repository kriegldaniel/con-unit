#!/usr/bin/env bash
# Scan for credentials and personal identifiers before anything is committed, pushed or shared.
#
#   scan_secrets.sh [--identifiers] --repo DIR     files git would add: tracked, plus untracked
#                                                  and not ignored
#   scan_secrets.sh [--identifiers] PATH...        files or directories, for example results/<RUN_ID>
#
# Findings print as a label and file:line. The matched text is never printed, so a hit does not
# copy the secret into a terminal scrollback, a CI log or a chat transcript.
#
# What counts as a finding
#   always:        private key blocks, AWS access key ids, AWS secret or session token assignments,
#                  GitHub and Slack tokens, macOS home directories (/Users/<name>/)
#   --identifiers: values that identify the operator but are not credentials, discovered at run
#                  time and held in memory only: AWS account id and IAM user name of the current
#                  session, and the current public IPv4 address
#
# Exit codes: 0 clean, 1 findings, 2 usage error.
set -euo pipefail

usage() {
    sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

IDENTIFIERS=0
REPO=''
PATHS=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --identifiers) IDENTIFIERS=1; shift ;;
        --repo) REPO=${2:?--repo needs a directory}; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        --) shift; PATHS+=("$@"); break ;;
        -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) PATHS+=("$1"); shift ;;
    esac
done
if [ -z "$REPO" ] && [ "${#PATHS[@]}" -eq 0 ]; then
    echo "usage error: give --repo DIR or at least one PATH" >&2
    exit 2
fi

if [ -t 1 ]; then
    RED=$'\033[31;1m'
    GRN=$'\033[32;1m'
    RST=$'\033[0m'
else
    RED=''
    GRN=''
    RST=''
fi

# ------------------------------------------------------------------ collect the files to scan
files=()
strip=''
if [ -n "$REPO" ]; then
    [ -d "$REPO" ] || { echo "usage error: not a directory: $REPO" >&2; exit 2; }
    git -C "$REPO" rev-parse --is-inside-work-tree > /dev/null 2>&1 || { echo "usage error: not a git work tree: $REPO" >&2; exit 2; }
    root=$(git -C "$REPO" rev-parse --show-toplevel)
    strip="$root/"
    while IFS= read -r -d '' f; do
        if [ -f "$root/$f" ]; then
            files+=("$root/$f")
        fi
    done < <(git -C "$root" ls-files -z --cached --others --exclude-standard)
fi
for p in "${PATHS[@]+"${PATHS[@]}"}"; do
    [ -e "$p" ] || { echo "usage error: no such path: $p" >&2; exit 2; }
    while IFS= read -r -d '' f; do
        files+=("$f")
    done < <(find "$p" -type f -not -path '*/.git/*' -print0)
done

# ------------------------------------------------------------------ patterns
# label|extended regular expression. The first pipe splits, so labels must not contain one.
# None of the expressions matches its own text, so this file scans clean.
PATTERNS=(
    "private key block|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    "AWS access key id|(^|[^A-Za-z0-9])(AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}([^A-Za-z0-9]|$)"
    "AWS secret or session token assignment|(aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_session_token|AWS_SESSION_TOKEN)[[:space:]]*[=:]"
    "GitHub or Slack token|(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,})"
    "macOS home directory|/Users/[A-Za-z0-9._-]+/"
)

# label|literal value. Filled only with --identifiers.
LITERALS=()
if [ "$IDENTIFIERS" = 1 ]; then
    acct=''
    arn=''
    if command -v aws > /dev/null 2>&1; then
        read -r acct arn < <(aws sts get-caller-identity --query '[Account,Arn]' --output text 2> /dev/null || true) || true
    fi
    if [[ "$acct" =~ ^[0-9]{12}$ ]]; then
        LITERALS+=("AWS account id|$acct")
    fi
    if [[ "$arn" == */* ]] && [ -n "${arn##*/}" ]; then
        LITERALS+=("AWS principal name|${arn##*/}")
    fi
    ip=''
    if command -v curl > /dev/null 2>&1; then
        ip=$(curl -4 -fsS --max-time 8 https://checkip.amazonaws.com 2> /dev/null | tr -d '[:space:]') || ip=''
    fi
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        LITERALS+=("operator public IPv4 address|$ip")
    fi
    if [ "${#LITERALS[@]}" -eq 0 ]; then
        echo "warning: --identifiers found no AWS session and no public address, only the fixed patterns are checked" >&2
    fi
fi

# ------------------------------------------------------------------ scan
FINDINGS=0
scan() { # label grep-mode needle
    local label=$1 mode=$2 needle=$3 hit
    [ "${#files[@]}" -gt 0 ] || return 0
    while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        FINDINGS=$((FINDINGS + 1))
        printf '  %sFINDING%s  %-40s %s\n' "$RED" "$RST" "$label" "${hit#"$strip"}"
    done < <(grep -HIn"$mode" -e "$needle" -- "${files[@]}" 2> /dev/null | cut -d: -f1,2)
}

printf 'Scanning %d files' "${#files[@]}"
[ -z "$REPO" ] || printf ' of %s' "$strip"
printf '\n'

for entry in "${PATTERNS[@]}"; do
    scan "${entry%%|*}" E "${entry#*|}"
done
for entry in "${LITERALS[@]+"${LITERALS[@]}"}"; do
    scan "${entry%%|*}" Fw "${entry#*|}"
done

if [ "$FINDINGS" -eq 0 ]; then
    printf '%sCLEAN%s  no findings\n' "$GRN" "$RST"
    exit 0
fi
printf '%s%d FINDINGS%s  do not commit, push or share until each one is resolved or accepted\n' "$RED" "$FINDINGS" "$RST"
exit 1
