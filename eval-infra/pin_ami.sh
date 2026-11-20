#!/usr/bin/env bash
# Pin the Ubuntu 24.04 LTS AMI used by the evaluation for one region.
#
#   pin_ami.sh <region>          resolve the newest Canonical AMI and record it in amis.json
#   pin_ami.sh <region> --show   print the newest candidate and the current pin, change nothing
#
# This is the only place where an AMI is looked up by "newest". Evaluation runs always use the
# pinned id from amis.json, so every run of a release starts from the same image. Re-pin only
# between releases and commit the changed amis.json.
#
# Needs AWS credentials with ec2:DescribeImages, plus aws and jq.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CATALOG="$SCRIPT_DIR/amis.json"
export AWS_PAGER=""

REGION="${1:-}"
SHOW_ONLY=0
[ "${2:-}" = "--show" ] && SHOW_ONLY=1
[[ "$REGION" =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]] || {
    echo "usage: pin_ami.sh <region> [--show]   (for example eu-central-1)" >&2
    exit 2
}
command -v aws > /dev/null || { echo "aws CLI not found (enter the dev shell: direnv allow)" >&2; exit 1; }
command -v jq > /dev/null || { echo "jq not found" >&2; exit 1; }

owner="$(jq -r .owner "$CATALOG")"
pattern="$(jq -r .name_pattern "$CATALOG")"

echo "[INFO] looking up the newest $pattern in $REGION (owner $owner)"
candidate="$(aws ec2 describe-images --region "$REGION" --owners "$owner" \
    --filters "Name=name,Values=$pattern" "Name=state,Values=available" "Name=architecture,Values=x86_64" "Name=virtualization-type,Values=hvm" \
    --query 'sort_by(Images, &CreationDate)[-1].{ami_id: ImageId, name: Name, creation_date: CreationDate}' --output json)"
[ "$(jq -r '.ami_id // empty' <<< "$candidate")" != "" ] || {
    echo "[ERROR] no matching AMI found in $REGION" >&2
    exit 1
}

echo "[INFO] newest candidate:"
jq . <<< "$candidate"
echo "[INFO] current pin for $REGION:"
jq --arg r "$REGION" '.pins[$r] // "none"' "$CATALOG"

if [ "$SHOW_ONLY" = 1 ]; then
    exit 0
fi

tmp="$(mktemp "$SCRIPT_DIR/.amis.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
jq --arg r "$REGION" --argjson c "$candidate" --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '.pins[$r] = ($c + {pinned_at: $t})' "$CATALOG" > "$tmp"
mv "$tmp" "$CATALOG"
trap - EXIT
echo "[SUCCESS] pinned $(jq -r --arg r "$REGION" '.pins[$r].ami_id' "$CATALOG") for $REGION in eval-infra/amis.json. Review and commit it."
