#!/bin/sh
# Reads one regression sample of the lint tests from a public registry.
#
#   fetch_sample.sh <registry host> <repository> <tag> <output file> <token url | none>
#
# It resolves <tag> to the linux/amd64 platform manifest, reads the image
# config blob and keeps only what the lint checks need: the config values
# (User, Env, Volumes, Healthcheck, Entrypoint, Cmd, WorkingDir) and, for every
# history entry, the command text and the empty-layer flag. Timestamps, authors,
# comments and layer data are dropped. The digests of the index or manifest, of
# the platform manifest and of the config are written into the output, so the
# sample can be traced to one exact image. The tests never run this script and
# never use the network. It needs curl and jq.
#
# The committed samples were read like this (anonymous pull tokens):
#   fetch_sample.sh registry-1.docker.io library/alpine 3.20 official-alpine.json \
#     'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull'
#   the same for library/debian bookworm-slim, library/python 3.12-slim,
#   library/nginx stable, library/postgres 17, library/ubuntu 24.04, and
#   fetch_sample.sh gcr.io distroless/static-debian12 nonroot official-distroless.json \
#     'https://gcr.io/v2/token?scope=repository:distroless/static-debian12:pull'
# A tag moves, so a new run can give other content. The digests in the files
# stay the reference.
host="$1"; repo="$2"; tag="$3"; out="$4"; tokenurl="$5"

auth=""
if [ "$tokenurl" != "none" ]; then
  token=$(curl -sSf "$tokenurl" | jq -r '.token // .access_token')
  auth="Authorization: Bearer $token"
fi
accept='Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

get() { curl -sSfL -H "$accept" ${auth:+-H "$auth"} "$@"; }

index_headers=$(mktemp)
index=$(curl -sSfL -D "$index_headers" -H "$accept" ${auth:+-H "$auth"} "https://$host/v2/$repo/manifests/$tag")
top_digest=$(grep -i '^docker-content-digest:' "$index_headers" | tr -d '\r' | awk '{print $2}')
rm -f "$index_headers"

mediatype=$(printf '%s' "$index" | jq -r '.mediaType // empty')
case "$mediatype" in
  *index*|*manifest.list*)
    digest=$(printf '%s' "$index" | jq -r '.manifests[] | select(.platform.os=="linux" and .platform.architecture=="amd64") | .digest' | head -n 1)
    manifest=$(get "https://$host/v2/$repo/manifests/$digest")
    ;;
  *)
    digest="$top_digest"
    manifest="$index"
    ;;
esac
config_digest=$(printf '%s' "$manifest" | jq -r '.config.digest')
config=$(get "https://$host/v2/$repo/blobs/$config_digest")

printf '%s' "$config" | jq --arg host "$host" --arg repo "$repo" --arg tag "$tag" --arg top "$top_digest" --arg manifest "$digest" --arg cfg "$config_digest" '{
  source: {registry: $host, repository: $repo, tag_at_fetch: $tag, index_or_manifest_digest: $top, platform_manifest_digest: $manifest, config_digest: $cfg},
  platform: (.os + "/" + .architecture),
  config: {
    User: (.config.User // ""),
    Env: (.config.Env // []),
    Volumes: (.config.Volumes // null),
    Healthcheck: (.config.Healthcheck // null),
    Entrypoint: (.config.Entrypoint // null),
    Cmd: (.config.Cmd // null),
    WorkingDir: (.config.WorkingDir // "")
  },
  history: [ .history[] | {created_by: (.created_by // ""), empty_layer: (.empty_layer // false)} ]
}' > "$out"
echo "wrote $out ($(wc -c < "$out") bytes, $(jq '.history | length' "$out") history entries)"
