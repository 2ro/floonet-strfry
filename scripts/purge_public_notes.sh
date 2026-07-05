#!/usr/bin/env bash
#
# purge_public_notes.sh - remove already-stored public notes (kinds 1 and
# 30023) that were NOT written by an authorized author, so enabling the
# public-note lockdown also cleans up what slipped in before it.
#
# It runs entirely through `docker exec` against a running strfry container
# and NEVER restarts, stops, or recreates anything.
#
# What it does:
#   1. `strfry scan '{"kinds":[1,30023]}'`   (all stored public notes)
#   2. filter OUT events whose pubkey is in the keep-list (jq)
#   3. collect the ids of everything that remains
#   4. delete them in chunks via `strfry delete --filter '{"ids":[...]}'`
#
# Default mode is a DRY RUN: it only prints counts and deletes nothing. Pass
# --execute to actually delete.
#
# Usage:
#   ./purge_public_notes.sh --container <name> --keep <hexpubkey>[,<hexpubkey>...]
#                           [--keep-file <path>] [--chunk N] [--execute]
#
#   --container   the strfry container name (required)
#   --keep        comma-separated hex pubkeys to PRESERVE (the authorized
#                 authors). npubs are NOT accepted here; convert first.
#   --keep-file   optional file with one hex pubkey per line (# comments ok),
#                 merged with --keep
#   --chunk       ids per delete call (default 500)
#   --execute     actually delete (otherwise dry run)
#
# NOTE on reclaiming space: deletes mark records free but do not shrink the
# LMDB file. `strfry compact` reclaims fragmentation, but it REQUIRES stopping
# strfry first, which is out of scope for this script (we never stop anything).
# Run compaction separately during a maintenance window if you need the space:
#     docker stop <name>; docker run ... strfry compact data.mdb.bak; docker start <name>
#
set -euo pipefail

CONTAINER=""
KEEP_CSV=""
KEEP_FILE=""
CHUNK=500
EXECUTE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --container) CONTAINER="$2"; shift 2 ;;
        --keep)      KEEP_CSV="$2"; shift 2 ;;
        --keep-file) KEEP_FILE="$2"; shift 2 ;;
        --chunk)     CHUNK="$2"; shift 2 ;;
        --execute)   EXECUTE=1; shift ;;
        --dry-run)   EXECUTE=0; shift ;;
        -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$CONTAINER" ] || { echo "error: --container is required" >&2; exit 2; }

# Build the keep-list (one hex pubkey per line) from --keep and --keep-file.
KEEP_LIST="$(mktemp)"
RAW_FILE="$(mktemp)"
IDS_FILE="$(mktemp)"
CHUNKS_FILE="$(mktemp)"
trap 'rm -f "$KEEP_LIST" "$RAW_FILE" "$IDS_FILE" "$CHUNKS_FILE" 2>/dev/null || true' EXIT
if [ -n "$KEEP_CSV" ]; then
    printf '%s\n' "$KEEP_CSV" | tr ',' '\n'
fi >> "$KEEP_LIST"
if [ -n "$KEEP_FILE" ]; then
    grep -v '^[[:space:]]*#' "$KEEP_FILE" 2>/dev/null || true
fi >> "$KEEP_LIST"
# Normalise: trim, lowercase, drop blanks, keep only 64-char hex, de-dup.
KEEP_CLEAN="$(mktemp)"
tr 'A-Z' 'a-z' < "$KEEP_LIST" | tr -d ' \t\r' \
    | grep -E '^[0-9a-f]{64}$' | sort -u > "$KEEP_CLEAN" || true
mv "$KEEP_CLEAN" "$KEEP_LIST"
KEEP_COUNT="$(wc -l < "$KEEP_LIST" | tr -d ' ')"

echo "container:  $CONTAINER"
echo "keep-list:  $KEEP_COUNT authorized pubkey(s)"
echo "mode:       $([ "$EXECUTE" -eq 1 ] && echo EXECUTE || echo 'DRY RUN (no deletes)')"

# jq program: emit the .id of every scanned event whose .pubkey is not in the
# keep-list. The keep-list is passed as a newline string and split into a set.
JQ_PROG='($keep | split("\n") | map(select(length>0))) as $k
         | select((.pubkey // "") as $p | ($k | index($p)) | not)
         | .id'

# Scan once into a file, then derive both counts from it (no second scan).
docker exec -i "$CONTAINER" strfry scan '{"kinds":[1,30023]}' > "$RAW_FILE" || true
jq -r --arg keep "$(cat "$KEEP_LIST")" "$JQ_PROG" < "$RAW_FILE" \
    | grep -E '^[0-9a-f]{64}$' | sort -u > "$IDS_FILE" || true

TOTAL_SCANNED="$(grep -c . "$RAW_FILE" || echo 0)"
TO_DELETE="$(wc -l < "$IDS_FILE" | tr -d ' ')"
echo "stored public notes (kinds 1,30023): $TOTAL_SCANNED"
echo "to delete (not from an authorized author): $TO_DELETE"

if [ "$TO_DELETE" -eq 0 ]; then
    echo "nothing to delete."
    exit 0
fi

if [ "$EXECUTE" -ne 1 ]; then
    echo "dry run: pass --execute to delete these $TO_DELETE event(s)."
    exit 0
fi

# Delete in chunks so the ids filter stays a sane size. Each chunk is one
# compact JSON object per line: {"ids":[...]}.
jq -R -s -c --argjson chunk "$CHUNK" '
    split("\n") | map(select(length>0))
    | [range(0; length; $chunk) as $i | .[$i:$i+$chunk]]
    | .[] | {ids: .}
' "$IDS_FILE" > "$CHUNKS_FILE"

deleted=0
while IFS= read -r chunk_json; do
    [ -n "$chunk_json" ] || continue
    docker exec -i "$CONTAINER" strfry delete --filter "$chunk_json"
    n="$(printf '%s' "$chunk_json" | jq '.ids | length')"
    deleted=$((deleted + n))
    echo "deleted chunk of $n (running total $deleted / $TO_DELETE)"
done < "$CHUNKS_FILE"

echo "done: deleted $deleted event(s). (Space is not reclaimed until a"
echo "separate 'strfry compact' during a maintenance window; see header.)"
