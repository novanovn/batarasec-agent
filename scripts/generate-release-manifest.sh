#!/usr/bin/env bash
set -euo pipefail

DIST_DIR="${DIST_DIR:-dist}"
VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"
RELEASE_VERSION="${RELEASE_VERSION:-${VERSION#v}}"
RELEASE_TAG="${RELEASE_TAG:-$VERSION}"
CHANNEL="${CHANNEL:-stable}"
RELEASE_DATE="${RELEASE_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
RELEASE_NOTES="${RELEASE_NOTES:-Agent release $RELEASE_VERSION}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-batarasec/batarasec-agent}"
BASE_URL="${BASE_URL:-https://github.com/${GITHUB_REPOSITORY}/releases/download/${RELEASE_TAG}}"
OUTPUT="${OUTPUT:-${DIST_DIR}/manifest.json}"

asset_json() {
  local os="$1"
  local arch="$2"
  local filename="$3"
  local path="${DIST_DIR}/${filename}"

  if [ ! -f "$path" ]; then
    return 0
  fi

  local hash size archive_path archive_hash archive_size
  hash=$(sha256sum "$path" | awk '{print $1}')
  size=$(wc -c < "$path" | tr -d ' ')
  archive_path="${path}.tar.gz"

  if [ -f "$archive_path" ]; then
    archive_hash=$(sha256sum "$archive_path" | awk '{print $1}')
    archive_size=$(wc -c < "$archive_path" | tr -d ' ')
    printf '{"os":"%s","arch":"%s","filename":"%s","url":"%s/%s","sha256":"%s","sizeBytes":%s,"archiveUrl":"%s/%s.tar.gz","archiveSha256":"%s","archiveSizeBytes":%s}' \
      "$os" "$arch" "$filename" "$BASE_URL" "$filename" "$hash" "$size" "$BASE_URL" "$filename" "$archive_hash" "$archive_size"
    return 0
  fi

  printf '{"os":"%s","arch":"%s","filename":"%s","url":"%s/%s","sha256":"%s","sizeBytes":%s}' \
    "$os" "$arch" "$filename" "$BASE_URL" "$filename" "$hash" "$size"
}

mkdir -p "$DIST_DIR"

assets=()
for item in \
  "linux amd64 batarasec-agent_linux_amd64" \
  "linux arm64 batarasec-agent_linux_arm64" \
  "windows amd64 batarasec-agent_windows_amd64.exe"; do
  read -r os arch filename <<< "$item"
  json=$(asset_json "$os" "$arch" "$filename")
  if [ -n "$json" ]; then
    assets+=("$json")
  fi
done

if [ "${#assets[@]}" -eq 0 ]; then
  echo "No release assets found in ${DIST_DIR}" >&2
  exit 1
fi

assets_json=$(IFS=,; printf '%s' "${assets[*]}")
python3 - "$OUTPUT" "$RELEASE_VERSION" "$RELEASE_DATE" "$CHANNEL" "$RELEASE_NOTES" "$assets_json" <<'PY'
import json
import sys
from pathlib import Path

output, version, release_date, channel, release_notes, assets_json = sys.argv[1:]
manifest = {
    "githubReleases": [
        {
            "version": version,
            "releaseDate": release_date,
            "channel": channel,
            "releaseNotes": release_notes,
            "assets": json.loads(f"[{assets_json}]"),
        }
    ]
}
Path(output).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY

echo "Wrote ${OUTPUT}"
