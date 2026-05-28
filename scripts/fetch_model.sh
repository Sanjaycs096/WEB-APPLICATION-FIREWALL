#!/usr/bin/env bash
set -euo pipefail

MODEL_DIR="${WAF_MODEL_PATH:-models/waf_transformer}"
MODEL_URL="${WAF_MODEL_URL:-}"

if [ -f "$MODEL_DIR/model.pt" ]; then
  echo "Model already present at $MODEL_DIR/model.pt"
  exit 0
fi

if [ -z "$MODEL_URL" ]; then
  echo "Missing model.pt and WAF_MODEL_URL is not set." >&2
  exit 1
fi

mkdir -p "$MODEL_DIR"
TMP_DIR="$(mktemp -d)"
ARCHIVE="$TMP_DIR/model.tgz"

curl -L "$MODEL_URL" -o "$ARCHIVE"
tar -xzf "$ARCHIVE" -C "$TMP_DIR"
rm -f "$ARCHIVE"

if [ -f "$TMP_DIR/model.pt" ]; then
  cp -R "$TMP_DIR/"* "$MODEL_DIR/"
elif [ -d "$TMP_DIR/waf_transformer" ]; then
  cp -R "$TMP_DIR/waf_transformer/"* "$MODEL_DIR/"
else
  echo "Archive does not contain model.pt; contents:" >&2
  ls -la "$TMP_DIR" >&2
  exit 1
fi

echo "Model downloaded to $MODEL_DIR"