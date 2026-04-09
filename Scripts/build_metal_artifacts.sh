#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHADER_DIR="$ROOT/NuMetal-Q/NuMetal/Shaders"
OUT_DIR="$ROOT/NuMetal-Q/NuMetal/Compiled"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

COMBINED_SOURCE="$TMP_DIR/NuMetalCombined.metal"
AIR_FILE="$TMP_DIR/NuMetal.air"
METALLIB_FILE="$OUT_DIR/NuMetal.metallib"
MANIFEST_FILE="$OUT_DIR/NuMetalManifest.json"

mkdir -p "$OUT_DIR"

cat \
  "$SHADER_DIR/NuAG64Common.metal" \
  "$SHADER_DIR/NuFieldKernels.metal" \
  "$SHADER_DIR/NuCommitKernels.metal" \
  "$SHADER_DIR/NuDecompKernels.metal" \
  "$SHADER_DIR/NuMatrixKernels.metal" \
  "$SHADER_DIR/NuSumCheckKernels.metal" \
  "$SHADER_DIR/NuSealKernels.metal" \
  > "$COMBINED_SOURCE"

xcrun metal -Os -c "$COMBINED_SOURCE" -o "$AIR_FILE"
xcrun metallib "$AIR_FILE" -o "$METALLIB_FILE"

cat > "$MANIFEST_FILE" <<'JSON'
{
  "version": 1,
  "storageLayoutVersion": 3,
  "shaders": [
    "NuAG64Common",
    "NuFieldKernels",
    "NuCommitKernels",
    "NuDecompKernels",
    "NuMatrixKernels",
    "NuSumCheckKernels",
    "NuSealKernels"
  ]
}
JSON

echo "Wrote:"
echo "  $METALLIB_FILE"
echo "  $MANIFEST_FILE"
