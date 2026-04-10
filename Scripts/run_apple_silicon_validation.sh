#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -m)" != "arm64" ]]; then
  echo "Apple-silicon validation requires an arm64 host." >&2
  exit 1
fi

OUT_DIR="${1:-$ROOT/artifacts/apple-silicon-validation}"
ACCEPTANCE_JSON="$OUT_DIR/acceptance-demo.json"
BENCH_SMOKE_DIR="$OUT_DIR/bench-smoke"
BENCH_PARITY_DIR="$OUT_DIR/bench-parity"

mkdir -p "$OUT_DIR"
rm -rf "$BENCH_SMOKE_DIR" "$BENCH_PARITY_DIR"

echo "Running Apple-silicon validation with outputs under:"
echo "  $OUT_DIR"

Scripts/check_repo_metadata.sh
swift test
Scripts/build_metal_artifacts.sh
swift run NuMetalQAcceptanceDemo --format json --output "$ACCEPTANCE_JSON"
swift run NuMetalQBenchmarks --iterations 1 --warmups 0 --output "$BENCH_SMOKE_DIR"
swift run NuMetalQBenchmarks \
  --iterations 1 \
  --warmups 0 \
  --seal-workload auth-policy-sparse \
  --output "$BENCH_PARITY_DIR"

echo "Apple-silicon validation complete."
echo "Artifacts:"
echo "  $ACCEPTANCE_JSON"
echo "  $BENCH_SMOKE_DIR/benchmark-report.json"
echo "  $BENCH_SMOKE_DIR/benchmark-dispatch-trace.json"
echo "  $BENCH_PARITY_DIR/benchmark-report.json"
echo "  $BENCH_PARITY_DIR/benchmark-dispatch-trace.json"
