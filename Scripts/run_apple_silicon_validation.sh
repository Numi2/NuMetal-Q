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

run_stage() {
  local stage="$1"
  shift
  echo "[validation] ${stage}"
  if ! "$@"; then
    echo "[validation] stage failed: ${stage}" >&2
    exit 1
  fi
}

run_stage "repo-metadata" Scripts/check_repo_metadata.sh
run_stage "swift-test" swift test
run_stage "build-metal-artifacts" Scripts/build_metal_artifacts.sh
run_stage "acceptance-demo" swift run NuMetalQAcceptanceDemo --format json --output "$ACCEPTANCE_JSON"
run_stage "bench-stress-all" swift run NuMetalQBenchmarks --iterations 1 --warmups 0 --output "$BENCH_SMOKE_DIR"
run_stage "bench-stress-auth-policy-sparse" swift run NuMetalQBenchmarks \
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
