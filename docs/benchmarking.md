# Benchmarking Guide

`NuMetalQBenchmarks` is the package's executable benchmark runner for seal workflows and verifier stages.

## Quick Start

```bash
swift run NuMetalQBenchmarks
swift run NuMetalQBenchmarks --iterations 1 --warmups 0
swift run NuMetalQBenchmarks --list-workloads
swift run NuMetalQBenchmarks --seal-workload auth-policy-sparse
```

By default the runner writes artifacts under `artifacts/benchmarks/<timestamp>/`.

## Artifacts

Each benchmark run emits:

- `benchmark-report.json`: structured report with metadata, workload status, and timing summaries
- `benchmark-report.md`: human-readable markdown summary
- `benchmark-dispatch-trace.json`: per-dispatch trace data plus a run-level GPU observability rollup
- `comparison-template.json`: schema template for tracking benchmark deltas across runs
- `review-bundle.json`: pointers to the benchmark output and supporting protocol references

## Workload Selection

Use the suite-specific selectors to narrow a run:

- `--seal-workload NAME`
- `--verifier-workload NAME`

Each selector can be repeated or given a comma-separated list.

## Interpreting Results

- CPU timing columns are the host-side medians and p95 values.
- Metal timing columns are the end-to-end assisted timings and GPU timings derived from either dispatch-boundary counters or command-buffer timelines.
- Verification parity fields capture whether CPU-only and Metal-assisted verification agree.
- Counter capture status is reported explicitly as `unsupported`, `available-but-not-captured`, or `captured`.
- GPU trace artifacts and dispatch-boundary counters are separate observability tiers:
  - trace artifacts are emitted for Metal-assisted runs,
  - dispatch-boundary counters are only used when the host supports them and the samples resolve successfully,
  - unsupported or unresolved hosts fall back to command-buffer timeline timing and report the fallback reason.
- Pending or running statuses in the markdown report indicate an in-progress run; the report is updated incrementally.
