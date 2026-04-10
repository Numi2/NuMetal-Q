# Benchmarking Guide

`NuMetalQBenchmarks` is the package's executable benchmark runner for seal workflows, PCS kernels, and verifier stages.

## Quick Start

```bash
swift run NuMetalQBenchmarks
swift run NuMetalQBenchmarks --iterations 1 --warmups 0
swift run NuMetalQBenchmarks --list-workloads
swift run NuMetalQBenchmarks --seal-workload auth-policy-sparse --pcs-workload pcs-8
```

By default the runner writes artifacts under `artifacts/benchmarks/<timestamp>/`.

## Artifacts

Each benchmark run emits:

- `benchmark-report.json`: structured report with metadata, workload status, and timing summaries
- `benchmark-report.md`: human-readable markdown summary
- `benchmark-dispatch-trace.json`: per-dispatch trace data for Metal-assisted runs
- `comparison-template.json`: schema template for tracking benchmark deltas across runs
- `review-bundle.json`: pointers to the benchmark output and supporting protocol references

## Workload Selection

Use the suite-specific selectors to narrow a run:

- `--seal-workload NAME`
- `--pcs-workload NAME`
- `--verifier-workload NAME`

Each selector can be repeated or given a comma-separated list.

## Interpreting Results

- CPU timing columns are the host-side medians and p95 values.
- Metal timing columns are the end-to-end assisted timings and, when available, GPU timeline samples.
- Verification parity fields capture whether CPU-only and Metal-assisted verification agree.
- Pending or running statuses in the markdown report indicate an in-progress run; the report is updated incrementally.
