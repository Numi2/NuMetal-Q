# NuMetalQ Benchmark Report

- Status: completed
- Generated: 2026-04-11T01:00:14Z
- Last updated: 2026-04-11T01:03:07Z
- Completed: 2026-04-11T01:03:07Z
- Host: T’s MacBook Air
- OS: Version 26.3 (Build 25D5087f)
- CPU cores: 10
- Memory bytes: 25769803776
- Iterations: 1
- Warmups: 0

## GPU Observability

- GPU: apple9 (Apple M4)
- Counter sampling: unsupported
- Counter state: unsupported
- Captured dispatches: 0/8 (0.0000)
- Timing sources: command-buffer-timeline=8
- Fallbacks: dispatch-boundary counters unsupported on this host; used command-buffer timeline

## Seal Workflow

| Workload | State | Progress | Family | Scenario | Rows | Witness | Matrices | NNZ | Density | Gate Deg | Peak RSS | GPU | Norm Ceiling | Headroom | Preflight Max | Repr | Public Proof Bytes | Resume Artifact Bytes | Total Export Bytes | Seed-1 p50/p95 | Seed-2 p50/p95 | Fuse p50/p95 | Seal p50/p95 | CPU Verify p50/p95 | Assisted Verify p50/p95 | Assisted GPU p50/p95 | Parity | Trace | Verify Note | Repr Note | Fuse Note |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| auth-policy-sparse | completed | 1/1 iters, 1/1 samples | pcd-auth | multi-factor authorization policy | 64 | 256 | 3 | 576 | 0.0116 | 1 | 1106149376 | apple9 | 8192 | 3845 | 4143 | verified | 246252 | 10513 | 257084 | 97.846 / 97.846 | 88.903 / 88.903 | n/a | 45500.200 / 45500.200 | 2401.663 / 2401.663 | 2900.678 / 2900.678 | n/a | matched | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-smoke/benchmark-dispatch-trace.json |  | guard=256 source<=1 derived<=4347 | witnessExceedsPiDECRepresentability(maxMagnitude: 194167, base: 2, limbs: 13) |
| rollup-settlement-dense | completed | 1/1 iters, 1/1 samples | pcd-rollup | batched settlement aggregation | 64 | 320 | 3 | 1856 | 0.0300 | 1 | 1879228416 | apple9 | 8192 | 425 | 6355 | verified | 258592 | 11043 | 269954 | 239.512 / 239.512 | 208.465 / 208.465 | n/a | 71709.068 / 71709.068 | 2680.366 / 2680.366 | 3508.228 / 3508.228 | n/a | matched | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-smoke/benchmark-dispatch-trace.json |  | guard=256 source<=3 derived<=7767 | witnessExceedsPiDECRepresentability(maxMagnitude: 257411, base: 2, limbs: 13) |

## Verifier Stages

| Workload | Stage | State | Progress | Peak RSS | GPU | CPU Verify p50/p95 | Assisted Verify p50/p95 | Assisted GPU p50/p95 | Dispatches | Counter State | GPU Timing | Fallback | Trace | Note |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- |
| piccs-verify | piCCS | completed | 1/1 iters, 1/1 samples | 1879228416 | apple9 | 0.190 / 0.190 | 104.552 / 104.552 | 0.012 / 0.012 | 1 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-smoke/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |
| pirlc-verify | piRLC | completed | 1/1 iters, 1/1 samples | 1879228416 | apple9 | 55.110 / 55.110 | 1783.758 / 1783.758 | 23.755 / 23.755 | 4 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-smoke/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |
| pidec-verify | piDEC | completed | 1/1 iters, 1/1 samples | 1879228416 | apple9 | 49.258 / 49.258 | 2057.324 / 2057.324 | 27.460 / 27.460 | 3 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-smoke/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |

## Verifier Dispatch Summary

| Workload | Stage | Dispatch | Kernel | Samples | CPU p50/p95 | GPU p50/p95 | Exec Widths | TG Widths | Counter State | GPU Timing | Fallback |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- |
| piccs-verify | piCCS | piCCS.matrix_lift[0] | nu_matrix_lift | 1 | 104.124 / 104.124 | 0.012 / 0.012 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.cross_term_commit_batch | nu_sparse_rot_commit_batch | 1 | 27.958 / 27.958 | 23.612 / 23.612 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.cross_terms | nu_ring_mul_ag64_d64 | 1 | 0.755 / 0.755 | 0.081 / 0.081 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.fold_commitment | nu_ring_bind_fold_batch | 1 | 0.260 / 0.260 | 0.032 / 0.032 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.fold_witness | nu_ring_bind_fold_batch | 1 | 0.274 / 0.274 | 0.030 / 0.030 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.decompose | nu_pidec_decompose | 1 | 0.547 / 0.547 | 0.004 / 0.004 | 32 | 256 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.limb_commit_batch | nu_sparse_rot_commit_batch | 1 | 33.367 / 33.367 | 27.280 / 27.280 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.reconstruct_commitment | nu_ring_bind_fold_batch | 1 | 0.408 / 0.408 | 0.176 / 0.176 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
