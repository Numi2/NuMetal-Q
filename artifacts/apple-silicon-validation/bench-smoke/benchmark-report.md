# NuMetalQ Benchmark Report

- Status: completed
- Generated: 2026-04-10T23:48:37Z
- Last updated: 2026-04-10T23:52:16Z
- Completed: 2026-04-10T23:52:16Z
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
| auth-policy-sparse | completed | 1/1 iters, 1/1 samples | pcd-auth | multi-factor authorization policy | 64 | 256 | 3 | 576 | 0.0116 | 1 | 1107607552 | apple9 | 8192 | 3845 | 4143 | verified | 246252 | 10513 | 257084 | 130.299 / 130.299 | 90.455 / 90.455 | n/a | 48009.411 / 48009.411 | 2460.309 / 2460.309 | 3007.247 / 3007.247 | n/a | matched | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-smoke/benchmark-dispatch-trace.json |  | guard=256 source<=1 derived<=4347 | witnessExceedsPiDECRepresentability(maxMagnitude: 194167, base: 2, limbs: 13) |
| rollup-settlement-dense | completed | 1/1 iters, 1/1 samples | pcd-rollup | batched settlement aggregation | 64 | 320 | 3 | 1856 | 0.0300 | 1 | 1621606400 | apple9 | 8192 | 425 | 6355 | verified | 258592 | 11043 | 269954 | 240.733 / 240.733 | 242.936 / 242.936 | n/a | 93852.779 / 93852.779 | 4924.898 / 4924.898 | 5020.696 / 5020.696 | n/a | matched | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-smoke/benchmark-dispatch-trace.json |  | guard=256 source<=3 derived<=7767 | witnessExceedsPiDECRepresentability(maxMagnitude: 257411, base: 2, limbs: 13) |

## Verifier Stages

| Workload | Stage | State | Progress | Peak RSS | GPU | CPU Verify p50/p95 | Assisted Verify p50/p95 | Assisted GPU p50/p95 | Dispatches | Counter State | GPU Timing | Fallback | Trace | Note |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- |
| piccs-verify | piCCS | completed | 1/1 iters, 1/1 samples | 1621606400 | apple9 | 0.265 / 0.265 | 12.681 / 12.681 | 0.011 / 0.011 | 1 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-smoke/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |
| pirlc-verify | piRLC | completed | 1/1 iters, 1/1 samples | 1621606400 | apple9 | 77.134 / 77.134 | 3191.733 / 3191.733 | 27.940 / 27.940 | 4 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-smoke/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |
| pidec-verify | piDEC | completed | 1/1 iters, 1/1 samples | 1621606400 | apple9 | 84.116 / 84.116 | 3692.766 / 3692.766 | 26.634 / 26.634 | 3 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-smoke/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |

## Verifier Dispatch Summary

| Workload | Stage | Dispatch | Kernel | Samples | CPU p50/p95 | GPU p50/p95 | Exec Widths | TG Widths | Counter State | GPU Timing | Fallback |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- |
| piccs-verify | piCCS | piCCS.matrix_lift[0] | nu_matrix_lift | 1 | 12.185 / 12.185 | 0.011 / 0.011 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.cross_term_commit_batch | nu_sparse_rot_commit_batch | 1 | 34.677 / 34.677 | 26.552 / 26.552 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.cross_terms | nu_ring_mul_ag64_d64 | 1 | 1.786 / 1.786 | 1.329 / 1.329 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.fold_commitment | nu_ring_bind_fold_batch | 1 | 0.238 / 0.238 | 0.029 / 0.029 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.fold_witness | nu_ring_bind_fold_batch | 1 | 0.573 / 0.573 | 0.030 / 0.030 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.decompose | nu_pidec_decompose | 1 | 0.478 / 0.478 | 0.005 / 0.005 | 32 | 256 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.limb_commit_batch | nu_sparse_rot_commit_batch | 1 | 34.977 / 34.977 | 26.380 / 26.380 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.reconstruct_commitment | nu_ring_bind_fold_batch | 1 | 1.356 / 1.356 | 0.250 / 0.250 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
