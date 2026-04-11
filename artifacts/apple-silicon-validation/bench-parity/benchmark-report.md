# NuMetalQ Benchmark Report

- Status: completed
- Generated: 2026-04-10T23:52:17Z
- Last updated: 2026-04-10T23:54:52Z
- Completed: 2026-04-10T23:54:52Z
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
| auth-policy-sparse | completed | 1/1 iters, 1/1 samples | pcd-auth | multi-factor authorization policy | 64 | 256 | 3 | 576 | 0.0116 | 1 | 911360000 | apple9 | 8192 | 3845 | 4143 | verified | 246252 | 10513 | 257084 | 153.450 / 153.450 | 156.490 / 156.490 | n/a | 87274.240 / 87274.240 | 4854.895 / 4854.895 | 4797.764 / 4797.764 | n/a | matched | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-parity/benchmark-dispatch-trace.json |  | guard=256 source<=1 derived<=4347 | witnessExceedsPiDECRepresentability(maxMagnitude: 194167, base: 2, limbs: 13) |

## Verifier Stages

| Workload | Stage | State | Progress | Peak RSS | GPU | CPU Verify p50/p95 | Assisted Verify p50/p95 | Assisted GPU p50/p95 | Dispatches | Counter State | GPU Timing | Fallback | Trace | Note |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- |
| piccs-verify | piCCS | completed | 1/1 iters, 1/1 samples | 911360000 | apple9 | 0.293 / 0.293 | 14.829 / 14.829 | 0.011 / 0.011 | 1 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-parity/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |
| pirlc-verify | piRLC | completed | 1/1 iters, 1/1 samples | 911360000 | apple9 | 106.431 / 106.431 | 4132.681 / 4132.681 | 33.942 / 33.942 | 4 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-parity/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |
| pidec-verify | piDEC | completed | 1/1 iters, 1/1 samples | 911360000 | apple9 | 129.836 / 129.836 | 5581.161 / 5581.161 | 49.001 / 49.001 | 3 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-parity/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |

## Verifier Dispatch Summary

| Workload | Stage | Dispatch | Kernel | Samples | CPU p50/p95 | GPU p50/p95 | Exec Widths | TG Widths | Counter State | GPU Timing | Fallback |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- |
| piccs-verify | piCCS | piCCS.matrix_lift[0] | nu_matrix_lift | 1 | 13.956 / 13.956 | 0.011 / 0.011 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.cross_term_commit_batch | nu_sparse_rot_commit_batch | 1 | 42.023 / 42.023 | 33.782 / 33.782 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.cross_terms | nu_ring_mul_ag64_d64 | 1 | 0.319 / 0.319 | 0.066 / 0.066 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.fold_commitment | nu_ring_bind_fold_batch | 1 | 0.623 / 0.623 | 0.046 / 0.046 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.fold_witness | nu_ring_bind_fold_batch | 1 | 0.600 / 0.600 | 0.048 / 0.048 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.decompose | nu_pidec_decompose | 1 | 0.585 / 0.585 | 0.012 / 0.012 | 32 | 256 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.limb_commit_batch | nu_sparse_rot_commit_batch | 1 | 59.793 / 59.793 | 47.974 / 47.974 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.reconstruct_commitment | nu_ring_bind_fold_batch | 1 | 1.659 / 1.659 | 1.014 / 1.014 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
