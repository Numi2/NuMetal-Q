# NuMetalQ Benchmark Report

- Status: completed
- Generated: 2026-04-11T01:03:08Z
- Last updated: 2026-04-11T01:04:25Z
- Completed: 2026-04-11T01:04:25Z
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
| auth-policy-sparse | completed | 1/1 iters, 1/1 samples | pcd-auth | multi-factor authorization policy | 64 | 256 | 3 | 576 | 0.0116 | 1 | 1106444288 | apple9 | 8192 | 3845 | 4143 | verified | 246252 | 10513 | 257084 | 98.767 / 98.767 | 90.289 / 90.289 | n/a | 46443.640 / 46443.640 | 2380.291 / 2380.291 | 2939.838 / 2939.838 | n/a | matched | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-parity/benchmark-dispatch-trace.json |  | guard=256 source<=1 derived<=4347 | witnessExceedsPiDECRepresentability(maxMagnitude: 194167, base: 2, limbs: 13) |

## Verifier Stages

| Workload | Stage | State | Progress | Peak RSS | GPU | CPU Verify p50/p95 | Assisted Verify p50/p95 | Assisted GPU p50/p95 | Dispatches | Counter State | GPU Timing | Fallback | Trace | Note |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- |
| piccs-verify | piCCS | completed | 1/1 iters, 1/1 samples | 1106493440 | apple9 | 0.186 / 0.186 | 9.162 / 9.162 | 0.011 / 0.011 | 1 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-parity/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |
| pirlc-verify | piRLC | completed | 1/1 iters, 1/1 samples | 1172193280 | apple9 | 54.672 / 54.672 | 1816.713 / 1816.713 | 24.169 / 24.169 | 4 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-parity/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |
| pidec-verify | piDEC | completed | 1/1 iters, 1/1 samples | 1219657728 | apple9 | 49.050 / 49.050 | 2091.645 / 2091.645 | 23.886 / 23.886 | 3 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline | /Users/home/NuMetal-Q/artifacts/apple-silicon-validation/bench-parity/benchmark-dispatch-trace.json | Metal-assisted verifier uses the recursive-stage GPU recomputation path. |

## Verifier Dispatch Summary

| Workload | Stage | Dispatch | Kernel | Samples | CPU p50/p95 | GPU p50/p95 | Exec Widths | TG Widths | Counter State | GPU Timing | Fallback |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- |
| piccs-verify | piCCS | piCCS.matrix_lift[0] | nu_matrix_lift | 1 | 8.792 / 8.792 | 0.011 / 0.011 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.cross_term_commit_batch | nu_sparse_rot_commit_batch | 1 | 27.694 / 27.694 | 24.041 / 24.041 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.cross_terms | nu_ring_mul_ag64_d64 | 1 | 0.616 / 0.616 | 0.069 / 0.069 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.fold_commitment | nu_ring_bind_fold_batch | 1 | 0.288 / 0.288 | 0.029 / 0.029 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pirlc-verify | piRLC | piRLC.fold_witness | nu_ring_bind_fold_batch | 1 | 0.271 / 0.271 | 0.030 / 0.030 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.decompose | nu_pidec_decompose | 1 | 0.648 / 0.648 | 0.006 / 0.006 | 32 | 256 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.limb_commit_batch | nu_sparse_rot_commit_batch | 1 | 27.435 / 27.435 | 23.704 / 23.704 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
| pidec-verify | piDEC | piDEC.reconstruct_commitment | nu_ring_bind_fold_batch | 1 | 0.462 / 0.462 | 0.177 / 0.177 | 32 | 64 | unsupported | command-buffer-timeline | dispatch-boundary counters unsupported on this host; used command-buffer timeline |
