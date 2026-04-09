# NuMetalQ Benchmark Report

- Status: running
- Generated: 2026-04-07T21:59:50Z
- Last updated: 2026-04-07T21:59:50Z
- Host: T’s MacBook Air
- OS: Version 26.3 (Build 25D5087f)
- CPU cores: 10
- Memory bytes: 25769803776
- Iterations: 1
- Warmups: 0

## Seal Workflow

| Workload | State | Progress | Family | Scenario | Rows | Witness | Matrices | NNZ | Density | Gate Deg | Peak RSS | GPU | Proof Bytes | Envelope Bytes | Seed-1 p50/p95 | Seed-2 p50/p95 | Fuse p50/p95 | Seal p50/p95 | Verify p50/p95 | Fuse Note |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | --- | --- | --- | --- | --- |
| auth-policy-sparse | running | 0/1 iters, 0/1 samples | pcd-auth | multi-factor authorization policy | 64 | 256 | 3 | 576 | 0.0116 | 1 | 16334848 | apple9 | 0 | 0 | n/a | n/a | n/a | n/a | n/a |  |
| rollup-settlement-dense | pending | 0/1 iters, 0/1 samples | pcd-rollup | batched settlement aggregation | 64 | 320 | 3 | 1856 | 0.0300 | 1 | 0 | unavailable | 0 | 0 | n/a | n/a | n/a | n/a | n/a |  |

## Lightning PCS

| Workload | State | Progress | Vars | Evals | Peak RSS | CPU Commit p50/p95 | CPU Open p50/p95 | Metal Commit p50/p95 | Metal Open p50/p95 | Metal Commit GPU p50/p95 | Metal Open GPU p50/p95 |
| --- | --- | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- |
| pcs-8 | pending | 0/1 iters, 0/1 samples | 8 | 256 | 0 | n/a | n/a | n/a | n/a | n/a | n/a |
| pcs-10 | pending | 0/1 iters, 0/1 samples | 10 | 1024 | 0 | n/a | n/a | n/a | n/a | n/a | n/a |
| pcs-12 | pending | 0/1 iters, 0/1 samples | 12 | 4096 | 0 | n/a | n/a | n/a | n/a | n/a | n/a |
