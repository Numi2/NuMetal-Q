# NuMetalQ Benchmark Report

- Generated: 2026-04-07T21:50:30Z
- Host: T’s MacBook Air
- OS: Version 26.3 (Build 25D5087f)
- CPU cores: 10
- Memory bytes: 25769803776
- Iterations: 9
- Warmups: 2

## Seal Workflow

| Workload | Family | Scenario | Rows | Witness | Matrices | NNZ | Density | Gate Deg | Peak RSS | GPU | Proof Bytes | Envelope Bytes | Seed-1 p50/p95 | Seed-2 p50/p95 | Fuse p50/p95 | Seal p50/p95 | Verify p50/p95 | Fuse Note |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | --- | --- | --- | --- | --- |
| auth-policy-sparse | pcd-auth | multi-factor authorization policy | 64 | 0 | 0 | 0 | 0.0000 | 0 | 413302784 | apple9 | 4421425 | 4421661 | 2.272 / 2.324 | 2.246 / 2.321 | 28.509 / 29.065 | 14388.353 / 14496.406 | 324.406 / 326.409 |  |
| rollup-settlement-dense | pcd-rollup | batched settlement aggregation | 64 | 0 | 0 | 0 | 0.0000 | 0 | 419971072 | apple9 | 4636025 | 4636261 | 3.060 / 3.830 | 3.125 / 4.111 | 36.264 / 42.598 | 42574.158 / 50764.660 | 401.931 / 443.554 |  |

## Lightning PCS

| Workload | Vars | Evals | Peak RSS | CPU Commit p50/p95 | CPU Open p50/p95 | Metal Commit p50/p95 | Metal Open p50/p95 | Metal Commit GPU p50/p95 | Metal Open GPU p50/p95 |
| --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- |
| pcs-8 | 8 | 256 | 419971072 | 33.072 / 34.433 | 2.812 / 2.996 | 5.226 / 6.530 | 16.150 / 18.516 | 0.054 / 1.265 | 1.897 / 2.497 |
| pcs-10 | 10 | 1024 | 419971072 | 486.586 / 520.286 | 10.978 / 11.848 | 17.591 / 21.418 | 37.620 / 39.132 | 0.072 / 1.029 | 1.815 / 2.371 |
| pcs-12 | 12 | 4096 | 419971072 | 7699.132 / 8083.351 | 42.466 / 44.939 | 76.864 / 84.089 | 114.048 / 118.257 | 0.157 / 0.806 | 2.517 / 3.240 |
