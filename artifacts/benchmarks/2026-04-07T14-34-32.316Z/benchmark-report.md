# NuMetalQ Benchmark Report

- Generated: 2026-04-07T14:34:32Z
- Host: T’s MacBook Air
- OS: Version 26.3 (Build 25D5087f)
- CPU cores: 10
- Memory bytes: 25769803776
- Iterations: 1
- Warmups: 0

## Seal Workflow

| Workload | Witness | Rows | Matrices | GPU | Proof Bytes | Envelope Bytes | Seed-1 ms | Seed-2 ms | Fuse ms | Seal ms | Verify ms |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| wallet-small | 64 | 64 | 1 | apple9 | 1333246 | 1333482 | 0.689 | 0.583 | 18.249 | 74.438 | 104.240 |
| wallet-medium | 256 | 256 | 2 | apple9 | 3130052 | 3130288 | 2.346 | 2.281 | 72.281 | 957.106 | 217.872 |
| wallet-large | 1024 | 1024 | 4 | apple9 | 7488670 | 7488906 | 9.557 | 9.266 | 1224.076 | 28064.871 | 510.730 |

## Lightning PCS

| Workload | Vars | Evals | CPU Commit ms | CPU Open ms | Metal Commit ms | Metal Open ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| pcs-8 | 8 | 256 | 29.025 | 2.578 | 144.415 | 14.195 |
| pcs-10 | 10 | 1024 | 412.272 | 9.352 | 17.442 | 40.880 |
| pcs-12 | 12 | 4096 | 6410.126 | 35.748 | 71.892 | 110.201 |
