# NuMetalQ Benchmark Report

- Generated: 2026-04-07T14:39:50Z
- Host: T’s MacBook Air
- OS: Version 26.3 (Build 25D5087f)
- CPU cores: 10
- Memory bytes: 25769803776
- Iterations: 1
- Warmups: 0

## Seal Workflow

| Workload | Witness | Rows | Matrices | GPU | Proof Bytes | Envelope Bytes | Seed-1 ms | Seed-2 ms | Fuse ms | Seal ms | Verify ms |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| wallet-small | 64 | 64 | 1 | apple9 | 1337922 | 1338158 | 0.731 | 0.601 | 18.725 | 74.518 | 102.171 |
| wallet-medium | 256 | 256 | 2 | apple9 | 3132225 | 3132461 | 2.502 | 2.338 | 72.264 | 957.020 | 218.867 |
| wallet-large | 1024 | 1024 | 4 | apple9 | 7492778 | 7493014 | 9.254 | 9.370 | 1220.392 | 27975.130 | 509.776 |

## Lightning PCS

| Workload | Vars | Evals | CPU Commit ms | CPU Open ms | Metal Commit ms | Metal Open ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| pcs-8 | 8 | 256 | 29.184 | 2.597 | 73.785 | 17.006 |
| pcs-10 | 10 | 1024 | 413.077 | 9.550 | 16.465 | 40.394 |
| pcs-12 | 12 | 4096 | 6412.729 | 36.584 | 66.437 | 110.854 |
