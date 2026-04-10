# NuMetal

GPU resource management, typed kernel dispatch, and Metal ABI utilities.

## Responsibilities

- load and validate the bundled Metal artifact set
- manage device, heaps, arenas, and binary archives
- expose typed dispatch wrappers for prover and verifier kernels
- collect dispatch timing and trace samples

## Main Types

- `MetalContext`
- `KernelDispatcher`
- `AG64RingMetal`
- `HeapArena`
- `ProverScheduler`

## Test Coverage

- ABI/parity checks in `CryptoHardeningTests`
- benchmark runner traces in `NuMetalQBenchmarks`

## Current Gaps

- `KernelDispatch.swift` is still too large
- dispatch-boundary counter capture remains host-dependent, but benchmark artifacts now report explicit counter states and timeline fallback reasons
