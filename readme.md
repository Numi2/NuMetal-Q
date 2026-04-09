
# NuMeQ

Post-quantum zero-knowledge proof-carrying data engine for Apple platforms.

## Overview

NuMeQ is an Apple-only PCD engine built on SuperNeo CCS folding with the Almost Goldilocks field profile (q = 2^64 − 2^32 − 31, d = 64, ~129-bit Module-SIS security).
The frozen production line is `HACHI-AG64-K4-DNU`: SuperNeo over `Fq/Fq2` for recursive accumulation, Hachi as the compiled terminal decider `D_Nu` over the certified quartic tower `Fq4`, and application-layer signing plus transport around the exported envelope.
The public profile stays exactly on AG64:
`q = 2^64 - 2^32 - 31`, `R_q = F_q[X]/(X^64 + 1)`.
Convolution-heavy kernels scalar-extend through the certified quartic tower, then project back to `Fq` with mandatory subfield checks; the proof statement and assumption family remain in AG64.

The public API model:

1. **Seed**: Create a base-case proof from a witness and public inputs.
2. **Fuse**: Combine two proofs into one (binary fuse).
3. **Seal**: Compile the Hachi decider for the final accumulator and export it in a signed `ProofEnvelope`.
4. **Resume**: Verify a `ProofEnvelope` and rebind into a fresh recursive state.
5. **Verify**: Check an envelope's cryptographic bindings and signature.
