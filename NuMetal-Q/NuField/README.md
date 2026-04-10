# NuField

Core algebra, transcripts, parameter derivation, and profile metadata.

## Responsibilities

- `Fq`, `Fq2`, `Fq4`, and negacyclic ring arithmetic
- transcript and challenge sampling
- canonical profile search metadata and parameter expansion
- rotation-matrix helpers used by the Metal commitment path

## Main Types

- `Fq`
- `Fq2`
- `Fq4`
- `RingElement`
- `NuTranscriptField`
- `NuSealCShake256`
- `NuProfile`
- `NuParams`

## Test Coverage

- transcript vectors in `TranscriptVectorTests`
- packing/parity and algebra checks in `CryptoHardeningTests`

## Current Gaps

- the seal transcript path and XOF bridge deserve more explicit failure-path tests
