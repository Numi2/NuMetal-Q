# NuCluster

Cluster-assisted proving between a principal device and a co-prover.

## Responsibilities

- pair devices and derive a session key
- sign and encrypt delegated work fragments
- validate replay, timestamp, and attestation constraints
- serialize fold, decompose, and seal work packets

## Main Types

- `ClusterSession`
- `ClusterWorkExecutor`
- `ClusterFoldWorkPacket`
- `ClusterDecomposeWorkPacket`
- `HachiClusterSealWorkPacket`

## Test Coverage

- packet serialization and tamper rejection in `ClusterWorkPacketTests`
- replay and stale-fragment handling in `ClusterWorkPacketTests`

## Current Gaps

- sender-side strict attestation generation is still awkward for callers because
  fragment-bound attestation payloads are created inside the session flow
