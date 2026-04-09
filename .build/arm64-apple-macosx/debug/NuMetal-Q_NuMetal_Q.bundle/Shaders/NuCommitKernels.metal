// NuMeQ Metal Compute Shaders — Sparse Rotation Commitment
// Ajtai commitment hot path: rotation-matrix accumulation, never NTT.

kernel void nu_sparse_rot_commit(
    device const uint* keyRotationRows [[buffer(0)]],
    device const uint* witness [[buffer(1)]],
    device uint* output [[buffer(2)]],
    constant uint32_t& keyCount [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= RING_DEGREE) {
        return;
    }

    const uint rotationPlaneLength = keyCount * RING_DEGREE * RING_DEGREE;
    const uint witnessPlaneLength = keyCount * RING_DEGREE;
    Ag64 acc = ag64_make(0u, 0u);

    for (uint ki = 0; ki < keyCount; ++ki) {
        uint rowBase = ki * RING_DEGREE * RING_DEGREE + tid * RING_DEGREE;
        uint witnessBase = ki * RING_DEGREE;
        for (uint j = 0; j < RING_DEGREE; ++j) {
            Ag64 aCoeff = ag64_load_soa(
                keyRotationRows,
                rotationPlaneLength,
                rowBase + j
            );
            Ag64 witnessValue = ag64_load_soa(
                witness,
                witnessPlaneLength,
                witnessBase + j
            );
            acc = ag64_add(acc, ag64_mul(aCoeff, witnessValue));
        }
    }

    ag64_store_soa(output, RING_DEGREE, tid, acc);
}

kernel void nu_sparse_rot_commit_batch(
    device const uint* keyRotationRows [[buffer(0)]],
    device const uint* witnessBatch [[buffer(1)]],
    device uint* outputBatch [[buffer(2)]],
    constant uint32_t& keyCount [[buffer(3)]],
    constant uint32_t& batchCount [[buffer(4)]],
    uint tid [[thread_position_in_grid]]
) {
    uint batchIndex = tid / RING_DEGREE;
    uint lane = tid % RING_DEGREE;
    if (batchIndex >= batchCount) {
        return;
    }

    const uint rotationPlaneLength = keyCount * RING_DEGREE * RING_DEGREE;
    const uint witnessCount = batchCount * keyCount * RING_DEGREE;
    const uint witnessBase = batchIndex * keyCount * RING_DEGREE;
    Ag64 acc = ag64_make(0u, 0u);

    for (uint ki = 0; ki < keyCount; ++ki) {
        uint rowBase = ki * RING_DEGREE * RING_DEGREE + lane * RING_DEGREE;
        uint laneBase = witnessBase + ki * RING_DEGREE;
        for (uint j = 0; j < RING_DEGREE; ++j) {
            acc = ag64_add(
                acc,
                ag64_mul(
                    ag64_load_soa(keyRotationRows, rotationPlaneLength, rowBase + j),
                    ag64_load_soa(witnessBatch, witnessCount, laneBase + j)
                )
            );
        }
    }

    uint outputCount = batchCount * RING_DEGREE;
    ag64_store_soa(outputBatch, outputCount, tid, acc);
}

kernel void nu_ring_mul_ag64_d64(
    device const uint* lhs [[buffer(0)]],
    device const uint* rhs [[buffer(1)]],
    device uint* output [[buffer(2)]],
    constant uint32_t& ringCount [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    uint ringIndex = tid / RING_DEGREE;
    uint lane = tid % RING_DEGREE;
    if (ringIndex >= ringCount) {
        return;
    }

    const uint planeLength = ringCount * RING_DEGREE;
    const uint base = ringIndex * RING_DEGREE;
    ag64_store_soa(
        output,
        planeLength,
        base + lane,
        ag64_ring_mul_lane(lhs, rhs, planeLength, planeLength, base, base, lane)
    );
}

kernel void nu_ring_bind_fold_batch(
    device const uint* challengeRings [[buffer(0)]],
    device const uint* inputRings [[buffer(1)]],
    device uint* outputRings [[buffer(2)]],
    constant uint32_t& sourceCount [[buffer(3)]],
    constant uint32_t& ringCount [[buffer(4)]],
    uint tid [[thread_position_in_grid]]
) {
    uint ringIndex = tid / RING_DEGREE;
    uint lane = tid % RING_DEGREE;
    if (ringIndex >= ringCount) {
        return;
    }

    const uint challengePlaneLength = sourceCount * RING_DEGREE;
    const uint inputPlaneLength = sourceCount * ringCount * RING_DEGREE;
    Ag64 acc = ag64_make(0u, 0u);

    for (uint sourceIndex = 0; sourceIndex < sourceCount; ++sourceIndex) {
        uint challengeBase = sourceIndex * RING_DEGREE;
        uint inputBase = (sourceIndex * ringCount + ringIndex) * RING_DEGREE;
        acc = ag64_add(
            acc,
            ag64_ring_mul_lane(
                challengeRings,
                inputRings,
                challengePlaneLength,
                inputPlaneLength,
                challengeBase,
                inputBase,
                lane
            )
        );
    }

    const uint outputPlaneLength = ringCount * RING_DEGREE;
    ag64_store_soa(outputRings, outputPlaneLength, ringIndex * RING_DEGREE + lane, acc);
}
