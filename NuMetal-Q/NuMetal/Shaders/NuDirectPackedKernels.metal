// NuMeQ Metal Compute Shaders — Direct-Packed Final Opening
// Dedicated protocol kernels for direct-packed Gaussian-mask preparation and
// final response/rejection metric computation.

struct DirectPackedMaskPrepareParams {
    uint32_t chunkCount;
    uint32_t sigma;
    uint32_t gaussianTableCount;
};

struct DirectPackedResponseFinalizeParams {
    uint32_t chunkCount;
    uint32_t maxAcceptedResponseBound;
    Ag64 sigmaChallenge;
};

struct DirectPackedResponseMetrics {
    ulong maskNorm;
    ulong responseNorm;
    ulong maxResponseMagnitude;
    uint responseBoundExceeded;
};

static inline ulong direct_packed_gaussian_magnitude(
    device const ulong* thresholds,
    uint thresholdCount,
    ulong raw
) {
    ulong target = raw >> 11;
    uint lower = 0u;
    uint upper = thresholdCount;
    while (lower < upper) {
        uint mid = lower + (upper - lower) / 2u;
        if (thresholds[mid] < target) {
            lower = mid + 1u;
        } else {
            upper = mid;
        }
    }
    if (thresholdCount == 0u) {
        return 0ull;
    }
    return ulong(min(lower, thresholdCount - 1u));
}

kernel void nu_direct_packed_mask_prepare(
    device const DirectPackedMaskPrepareParams& params [[buffer(0)]],
    device const ulong* gaussianThresholds [[buffer(1)]],
    device const ulong* shortMagnitudeRaw [[buffer(2)]],
    device const ulong* shortSignRaw [[buffer(3)]],
    device const ulong* outerMagnitudeRaw [[buffer(4)]],
    device const ulong* outerSignRaw [[buffer(5)]],
    device const uint* bindingCoefficients [[buffer(6)]],
    device const uint* relationShortCoefficients [[buffer(7)]],
    device const uint* relationOuterCoefficients [[buffer(8)]],
    device const uint* evaluationWeights [[buffer(9)]],
    device const uint* outerCoefficients [[buffer(10)]],
    device uint* shortMasks [[buffer(11)]],
    device uint* outerMasks [[buffer(12)]],
    device uint* bindingMaskVector [[buffer(13)]],
    device uint* relationMaskVector [[buffer(14)]],
    device uint* evaluationMask [[buffer(15)]],
    device uint* outerMaskVector [[buffer(16)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid != 0u) {
        return;
    }

    uint totalCount = params.chunkCount * RING_DEGREE;
    uint planeLength = totalCount;
    for (uint index = 0u; index < totalCount; ++index) {
        ulong shortMagnitude = direct_packed_gaussian_magnitude(
            gaussianThresholds,
            params.gaussianTableCount,
            shortMagnitudeRaw[index]
        );
        ulong outerMagnitude = direct_packed_gaussian_magnitude(
            gaussianThresholds,
            params.gaussianTableCount,
            outerMagnitudeRaw[index]
        );

        Ag64 shortMask = ag64_from_centered_magnitude(
            shortMagnitude,
            shortMagnitude != 0ull && (shortSignRaw[index] & 1ull) == 1ull
        );
        Ag64 outerMask = ag64_from_centered_magnitude(
            outerMagnitude,
            outerMagnitude != 0ull && (outerSignRaw[index] & 1ull) == 1ull
        );

        ag64_store_soa(shortMasks, planeLength, index, shortMask);
        ag64_store_soa(outerMasks, planeLength, index, outerMask);
    }

    for (uint index = 0u; index < totalCount; ++index) {
        uint chunkIndex = index / RING_DEGREE;
        uint lane = index % RING_DEGREE;
        uint ringBase = chunkIndex * RING_DEGREE;

        ag64_store_soa(
            bindingMaskVector,
            planeLength,
            index,
            ag64_ring_mul_lane(
                bindingCoefficients,
                shortMasks,
                planeLength,
                planeLength,
                ringBase,
                ringBase,
                lane
            )
        );

        Ag64 relationShort = ag64_ring_mul_lane(
            relationShortCoefficients,
            shortMasks,
            planeLength,
            planeLength,
            ringBase,
            ringBase,
            lane
        );
        Ag64 relationOuter = ag64_ring_mul_lane(
            relationOuterCoefficients,
            outerMasks,
            planeLength,
            planeLength,
            ringBase,
            ringBase,
            lane
        );
        ag64_store_soa(relationMaskVector, planeLength, index, ag64_add(relationShort, relationOuter));

        ag64_store_soa(
            outerMaskVector,
            planeLength,
            index,
            ag64_ring_mul_lane(
                outerCoefficients,
                outerMasks,
                planeLength,
                planeLength,
                ringBase,
                ringBase,
                lane
            )
        );
    }

    Ag64 evaluation = ag64_make(0u, 0u);
    for (uint chunk = 0u; chunk < params.chunkCount; ++chunk) {
        uint base = chunk * RING_DEGREE;
        for (uint i = 0u; i < RING_DEGREE; ++i) {
            evaluation = ag64_add(
                evaluation,
                ag64_mul(
                    ag64_load_soa(shortMasks, planeLength, base + i),
                    ag64_load_soa(evaluationWeights, planeLength, base + i)
                )
            );
        }
    }

    for (uint laneIndex = 0u; laneIndex < RING_DEGREE; ++laneIndex) {
        ag64_store_soa(
            evaluationMask,
            RING_DEGREE,
            laneIndex,
            laneIndex == 0u ? evaluation : ag64_make(0u, 0u)
        );
    }
}

kernel void nu_direct_packed_response_finalize(
    device const DirectPackedResponseFinalizeParams& params [[buffer(0)]],
    device const uint* shortMasks [[buffer(1)]],
    device const uint* outerMasks [[buffer(2)]],
    device const uint* residualShort [[buffer(3)]],
    device const uint* residualOuter [[buffer(4)]],
    device uint* shortResponses [[buffer(5)]],
    device uint* outerResponses [[buffer(6)]],
    device DirectPackedResponseMetrics* metrics [[buffer(7)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid != 0u) {
        return;
    }

    uint totalCount = params.chunkCount * RING_DEGREE;
    uint planeLength = totalCount;
    Ag64 sigmaChallenge = params.sigmaChallenge;

    for (uint index = 0u; index < totalCount; ++index) {
        Ag64 shortResponse = ag64_add(
            ag64_load_soa(shortMasks, planeLength, index),
            ag64_mul(sigmaChallenge, ag64_load_soa(residualShort, planeLength, index))
        );
        Ag64 outerResponse = ag64_add(
            ag64_load_soa(outerMasks, planeLength, index),
            ag64_mul(sigmaChallenge, ag64_load_soa(residualOuter, planeLength, index))
        );

        ag64_store_soa(shortResponses, planeLength, index, shortResponse);
        ag64_store_soa(outerResponses, planeLength, index, outerResponse);
    }

    ulong maskNorm = 0ull;
    ulong responseNorm = 0ull;
    ulong maxResponseMagnitude = 0ull;
    uint responseBoundExceeded = 0u;
    ulong bound = ulong(params.maxAcceptedResponseBound);

    for (uint index = 0u; index < totalCount; ++index) {
        ulong shortMaskMagnitude = ag64_centered_magnitude(ag64_load_soa(shortMasks, planeLength, index));
        ulong outerMaskMagnitude = ag64_centered_magnitude(ag64_load_soa(outerMasks, planeLength, index));
        ulong shortResponseMagnitude = ag64_centered_magnitude(ag64_load_soa(shortResponses, planeLength, index));
        ulong outerResponseMagnitude = ag64_centered_magnitude(ag64_load_soa(outerResponses, planeLength, index));

        maskNorm += (shortMaskMagnitude * shortMaskMagnitude) + (outerMaskMagnitude * outerMaskMagnitude);
        responseNorm += (shortResponseMagnitude * shortResponseMagnitude) + (outerResponseMagnitude * outerResponseMagnitude);
        maxResponseMagnitude = max(maxResponseMagnitude, max(shortResponseMagnitude, outerResponseMagnitude));
        if (shortResponseMagnitude >= bound || outerResponseMagnitude >= bound) {
            responseBoundExceeded = 1u;
        }
    }

    metrics[0].maskNorm = maskNorm;
    metrics[0].responseNorm = responseNorm;
    metrics[0].maxResponseMagnitude = maxResponseMagnitude;
    metrics[0].responseBoundExceeded = responseBoundExceeded;
}
