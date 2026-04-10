// NuMeQ Metal Compute Shaders — Direct-Packed Final Opening
// Staged Apple-silicon pipeline:
// - decode transcript-derived Gaussian mask seeds
// - prepare image vectors per chunk
// - reduce evaluation mask in two passes
// - form responses
// - reduce rejection metrics in two passes

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

static constant uint DIRECT_PACKED_CHUNK_WIDTH = RING_DEGREE;
static constant uint DIRECT_PACKED_REDUCTION_WIDTH = 64u;
static constant uint DIRECT_PACKED_METRICS_WIDTH = 128u;

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

kernel void nu_direct_packed_mask_decode(
    device const DirectPackedMaskPrepareParams& params [[buffer(0)]],
    device const ulong* gaussianThresholds [[buffer(1)]],
    device const ulong* shortMagnitudeRaw [[buffer(2)]],
    device const ulong* shortSignRaw [[buffer(3)]],
    device const ulong* outerMagnitudeRaw [[buffer(4)]],
    device const ulong* outerSignRaw [[buffer(5)]],
    device uint* shortMasks [[buffer(6)]],
    device uint* outerMasks [[buffer(7)]],
    uint tid [[thread_position_in_grid]]
) {
    uint totalCount = params.chunkCount * RING_DEGREE;
    if (tid >= totalCount) {
        return;
    }

    ulong shortMagnitude = direct_packed_gaussian_magnitude(
        gaussianThresholds,
        params.gaussianTableCount,
        shortMagnitudeRaw[tid]
    );
    ulong outerMagnitude = direct_packed_gaussian_magnitude(
        gaussianThresholds,
        params.gaussianTableCount,
        outerMagnitudeRaw[tid]
    );

    Ag64 shortMask = ag64_from_centered_magnitude(
        shortMagnitude,
        shortMagnitude != 0ull && (shortSignRaw[tid] & 1ull) == 1ull
    );
    Ag64 outerMask = ag64_from_centered_magnitude(
        outerMagnitude,
        outerMagnitude != 0ull && (outerSignRaw[tid] & 1ull) == 1ull
    );

    ag64_store_soa(shortMasks, totalCount, tid, shortMask);
    ag64_store_soa(outerMasks, totalCount, tid, outerMask);
}

kernel void nu_direct_packed_image_prepare(
    device const DirectPackedMaskPrepareParams& params [[buffer(0)]],
    device const uint* bindingCoefficients [[buffer(1)]],
    device const uint* relationShortCoefficients [[buffer(2)]],
    device const uint* relationOuterCoefficients [[buffer(3)]],
    device const uint* outerCoefficients [[buffer(4)]],
    device const uint* shortMasks [[buffer(5)]],
    device const uint* outerMasks [[buffer(6)]],
    device uint* bindingMaskVector [[buffer(7)]],
    device uint* relationMaskVector [[buffer(8)]],
    device uint* outerMaskVector [[buffer(9)]],
    uint tid [[thread_position_in_grid]],
    uint localIndex [[thread_position_in_threadgroup]]
) {
    uint totalCount = params.chunkCount * RING_DEGREE;
    if (tid >= totalCount || localIndex >= DIRECT_PACKED_CHUNK_WIDTH) {
        return;
    }

    uint chunkIndex = tid / RING_DEGREE;
    uint lane = tid % RING_DEGREE;
    uint ringBase = chunkIndex * RING_DEGREE;

    ag64_store_soa(
        bindingMaskVector,
        totalCount,
        tid,
        ag64_ring_mul_lane(
            bindingCoefficients,
            shortMasks,
            totalCount,
            totalCount,
            ringBase,
            ringBase,
            lane
        )
    );

    Ag64 relationShort = ag64_ring_mul_lane(
        relationShortCoefficients,
        shortMasks,
        totalCount,
        totalCount,
        ringBase,
        ringBase,
        lane
    );
    Ag64 relationOuter = ag64_ring_mul_lane(
        relationOuterCoefficients,
        outerMasks,
        totalCount,
        totalCount,
        ringBase,
        ringBase,
        lane
    );
    ag64_store_soa(relationMaskVector, totalCount, tid, ag64_add(relationShort, relationOuter));

    ag64_store_soa(
        outerMaskVector,
        totalCount,
        tid,
        ag64_ring_mul_lane(
            outerCoefficients,
            outerMasks,
            totalCount,
            totalCount,
            ringBase,
            ringBase,
            lane
        )
    );
}

kernel void nu_direct_packed_evaluation_partial_reduce(
    device const DirectPackedMaskPrepareParams& params [[buffer(0)]],
    device const uint* shortMasks [[buffer(1)]],
    device const uint* evaluationWeights [[buffer(2)]],
    device uint* evaluationPartials [[buffer(3)]],
    uint tid [[thread_position_in_grid]],
    uint localIndex [[thread_position_in_threadgroup]],
    uint groupIndex [[threadgroup_position_in_grid]]
) {
    uint totalCount = params.chunkCount * RING_DEGREE;
    if (tid >= totalCount || groupIndex >= params.chunkCount || localIndex >= DIRECT_PACKED_CHUNK_WIDTH) {
        return;
    }

    threadgroup Ag64 scratch[DIRECT_PACKED_CHUNK_WIDTH];
    scratch[localIndex] = ag64_mul(
        ag64_load_soa(shortMasks, totalCount, tid),
        ag64_load_soa(evaluationWeights, totalCount, tid)
    );
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint stride = DIRECT_PACKED_CHUNK_WIDTH / 2u; stride > 0u; stride >>= 1u) {
        if (localIndex < stride) {
            scratch[localIndex] = ag64_add(scratch[localIndex], scratch[localIndex + stride]);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (localIndex == 0u) {
        ag64_store_soa(evaluationPartials, params.chunkCount, groupIndex, scratch[0]);
    }
}

kernel void nu_direct_packed_evaluation_finalize(
    device const DirectPackedMaskPrepareParams& params [[buffer(0)]],
    device const uint* evaluationPartials [[buffer(1)]],
    device uint* evaluationMask [[buffer(2)]],
    uint localIndex [[thread_position_in_threadgroup]]
) {
    threadgroup Ag64 scratch[DIRECT_PACKED_REDUCTION_WIDTH];
    Ag64 accumulator = ag64_make(0u, 0u);

    for (uint index = localIndex; index < params.chunkCount; index += DIRECT_PACKED_REDUCTION_WIDTH) {
        accumulator = ag64_add(accumulator, ag64_load_soa(evaluationPartials, params.chunkCount, index));
    }

    scratch[localIndex] = accumulator;
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint stride = DIRECT_PACKED_REDUCTION_WIDTH / 2u; stride > 0u; stride >>= 1u) {
        if (localIndex < stride) {
            scratch[localIndex] = ag64_add(scratch[localIndex], scratch[localIndex + stride]);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (localIndex < RING_DEGREE) {
        ag64_store_soa(
            evaluationMask,
            RING_DEGREE,
            localIndex,
            localIndex == 0u ? scratch[0] : ag64_make(0u, 0u)
        );
    }
}

kernel void nu_direct_packed_response_form(
    device const DirectPackedResponseFinalizeParams& params [[buffer(0)]],
    device const uint* shortMasks [[buffer(1)]],
    device const uint* outerMasks [[buffer(2)]],
    device const uint* residualShort [[buffer(3)]],
    device const uint* residualOuter [[buffer(4)]],
    device uint* shortResponses [[buffer(5)]],
    device uint* outerResponses [[buffer(6)]],
    uint tid [[thread_position_in_grid]]
) {
    uint totalCount = params.chunkCount * RING_DEGREE;
    if (tid >= totalCount) {
        return;
    }

    Ag64 shortResponse = ag64_add(
        ag64_load_soa(shortMasks, totalCount, tid),
        ag64_mul(params.sigmaChallenge, ag64_load_soa(residualShort, totalCount, tid))
    );
    Ag64 outerResponse = ag64_add(
        ag64_load_soa(outerMasks, totalCount, tid),
        ag64_mul(params.sigmaChallenge, ag64_load_soa(residualOuter, totalCount, tid))
    );

    ag64_store_soa(shortResponses, totalCount, tid, shortResponse);
    ag64_store_soa(outerResponses, totalCount, tid, outerResponse);
}

kernel void nu_direct_packed_response_metrics_partial_reduce(
    device const DirectPackedResponseFinalizeParams& params [[buffer(0)]],
    device const uint* shortMasks [[buffer(1)]],
    device const uint* outerMasks [[buffer(2)]],
    device const uint* shortResponses [[buffer(3)]],
    device const uint* outerResponses [[buffer(4)]],
    device DirectPackedResponseMetrics* partialMetrics [[buffer(5)]],
    uint tid [[thread_position_in_grid]],
    uint localIndex [[thread_position_in_threadgroup]],
    uint groupIndex [[threadgroup_position_in_grid]]
) {
    uint totalCount = params.chunkCount * RING_DEGREE;
    threadgroup ulong maskScratch[DIRECT_PACKED_METRICS_WIDTH];
    threadgroup ulong responseScratch[DIRECT_PACKED_METRICS_WIDTH];
    threadgroup ulong maxScratch[DIRECT_PACKED_METRICS_WIDTH];
    threadgroup uint overflowScratch[DIRECT_PACKED_METRICS_WIDTH];

    ulong maskNorm = 0ull;
    ulong responseNorm = 0ull;
    ulong maxResponseMagnitude = 0ull;
    uint responseBoundExceeded = 0u;
    ulong bound = ulong(params.maxAcceptedResponseBound);

    if (tid < totalCount) {
        ulong shortMaskMagnitude = ag64_centered_magnitude(ag64_load_soa(shortMasks, totalCount, tid));
        ulong outerMaskMagnitude = ag64_centered_magnitude(ag64_load_soa(outerMasks, totalCount, tid));
        ulong shortResponseMagnitude = ag64_centered_magnitude(ag64_load_soa(shortResponses, totalCount, tid));
        ulong outerResponseMagnitude = ag64_centered_magnitude(ag64_load_soa(outerResponses, totalCount, tid));

        maskNorm = (shortMaskMagnitude * shortMaskMagnitude) + (outerMaskMagnitude * outerMaskMagnitude);
        responseNorm = (shortResponseMagnitude * shortResponseMagnitude) + (outerResponseMagnitude * outerResponseMagnitude);
        maxResponseMagnitude = max(shortResponseMagnitude, outerResponseMagnitude);
        responseBoundExceeded = (shortResponseMagnitude >= bound || outerResponseMagnitude >= bound) ? 1u : 0u;
    }

    maskScratch[localIndex] = maskNorm;
    responseScratch[localIndex] = responseNorm;
    maxScratch[localIndex] = maxResponseMagnitude;
    overflowScratch[localIndex] = responseBoundExceeded;
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint stride = DIRECT_PACKED_METRICS_WIDTH / 2u; stride > 0u; stride >>= 1u) {
        if (localIndex < stride) {
            maskScratch[localIndex] += maskScratch[localIndex + stride];
            responseScratch[localIndex] += responseScratch[localIndex + stride];
            maxScratch[localIndex] = max(maxScratch[localIndex], maxScratch[localIndex + stride]);
            overflowScratch[localIndex] = max(overflowScratch[localIndex], overflowScratch[localIndex + stride]);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (localIndex == 0u) {
        partialMetrics[groupIndex].maskNorm = maskScratch[0];
        partialMetrics[groupIndex].responseNorm = responseScratch[0];
        partialMetrics[groupIndex].maxResponseMagnitude = maxScratch[0];
        partialMetrics[groupIndex].responseBoundExceeded = overflowScratch[0];
    }
}

kernel void nu_direct_packed_response_metrics_finalize(
    device const DirectPackedResponseFinalizeParams& params [[buffer(0)]],
    device const DirectPackedResponseMetrics* partialMetrics [[buffer(1)]],
    device DirectPackedResponseMetrics* metrics [[buffer(2)]],
    uint localIndex [[thread_position_in_threadgroup]]
) {
    uint partialCount = max(
        1u,
        (params.chunkCount * RING_DEGREE + DIRECT_PACKED_METRICS_WIDTH - 1u) / DIRECT_PACKED_METRICS_WIDTH
    );
    threadgroup ulong maskScratch[DIRECT_PACKED_REDUCTION_WIDTH];
    threadgroup ulong responseScratch[DIRECT_PACKED_REDUCTION_WIDTH];
    threadgroup ulong maxScratch[DIRECT_PACKED_REDUCTION_WIDTH];
    threadgroup uint overflowScratch[DIRECT_PACKED_REDUCTION_WIDTH];

    ulong maskNorm = 0ull;
    ulong responseNorm = 0ull;
    ulong maxResponseMagnitude = 0ull;
    uint responseBoundExceeded = 0u;

    for (uint index = localIndex; index < partialCount; index += DIRECT_PACKED_REDUCTION_WIDTH) {
        maskNorm += partialMetrics[index].maskNorm;
        responseNorm += partialMetrics[index].responseNorm;
        maxResponseMagnitude = max(maxResponseMagnitude, partialMetrics[index].maxResponseMagnitude);
        responseBoundExceeded = max(responseBoundExceeded, partialMetrics[index].responseBoundExceeded);
    }

    maskScratch[localIndex] = maskNorm;
    responseScratch[localIndex] = responseNorm;
    maxScratch[localIndex] = maxResponseMagnitude;
    overflowScratch[localIndex] = responseBoundExceeded;
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint stride = DIRECT_PACKED_REDUCTION_WIDTH / 2u; stride > 0u; stride >>= 1u) {
        if (localIndex < stride) {
            maskScratch[localIndex] += maskScratch[localIndex + stride];
            responseScratch[localIndex] += responseScratch[localIndex + stride];
            maxScratch[localIndex] = max(maxScratch[localIndex], maxScratch[localIndex + stride]);
            overflowScratch[localIndex] = max(overflowScratch[localIndex], overflowScratch[localIndex + stride]);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (localIndex == 0u) {
        metrics[0].maskNorm = maskScratch[0];
        metrics[0].responseNorm = responseScratch[0];
        metrics[0].maxResponseMagnitude = maxScratch[0];
        metrics[0].responseBoundExceeded = overflowScratch[0];
    }
}
