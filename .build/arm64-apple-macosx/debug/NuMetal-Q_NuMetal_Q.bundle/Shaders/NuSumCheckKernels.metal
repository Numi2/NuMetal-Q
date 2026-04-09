// NuMeQ Metal Compute Shaders — Sum-Check Partial Reductions
// AG64 field core with 32-bit partial products and Solinas reduction.

struct SumCheckParams {
    uint32_t count;
    uint32_t outputCount;
};

kernel void nu_sumcheck_partial(
    device const uint* evals [[buffer(0)]],
    device uint* output [[buffer(1)]],
    constant SumCheckParams& params [[buffer(2)]],
    uint tid [[thread_position_in_grid]],
    uint tgid [[threadgroup_position_in_grid]],
    uint lid [[thread_position_in_threadgroup]],
    uint tgSize [[threads_per_threadgroup]]
) {
    uint nHalf = params.count / 2u;
    if (tid >= nHalf) {
        return;
    }

    Ag64 value0 = ag64_load_soa(evals, params.count, 2u * tid);
    Ag64 value1 = ag64_load_soa(evals, params.count, 2u * tid + 1u);

    threadgroup uint shared0Lo[256];
    threadgroup uint shared0Hi[256];
    threadgroup uint shared1Lo[256];
    threadgroup uint shared1Hi[256];

    shared0Lo[lid] = value0.lo;
    shared0Hi[lid] = value0.hi;
    shared1Lo[lid] = value1.lo;
    shared1Hi[lid] = value1.hi;
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint stride = tgSize / 2u; stride > 0u; stride >>= 1u) {
        if (lid < stride) {
            Ag64 shared0 = ag64_add(
                ag64_make(shared0Lo[lid], shared0Hi[lid]),
                ag64_make(shared0Lo[lid + stride], shared0Hi[lid + stride])
            );
            Ag64 shared1 = ag64_add(
                ag64_make(shared1Lo[lid], shared1Hi[lid]),
                ag64_make(shared1Lo[lid + stride], shared1Hi[lid + stride])
            );
            shared0Lo[lid] = shared0.lo;
            shared0Hi[lid] = shared0.hi;
            shared1Lo[lid] = shared1.lo;
            shared1Hi[lid] = shared1.hi;
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (lid == 0u) {
        ag64_store_soa(
            output,
            params.outputCount,
            2u * tgid,
            ag64_make(shared0Lo[0], shared0Hi[0])
        );
        ag64_store_soa(
            output,
            params.outputCount,
            2u * tgid + 1u,
            ag64_make(shared1Lo[0], shared1Hi[0])
        );
    }
}

kernel void nu_pirlc_fold(
    device const uint* evals [[buffer(0)]],
    device uint* output [[buffer(1)]],
    constant uint2& challenge [[buffer(2)]],
    constant uint32_t& count [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    uint nHalf = count / 2u;
    if (tid >= nHalf) {
        return;
    }

    Ag64 challengeValue = ag64_make(challenge.x, challenge.y);
    Ag64 oneMinusR = ag64_sub(ag64_make(1u, 0u), challengeValue);
    Ag64 e0 = ag64_load_soa(evals, count, 2u * tid);
    Ag64 e1 = ag64_load_soa(evals, count, 2u * tid + 1u);

    ag64_store_soa(
        output,
        nHalf,
        tid,
        ag64_add(
            ag64_mul(oneMinusR, e0),
            ag64_mul(challengeValue, e1)
        )
    );
}
