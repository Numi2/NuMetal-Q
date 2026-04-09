kernel void nu_field(
    device const uint* a [[buffer(0)]],
    device const uint* b [[buffer(1)]],
    device uint* out [[buffer(2)]],
    constant uint32_t& count [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) {
        return;
    }
    ag64_store_soa(
        out,
        count,
        tid,
        ag64_add(ag64_load_soa(a, count, tid), ag64_load_soa(b, count, tid))
    );
}

kernel void nu_fq2(
    device const uint* a [[buffer(0)]],
    device const uint* b [[buffer(1)]],
    device uint* out [[buffer(2)]],
    constant uint32_t& count [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) {
        return;
    }
    ag64_store_fq2_soa(
        out,
        count,
        tid,
        ag64_fq2_mul(
            ag64_load_fq2_soa(a, count, tid),
            ag64_load_fq2_soa(b, count, tid)
        )
    );
}
