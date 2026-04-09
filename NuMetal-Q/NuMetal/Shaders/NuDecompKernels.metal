// NuMeQ Metal Compute Shaders — PiDEC Decomposition
// Decomposes centered ring coefficients into bounded limbs.
// Each coefficient c is split into: c = c_0 + c_1*B + c_2*B^2 + ...
// where each c_i has centered norm < b and the current Metal hot path supports power-of-two b.

struct DecompParams {
    uint32_t numElements;
    uint32_t limbBitWidth;
    uint32_t numLimbs;
};

kernel void nu_pidec_decompose(
    device const uint* input   [[buffer(0)]],
    device uint*       output  [[buffer(1)]],
    constant DecompParams& params  [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= params.numElements) return;

    Ag64 fieldValue = ag64_load_soa(input, params.numElements, tid);
    uint64_t value = ag64_to_u64(fieldValue);
    uint64_t mask = (1ULL << params.limbBitWidth) - 1;
    bool isNegative = value > (ag64_to_u64(AG64_MOD) >> 1);
    uint64_t magnitude = isNegative ? (ag64_to_u64(AG64_MOD) - value) : value;
    uint totalValueCount = params.numElements * params.numLimbs;

    for (uint l = 0; l < params.numLimbs; l++) {
        uint outIdx = l * params.numElements + tid;
        uint64_t digit = (magnitude >> (l * params.limbBitWidth)) & mask;
        Ag64 outputDigit = ag64_from_u64(
            (isNegative && digit != 0) ? (ag64_to_u64(AG64_MOD) - digit) : digit
        );
        ag64_store_soa(output, totalValueCount, outIdx, outputDigit);
    }
}
