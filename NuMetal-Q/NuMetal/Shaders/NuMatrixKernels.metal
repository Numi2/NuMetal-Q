// NuMeQ Metal Compute Shaders — Matrix Lift / Evaluation
// CCS sparse matrix-vector work over the AG64 base field.

struct MatrixLiftParams {
    uint32_t numRows;
    uint32_t valueCount;
    uint32_t xCount;
};

kernel void nu_matrix_lift(
    device const uint32_t* rowPtr [[buffer(0)]],
    device const uint32_t* colIdx [[buffer(1)]],
    device const uint* values [[buffer(2)]],
    device const uint* x [[buffer(3)]],
    device uint* y [[buffer(4)]],
    constant MatrixLiftParams& params [[buffer(5)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= params.numRows) {
        return;
    }

    uint32_t start = rowPtr[tid];
    uint32_t end = rowPtr[tid + 1];

    Ag64 acc = ag64_make(0u, 0u);
    for (uint32_t index = start; index < end; ++index) {
        acc = ag64_add(
            acc,
            ag64_mul(
                ag64_load_soa(values, params.valueCount, index),
                ag64_load_soa(x, params.xCount, colIdx[index])
            )
        );
    }

    ag64_store_soa(y, params.numRows, tid, acc);
}
