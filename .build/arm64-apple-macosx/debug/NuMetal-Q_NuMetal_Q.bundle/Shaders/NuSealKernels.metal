// NuMeQ Metal Compute Shaders — Seal PCS Kernels
// Codeword encoding, query evaluation, and Merkle tree construction
// for Lightning PCS work inside the terminal Hachi decider.

struct SealQueryParams {
    uint32_t numQueries;
    uint32_t codewordLength;
};

// Deterministic codeword extension for Lightning PCS.
// The current CPU reference extends a multilinear evaluation table by repeating
// boolean-hypercube evaluations modulo n. The GPU path must match that exactly
// for equivalence testing and seal-opening validation.
kernel void nu_seal_encode(
    device const uint*     evals   [[buffer(0)]],
    device uint*           codeword [[buffer(1)]],
    constant uint32_t&     n       [[buffer(2)]],
    constant uint32_t&     blowup  [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    uint total = n * blowup;
    if (tid >= total) return;
    ag64_store_soa(codeword, total, tid, ag64_load_soa(evals, n, tid % n));
}

// Query evaluation: extract values at queried positions across folding levels.
kernel void nu_seal_query(
    device const uint*      codeword   [[buffer(0)]],
    device const uint32_t*  positions  [[buffer(1)]],
    device uint*            results    [[buffer(2)]],
    constant SealQueryParams& params [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= params.numQueries) return;
    uint32_t pos = positions[tid];
    ag64_store_soa(results, params.numQueries, tid, ag64_load_soa(codeword, params.codewordLength, pos));
}

// SHA-256 Merkle tree leaf hashing for the Lightning PCS leaf domain:
// H(0x00 || leaf-bytes), where each leaf is one 64-bit field element in
// canonical little-endian form.

[[maybe_unused]] constant uint32_t SHA_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr32(uint32_t x, uint n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t sha_ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t sha_maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t sha_big_sigma0(uint32_t x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
inline uint32_t sha_big_sigma1(uint32_t x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }
inline uint32_t sha_small_sigma0(uint32_t x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
inline uint32_t sha_small_sigma1(uint32_t x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }

kernel void nu_merkle_hash(
    device const uint*      leaves    [[buffer(0)]],
    device uint32_t*        nodes     [[buffer(1)]],
    constant uint32_t&      numLeaves [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= numLeaves) return;

    uint64_t leaf = ag64_to_u64(ag64_load_soa(leaves, numLeaves, tid));
    uchar block[64];
    for (uint i = 0; i < 64; ++i) {
        block[i] = 0;
    }

    block[0] = 0x00;
    for (uint i = 0; i < 8; ++i) {
        block[1 + i] = uchar((leaf >> (8 * i)) & 0xFF);
    }
    block[9] = 0x80;
    block[63] = 72; // message length = 9 bytes = 72 bits

    uint32_t w[64];
    for (uint i = 0; i < 16; ++i) {
        uint base = i * 4;
        w[i] =
            (uint32_t(block[base]) << 24) |
            (uint32_t(block[base + 1]) << 16) |
            (uint32_t(block[base + 2]) << 8) |
            uint32_t(block[base + 3]);
    }
    for (uint i = 16; i < 64; ++i) {
        w[i] = sha_small_sigma1(w[i - 2]) + w[i - 7] + sha_small_sigma0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = 0x6a09e667;
    uint32_t b = 0xbb67ae85;
    uint32_t c = 0x3c6ef372;
    uint32_t d = 0xa54ff53a;
    uint32_t e = 0x510e527f;
    uint32_t f = 0x9b05688c;
    uint32_t g = 0x1f83d9ab;
    uint32_t h = 0x5be0cd19;

    for (uint i = 0; i < 64; ++i) {
        uint32_t t1 = h + sha_big_sigma1(e) + sha_ch(e, f, g) + SHA_K[i] + w[i];
        uint32_t t2 = sha_big_sigma0(a) + sha_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    uint32_t h0 = 0x6a09e667 + a;
    uint32_t h1 = 0xbb67ae85 + b;
    uint32_t h2 = 0x3c6ef372 + c;
    uint32_t h3 = 0xa54ff53a + d;
    uint32_t h4 = 0x510e527f + e;
    uint32_t h5 = 0x9b05688c + f;
    uint32_t h6 = 0x1f83d9ab + g;
    uint32_t h7 = 0x5be0cd19 + h;

    uint outBase = tid * 8;
    nodes[outBase + 0] = h0;
    nodes[outBase + 1] = h1;
    nodes[outBase + 2] = h2;
    nodes[outBase + 3] = h3;
    nodes[outBase + 4] = h4;
    nodes[outBase + 5] = h5;
    nodes[outBase + 6] = h6;
    nodes[outBase + 7] = h7;
}

kernel void nu_merkle_parent(
    device const uint32_t*  childNodes  [[buffer(0)]],
    device uint32_t*        parentNodes [[buffer(1)]],
    constant uint32_t&      numParents  [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= numParents) return;

    uint leftBase = (2u * tid) * 8u;
    uint rightBase = (2u * tid + 1u) * 8u;

    uint32_t w[64];
    for (uint i = 0; i < 16; ++i) {
        w[i] = i < 8u ? childNodes[leftBase + i] : childNodes[rightBase + (i - 8u)];
    }
    for (uint i = 16; i < 64; ++i) {
        w[i] = sha_small_sigma1(w[i - 2]) + w[i - 7] + sha_small_sigma0(w[i - 15]) + w[i - 16];
    }

    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (uint i = 0; i < 64; ++i) {
        uint32_t t1 = h + sha_big_sigma1(e) + sha_ch(e, f, g) + SHA_K[i] + w[i];
        uint32_t t2 = sha_big_sigma0(a) + sha_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

    w[0] = 0x80000000;
    for (uint i = 1; i < 15; ++i) {
        w[i] = 0;
    }
    w[15] = 64u * 8u;
    for (uint i = 16; i < 64; ++i) {
        w[i] = sha_small_sigma1(w[i - 2]) + w[i - 7] + sha_small_sigma0(w[i - 15]) + w[i - 16];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (uint i = 0; i < 64; ++i) {
        uint32_t t1 = h + sha_big_sigma1(e) + sha_ch(e, f, g) + SHA_K[i] + w[i];
        uint32_t t2 = sha_big_sigma0(a) + sha_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    uint outBase = tid * 8u;
    parentNodes[outBase + 0] = state[0] + a;
    parentNodes[outBase + 1] = state[1] + b;
    parentNodes[outBase + 2] = state[2] + c;
    parentNodes[outBase + 3] = state[3] + d;
    parentNodes[outBase + 4] = state[4] + e;
    parentNodes[outBase + 5] = state[5] + f;
    parentNodes[outBase + 6] = state[6] + g;
    parentNodes[outBase + 7] = state[7] + h;
}
