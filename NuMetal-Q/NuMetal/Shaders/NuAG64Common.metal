// NuMeQ Metal Compute Shaders — Shared AG64 Module
// Canonical production ABI:
// - Fq as two UInt32 limbs in low-plane/high-plane SoA form
// - Fq2 as four UInt32 planes
// - Rq as SoA tiles of 64 lanes

#include <metal_stdlib>
using namespace metal;

struct Ag64 {
    uint lo;
    uint hi;
};

struct Ag64AddResult {
    Ag64 value;
    uint carry;
};

struct Ag64SubResult {
    Ag64 value;
    uint borrow;
};

struct Ag64Fq2 {
    Ag64 a;
    Ag64 b;
};

static constant Ag64 AG64_MOD = { 0xFFFF'FFE1u, 0xFFFF'FFFEu };
static constant Ag64 AG64_CORR = { 31u, 1u };
static constant uint64_t AG64_BETA = 3ull;
static constant uint RING_DEGREE = 64u;

static inline Ag64 ag64_make(uint lo, uint hi) {
    Ag64 value;
    value.lo = lo;
    value.hi = hi;
    return value;
}

static inline bool ag64_ge(Ag64 lhs, Ag64 rhs) {
    return lhs.hi > rhs.hi || (lhs.hi == rhs.hi && lhs.lo >= rhs.lo);
}

static inline Ag64AddResult ag64_add_raw(Ag64 lhs, Ag64 rhs) {
    uint lo = lhs.lo + rhs.lo;
    uint carry0 = lo < lhs.lo ? 1u : 0u;
    uint hi = lhs.hi + rhs.hi;
    uint carry1 = hi < lhs.hi ? 1u : 0u;
    uint hiWithCarry = hi + carry0;
    uint carry2 = hiWithCarry < hi ? 1u : 0u;

    Ag64AddResult result;
    result.value = ag64_make(lo, hiWithCarry);
    result.carry = carry1 | carry2;
    return result;
}

static inline Ag64SubResult ag64_sub_raw(Ag64 lhs, Ag64 rhs) {
    uint lo = lhs.lo - rhs.lo;
    uint borrow0 = lhs.lo < rhs.lo ? 1u : 0u;
    uint hi = lhs.hi - rhs.hi - borrow0;
    uint borrow1 = (lhs.hi < rhs.hi) || (borrow0 != 0u && lhs.hi == rhs.hi) ? 1u : 0u;

    Ag64SubResult result;
    result.value = ag64_make(lo, hi);
    result.borrow = borrow1;
    return result;
}

static inline Ag64 ag64_add(Ag64 lhs, Ag64 rhs) {
    Ag64AddResult sum = ag64_add_raw(lhs, rhs);
    Ag64 value = sum.value;
    if (sum.carry != 0u) {
        value = ag64_add_raw(value, AG64_CORR).value;
    }
    if (ag64_ge(value, AG64_MOD)) {
        value = ag64_sub_raw(value, AG64_MOD).value;
    }
    return value;
}

static inline Ag64 ag64_sub(Ag64 lhs, Ag64 rhs) {
    if (ag64_ge(lhs, rhs)) {
        return ag64_sub_raw(lhs, rhs).value;
    }
    return ag64_add_raw(ag64_sub_raw(AG64_MOD, rhs).value, lhs).value;
}

static inline Ag64 ag64_neg(Ag64 value) {
    if (value.lo == 0u && value.hi == 0u) {
        return value;
    }
    return ag64_sub_raw(AG64_MOD, value).value;
}

static inline Ag64 ag64_mul(Ag64 lhs, Ag64 rhs) {
    uint64_t p00 = uint64_t(lhs.lo) * uint64_t(rhs.lo);
    uint64_t p01 = uint64_t(lhs.lo) * uint64_t(rhs.hi);
    uint64_t p10 = uint64_t(lhs.hi) * uint64_t(rhs.lo);
    uint64_t p11 = uint64_t(lhs.hi) * uint64_t(rhs.hi);

    uint64_t limb0 = p00 & 0xFFFF'FFFFull;
    uint64_t limb1Acc = (p00 >> 32) + (p01 & 0xFFFF'FFFFull) + (p10 & 0xFFFF'FFFFull);
    uint64_t limb1 = limb1Acc & 0xFFFF'FFFFull;
    uint64_t limb2Acc = (limb1Acc >> 32) + (p01 >> 32) + (p10 >> 32) + (p11 & 0xFFFF'FFFFull);
    uint64_t limb2 = limb2Acc & 0xFFFF'FFFFull;
    uint64_t limb3 = (limb2Acc >> 32) + (p11 >> 32);

    uint64_t folded0 = limb0 + 31ull * limb2 + 31ull * limb3;
    uint64_t folded1 = limb1 + limb2 + 32ull * limb3 + (folded0 >> 32);
    uint s0 = uint(folded0 & 0xFFFF'FFFFull);
    uint s1 = uint(folded1 & 0xFFFF'FFFFull);
    uint64_t s2 = folded1 >> 32;

    uint64_t reduced0 = uint64_t(s0) + 31ull * s2;
    uint64_t reduced1 = uint64_t(s1) + s2 + (reduced0 >> 32);
    Ag64 result = ag64_make(
        uint(reduced0 & 0xFFFF'FFFFull),
        uint(reduced1 & 0xFFFF'FFFFull)
    );

    if ((reduced1 >> 32) != 0ull) {
        result = ag64_add(result, AG64_CORR);
    }
    if (ag64_ge(result, AG64_MOD)) {
        result = ag64_sub_raw(result, AG64_MOD).value;
    }
    if (ag64_ge(result, AG64_MOD)) {
        result = ag64_sub_raw(result, AG64_MOD).value;
    }
    return result;
}

static inline Ag64 ag64_from_u64(uint64_t value) {
    return ag64_make(uint(value & 0xFFFF'FFFFull), uint(value >> 32));
}

static inline uint64_t ag64_to_u64(Ag64 value) {
    return (uint64_t(value.hi) << 32) | uint64_t(value.lo);
}

static inline Ag64 ag64_from_centered_magnitude(uint64_t magnitude, bool isNegative) {
    Ag64 value = ag64_from_u64(magnitude);
    return isNegative && magnitude != 0ull ? ag64_neg(value) : value;
}

static inline uint64_t ag64_centered_magnitude(Ag64 value) {
    uint64_t raw = ag64_to_u64(value);
    uint64_t modulus = ag64_to_u64(AG64_MOD);
    uint64_t midpoint = modulus / 2ull;
    return raw <= midpoint ? raw : modulus - raw;
}

static inline Ag64 ag64_load_soa(
    device const uint* storage,
    uint planeLength,
    uint index
) {
    return ag64_make(storage[index], storage[planeLength + index]);
}

static inline void ag64_store_soa(
    device uint* storage,
    uint planeLength,
    uint index,
    Ag64 value
) {
    storage[index] = value.lo;
    storage[planeLength + index] = value.hi;
}

static inline Ag64Fq2 ag64_load_fq2_soa(
    device const uint* storage,
    uint count,
    uint index
) {
    Ag64Fq2 value;
    value.a = ag64_make(storage[index], storage[count + index]);
    value.b = ag64_make(storage[(2u * count) + index], storage[(3u * count) + index]);
    return value;
}

static inline void ag64_store_fq2_soa(
    device uint* storage,
    uint count,
    uint index,
    Ag64Fq2 value
) {
    storage[index] = value.a.lo;
    storage[count + index] = value.a.hi;
    storage[(2u * count) + index] = value.b.lo;
    storage[(3u * count) + index] = value.b.hi;
}

static inline Ag64Fq2 ag64_fq2_mul(Ag64Fq2 lhs, Ag64Fq2 rhs) {
    Ag64 aa = ag64_mul(lhs.a, rhs.a);
    Ag64 bb = ag64_mul(lhs.b, rhs.b);
    Ag64 abSum = ag64_mul(
        ag64_add(lhs.a, lhs.b),
        ag64_add(rhs.a, rhs.b)
    );

    Ag64Fq2 result;
    result.a = ag64_add(aa, ag64_mul(ag64_from_u64(AG64_BETA), bb));
    result.b = ag64_sub(abSum, ag64_add(aa, bb));
    return result;
}

static inline Ag64 ag64_ring_mul_lane(
    device const uint* lhs,
    device const uint* rhs,
    uint lhsPlaneLength,
    uint rhsPlaneLength,
    uint lhsBase,
    uint rhsBase,
    uint lane
) {
    Ag64 acc = ag64_make(0u, 0u);
    for (uint i = 0; i < RING_DEGREE; ++i) {
        uint j = (lane + RING_DEGREE - i) % RING_DEGREE;
        Ag64 product = ag64_mul(
            ag64_load_soa(lhs, lhsPlaneLength, lhsBase + i),
            ag64_load_soa(rhs, rhsPlaneLength, rhsBase + j)
        );
        acc = i > lane ? ag64_sub(acc, product) : ag64_add(acc, product);
    }
    return acc;
}
