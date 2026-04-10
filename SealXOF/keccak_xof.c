#include "NuMetalQSealXOF.h"

#include <stdlib.h>
#include <string.h>

#define KECCAK_LANES 25
#define SHAKE256_RATE 136

static uint64_t rotl64(uint64_t value, unsigned shift) {
    return (value << shift) | (value >> (64 - shift));
}

static uint64_t load64_le(const uint8_t *src) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value |= ((uint64_t)src[i]) << (8 * i);
    }
    return value;
}

static void store64_le(uint8_t *dst, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        dst[i] = (uint8_t)((value >> (8 * i)) & 0xFF);
    }
}

static void keccakf1600(uint64_t state[KECCAK_LANES]) {
    static const uint64_t round_constants[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808AULL, 0x8000000080008000ULL,
        0x000000000000808BULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008AULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000AULL,
        0x000000008000808BULL, 0x800000000000008BULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800AULL, 0x800000008000000AULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL
    };
    static const unsigned rotations[24] = {
         1,  3,  6, 10, 15, 21,
        28, 36, 45, 55,  2, 14,
        27, 41, 56,  8, 25, 43,
        62, 18, 39, 61, 20, 44
    };
    static const unsigned pi_lane[24] = {
        10,  7, 11, 17, 18, 3,
         5, 16,  8, 21, 24, 4,
        15, 23, 19, 13, 12, 2,
        20, 14, 22,  9, 6,  1
    };

    for (size_t round = 0; round < 24; ++round) {
        uint64_t c[5];
        for (size_t x = 0; x < 5; ++x) {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        uint64_t d[5];
        for (size_t x = 0; x < 5; ++x) {
            d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        }
        for (size_t x = 0; x < 5; ++x) {
            for (size_t y = 0; y < 25; y += 5) {
                state[y + x] ^= d[x];
            }
        }

        uint64_t current = state[1];
        for (size_t i = 0; i < 24; ++i) {
            const unsigned index = pi_lane[i];
            uint64_t next = state[index];
            state[index] = rotl64(current, rotations[i]);
            current = next;
        }

        for (size_t y = 0; y < 25; y += 5) {
            uint64_t row[5];
            for (size_t x = 0; x < 5; ++x) {
                row[x] = state[y + x];
            }
            for (size_t x = 0; x < 5; ++x) {
                state[y + x] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }

        state[0] ^= round_constants[round];
    }
}

static void keccak_absorb(
    uint64_t state[KECCAK_LANES],
    const uint8_t *input,
    size_t input_len,
    uint8_t suffix
) {
    while (input_len >= SHAKE256_RATE) {
        for (size_t i = 0; i < SHAKE256_RATE / 8; ++i) {
            state[i] ^= load64_le(input + 8 * i);
        }
        keccakf1600(state);
        input += SHAKE256_RATE;
        input_len -= SHAKE256_RATE;
    }

    uint8_t block[SHAKE256_RATE];
    memset(block, 0, sizeof(block));
    if (input_len > 0) {
        memcpy(block, input, input_len);
    }
    block[input_len] ^= suffix;
    block[SHAKE256_RATE - 1] ^= 0x80;

    for (size_t i = 0; i < SHAKE256_RATE / 8; ++i) {
        state[i] ^= load64_le(block + 8 * i);
    }
}

static void keccak_squeeze(
    uint64_t state[KECCAK_LANES],
    uint8_t *output,
    size_t output_len
) {
    while (output_len > 0) {
        keccakf1600(state);
        const size_t take = output_len < SHAKE256_RATE ? output_len : SHAKE256_RATE;
        for (size_t i = 0; i < take / 8; ++i) {
            store64_le(output + 8 * i, state[i]);
        }
        if (take % 8 != 0) {
            uint8_t lane_bytes[8];
            store64_le(lane_bytes, state[take / 8]);
            memcpy(output + (take / 8) * 8, lane_bytes, take % 8);
        }
        output += take;
        output_len -= take;
    }
}

static size_t left_encode(uint64_t value, uint8_t out[9]) {
    size_t n = 1;
    uint64_t tmp = value;
    while (tmp > 0xFF) {
        ++n;
        tmp >>= 8;
    }
    out[0] = (uint8_t)n;
    for (size_t i = 0; i < n; ++i) {
        out[n - i] = (uint8_t)(value & 0xFF);
        value >>= 8;
    }
    return n + 1;
}

static size_t encode_string(
    const uint8_t *input,
    size_t input_len,
    uint8_t **out
) {
    uint8_t prefix[9];
    size_t prefix_len = left_encode((uint64_t)input_len * 8ULL, prefix);
    size_t total = prefix_len + input_len;
    uint8_t *buffer = (uint8_t *)malloc(total == 0 ? 1 : total);
    if (buffer == NULL) {
        *out = NULL;
        return 0;
    }
    memcpy(buffer, prefix, prefix_len);
    if (input_len > 0) {
        memcpy(buffer + prefix_len, input, input_len);
    }
    *out = buffer;
    return total;
}

static size_t bytepad(
    const uint8_t *input,
    size_t input_len,
    size_t width,
    uint8_t **out
) {
    uint8_t prefix[9];
    size_t prefix_len = left_encode((uint64_t)width, prefix);
    size_t total = prefix_len + input_len;
    size_t padded = total;
    size_t remainder = padded % width;
    if (remainder != 0) {
        padded += width - remainder;
    }

    uint8_t *buffer = (uint8_t *)calloc(padded == 0 ? 1 : padded, sizeof(uint8_t));
    if (buffer == NULL) {
        *out = NULL;
        return 0;
    }
    memcpy(buffer, prefix, prefix_len);
    if (input_len > 0) {
        memcpy(buffer + prefix_len, input, input_len);
    }
    *out = buffer;
    return padded;
}

void numeq_seal_shake256(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len
) {
    uint64_t state[KECCAK_LANES];
    memset(state, 0, sizeof(state));
    keccak_absorb(state, input, input_len, 0x1F);
    keccak_squeeze(state, output, output_len);
}

int numeq_seal_cshake256(
    const uint8_t *name,
    size_t name_len,
    const uint8_t *custom,
    size_t custom_len,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len
) {
    if ((name_len == 0 || name == NULL) && (custom_len == 0 || custom == NULL)) {
        numeq_seal_shake256(input, input_len, output, output_len);
        return 1;
    }

    uint64_t state[KECCAK_LANES];
    memset(state, 0, sizeof(state));

    uint8_t *encoded_name = NULL;
    uint8_t *encoded_custom = NULL;
    size_t encoded_name_len = encode_string(name, name_len, &encoded_name);
    size_t encoded_custom_len = encode_string(custom, custom_len, &encoded_custom);
    size_t combined_len = encoded_name_len + encoded_custom_len;

    uint8_t *combined = (uint8_t *)malloc(combined_len == 0 ? 1 : combined_len);
    if (combined == NULL || encoded_name == NULL || encoded_custom == NULL) {
        free(encoded_name);
        free(encoded_custom);
        free(combined);
        return 0;
    }
    memcpy(combined, encoded_name, encoded_name_len);
    memcpy(combined + encoded_name_len, encoded_custom, encoded_custom_len);

    uint8_t *customized = NULL;
    size_t customized_len = bytepad(combined, combined_len, SHAKE256_RATE, &customized);
    if (customized == NULL) {
        free(encoded_name);
        free(encoded_custom);
        free(combined);
        return 0;
    }

    size_t total_len = customized_len + input_len;
    uint8_t *message = (uint8_t *)malloc(total_len == 0 ? 1 : total_len);
    if (message == NULL) {
        free(encoded_name);
        free(encoded_custom);
        free(combined);
        free(customized);
        return 0;
    }
    memcpy(message, customized, customized_len);
    if (input_len > 0) {
        memcpy(message + customized_len, input, input_len);
    }

    keccak_absorb(state, message, total_len, 0x04);
    keccak_squeeze(state, output, output_len);

    free(encoded_name);
    free(encoded_custom);
    free(combined);
    free(customized);
    free(message);
    return 1;
}
