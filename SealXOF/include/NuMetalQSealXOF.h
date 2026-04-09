#ifndef NUMETALQSEALXOF_H
#define NUMETALQSEALXOF_H

#include <stddef.h>
#include <stdint.h>

void numeq_seal_shake256(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len
);

void numeq_seal_cshake256(
    const uint8_t *name,
    size_t name_len,
    const uint8_t *custom,
    size_t custom_len,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len
);

#endif
