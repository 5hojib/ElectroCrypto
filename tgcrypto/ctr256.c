#include "aes256.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

uint8_t *ctr256(const uint8_t in[], uint32_t length, const uint8_t key[32], uint8_t iv[16], uint8_t *state) {
    uint8_t *out = (uint8_t *) malloc(length * sizeof(uint8_t));
    uint8_t chunk[AES_BLOCK_SIZE];
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
    uint32_t i, j, k;

    memcpy(out, in, length);
    aes256_set_encryption_key(key, expandedKey);

    aes256_encrypt(iv, chunk, expandedKey);

    for (i = 0; i < length; i += AES_BLOCK_SIZE)
        for (j = 0; j < MIN(length - i, AES_BLOCK_SIZE); ++j) {
            out[i + j] ^= chunk[(*state)++];

            if (*state >= AES_BLOCK_SIZE)
                *state = 0;

            if (*state == 0) {
                k = AES_BLOCK_SIZE;
                while(k--)
                    if (++iv[k])
                        break;

                aes256_encrypt(iv, chunk, expandedKey);
            }
        }

    return out;
}
