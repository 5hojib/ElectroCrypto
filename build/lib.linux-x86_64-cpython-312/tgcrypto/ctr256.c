#include "aes256.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

void ctr256(const uint8_t in[], uint8_t out[], uint32_t length, const uint8_t key[32], uint8_t iv[16], uint8_t *state) {
    uint8_t chunk[AES_BLOCK_SIZE];
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
    uint32_t i, j, k;

    aes256_set_encryption_key(key, expandedKey);

    aes256_encrypt(iv, chunk, expandedKey);

    for (i = 0; i < length; ) {
        if (*state == 0 && length - i >= AES_BLOCK_SIZE) {
            for (j = 0; j < AES_BLOCK_SIZE; j++) {
                out[i + j] = in[i + j] ^ chunk[j];
            }
            i += AES_BLOCK_SIZE;
            k = AES_BLOCK_SIZE;
            while(k--)
                if (++iv[k])
                    break;
            aes256_encrypt(iv, chunk, expandedKey);
        } else {
            out[i] = in[i] ^ chunk[(*state)++];
            i++;
            if (*state >= AES_BLOCK_SIZE) {
                *state = 0;
                k = AES_BLOCK_SIZE;
                while(k--)
                    if (++iv[k])
                        break;
                aes256_encrypt(iv, chunk, expandedKey);
            }
        }
    }

}
