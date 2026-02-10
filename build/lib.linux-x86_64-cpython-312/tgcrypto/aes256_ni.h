#ifndef AES256_NI_H
#define AES256_NI_H

#include <stdint.h>

int has_aes_ni(void);

void aes256_ni_set_encryption_key(const uint8_t key[32], uint32_t expandedKey[60]);
void aes256_ni_set_decryption_key(const uint8_t key[32], uint32_t expandedKey[60]);
void aes256_ni_encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]);
void aes256_ni_decrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]);

#endif
