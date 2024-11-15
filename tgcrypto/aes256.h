#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef AES256_H
#define AES256_H

#define AES_BLOCK_SIZE 16
#define EXPANDED_KEY_SIZE 60

void aes256_set_encryption_key(const uint8_t key[32], uint32_t expandedKey[60]);

void aes256_set_decryption_key(const uint8_t key[32], uint32_t expandedKey[60]);

void aes256_encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]);

void aes256_decrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]);

#endif  // AES256_H
