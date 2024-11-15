#ifndef CBC256_H
#define CBC256_H

uint8_t *cbc256(const uint8_t in[], uint32_t length, const uint8_t key[32], uint8_t iv[16], uint8_t encrypt);

#endif
