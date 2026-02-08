#include "aes256_ni.h"
#include "aes256.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#include <wmmintrin.h>
#include <immintrin.h>

int has_aes_ni(void) {
#if defined(_MSC_VER)
    int cpuinfo[4];
    __cpuid(cpuinfo, 1);
    return (cpuinfo[2] & (1 << 25)) != 0;
#else
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & (1 << 25)) != 0;
    }
    return 0;
#endif
}

static void swap_endian(uint32_t *key, int words) {
    for (int i = 0; i < words; i++) {
        uint32_t x = key[i];
        key[i] = ((x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24));
    }
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("aes,sse2")))
#endif
void aes256_ni_set_encryption_key(const uint8_t key[32], uint32_t expandedKey[60]) {
    aes256_set_encryption_key_portable(key, expandedKey);
    swap_endian(expandedKey, 60);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("aes,sse2")))
#endif
void aes256_ni_set_decryption_key(const uint8_t key[32], uint32_t expandedKey[60]) {
    // We need the encryption keys in reverse order, but in host-endian for NI
    // The portable aes256_set_encryption_key_portable produces Big-Endian words.
    aes256_set_encryption_key_portable(key, expandedKey);
    __m128i *k = (__m128i *)expandedKey;

    // Reverse keys
    for (int i = 0; i < 7; ++i) {
        __m128i tmp = _mm_loadu_si128(&k[i]);
        _mm_storeu_si128(&k[i], _mm_loadu_si128(&k[14 - i]));
        _mm_storeu_si128(&k[14 - i], tmp);
    }

    // Swap endian for all words (NI expects Little-Endian on x86)
    swap_endian(expandedKey, 60);

    // Apply aesimc to all but first and last
    for (int i = 1; i < 14; ++i) {
        _mm_storeu_si128(&k[i], _mm_aesimc_si128(_mm_loadu_si128(&k[i])));
    }
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("aes,sse2")))
#endif
void aes256_ni_encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]) {
    __m128i m = _mm_loadu_si128((const __m128i *)in);
    const __m128i *k = (const __m128i *)expandedKey;

    m = _mm_xor_si128(m, _mm_loadu_si128(&k[0]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[1]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[2]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[3]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[4]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[5]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[6]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[7]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[8]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[9]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[10]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[11]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[12]));
    m = _mm_aesenc_si128(m, _mm_loadu_si128(&k[13]));
    m = _mm_aesenclast_si128(m, _mm_loadu_si128(&k[14]));

    _mm_storeu_si128((__m128i *)out, m);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("aes,sse2")))
#endif
void aes256_ni_decrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]) {
    __m128i m = _mm_loadu_si128((const __m128i *)in);
    const __m128i *k = (const __m128i *)expandedKey;

    m = _mm_xor_si128(m, _mm_loadu_si128(&k[0]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[1]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[2]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[3]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[4]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[5]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[6]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[7]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[8]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[9]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[10]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[11]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[12]));
    m = _mm_aesdec_si128(m, _mm_loadu_si128(&k[13]));
    m = _mm_aesdeclast_si128(m, _mm_loadu_si128(&k[14]));

    _mm_storeu_si128((__m128i *)out, m);
}

#else
int has_aes_ni(void) { return 0; }
void aes256_ni_set_encryption_key(const uint8_t key[32], uint32_t expandedKey[60]) {}
void aes256_ni_set_decryption_key(const uint8_t key[32], uint32_t expandedKey[60]) {}
void aes256_ni_encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]) {}
void aes256_ni_decrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]) {}
#endif
