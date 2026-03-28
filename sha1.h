#ifndef SHA1_H
#define SHA1_H

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

#include "stdint.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(
    uint32_t state[5],
    const unsigned char buffer[64]
    );

void SHA1Init(
    SHA1_CTX * context
    );

void SHA1Update(
    SHA1_CTX * context,
    const unsigned char *data,
    uint32_t len
    );

void SHA1Final(
    unsigned char digest[20],
    SHA1_CTX * context
    );

void SHA1(
    char *hash_out,
    const char *str,
    uint32_t len);

void SHA1WithStartingRegisters(char *hash_out,
                          const char *str,
                          uint32_t len,
                          uint32_t reg1, uint32_t reg2, uint32_t reg3, uint32_t reg4, uint32_t reg5,
                          uint64_t totalBytesProcessed);

#if defined(__cplusplus)
}
#endif

#endif /* SHA1_H */