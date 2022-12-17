/* public api for steve reid's public domain SHA-1 implementation */
/* this file is in the public domain */

#ifndef __SHA1_H
#define __SHA1_H

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdint.h>
#include <cstddef>
typedef struct {
    uint32_t s[5];
    uint32_t c[2];
    uint8_t buf[64];
} SHA1_CTX;

#define SHA1_DIGEST_SIZE 20

void SHA1_Init(SHA1_CTX *ctx);
void SHA1_Update(SHA1_CTX *ctx, const uint8_t *data, const size_t len);
void SHA1_Final(SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif                          /* __SHA1_H */
