#ifndef CRYPTONIGHT_SOFT_SHELL_H
#define CRYPTONIGHT_SOFT_SHELL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void cryptonight_soft_shell_hash(const char* input, char* output, uint32_t len, int variant, uint32_t scratchpad, uint32_t iterations);
void cryptonight_soft_shell_fast_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
