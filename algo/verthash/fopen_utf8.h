#ifndef H_FOPEN_UTF8
#define H_FOPEN_UTF8
#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

int utf8_char_size(const uint8_t *c);
uint32_t utf8_to_unicode32(const uint8_t *c, size_t *index);
int codepoint_utf16_size(uint32_t c);
uint16_t *sprint_utf16(uint16_t *str, uint32_t c);
size_t strlen_utf8_to_utf16(const uint8_t *str);
uint16_t *utf8_to_utf16(const uint8_t *utf8, uint16_t *utf16);

FILE *fopen_utf8(const char *path, const char *mode);

#ifdef __cplusplus
}
#endif
#endif

