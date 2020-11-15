#if !defined(GROESTL512_HASH_4WAY_H__)
#define GROESTL512_HASH_4WAY_H__ 1

#include "simd-utils.h"
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#if defined(_WIN64) || defined(__WINDOWS__)
#include <windows.h>
#endif
#include <stdlib.h>

#if defined(__AVX2__) && defined(__VAES__)

#define LENGTH (512)

/* some sizes (number of bytes) */
#define ROWS (8)
#define LENGTHFIELDLEN (ROWS)
//#define COLS512 (8)
#define COLS1024 (16)
//#define SIZE512 ((ROWS)*(COLS512))
#define SIZE_1024 ((ROWS)*(COLS1024))
//#define ROUNDS512 (10)
#define ROUNDS1024 (14)

//#if LENGTH<=256
//#define COLS (COLS512)
//#define SIZE (SIZE512)
//#define ROUNDS (ROUNDS512)
//#else
#define COLS (COLS1024)
//#define SIZE (SIZE1024)
#define ROUNDS (ROUNDS1024)
//#endif

#define SIZE512 (SIZE_1024/16)

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

typedef struct {
  __attribute__ ((aligned (128))) __m512i chaining[SIZE512];
  __attribute__ ((aligned (64))) __m512i buffer[SIZE512];
  int blk_count;     // SIZE_m128i
  int buf_ptr;       // __m128i offset
  int rem_ptr;
} groestl512_4way_context;


int groestl512_4way_init( groestl512_4way_context*, uint64_t );

int groestl512_4way_update( groestl512_4way_context*, const void*,
                              uint64_t );
int groestl512_4way_close( groestl512_4way_context*, void* );
int groestl512_4way_update_close( groestl512_4way_context*,  void*,
                                        const void*, uint64_t );
int groestl512_4way_full( groestl512_4way_context*,  void*,
                          const void*, uint64_t );

#endif   // AVX512

// AVX2 + VAES

typedef struct {
  __attribute__ ((aligned (128))) __m256i chaining[SIZE512];
  __attribute__ ((aligned (64))) __m256i buffer[SIZE512];
  int blk_count;     // SIZE_m128i
  int buf_ptr;       // __m128i offset
  int rem_ptr;
} groestl512_2way_context;


int groestl512_2way_init( groestl512_2way_context*, uint64_t );

int groestl512_2way_update( groestl512_2way_context*, const void*,
                              uint64_t );
int groestl512_2way_close( groestl512_2way_context*, void* );
int groestl512_2way_update_close( groestl512_2way_context*,  void*,
                                        const void*, uint64_t );
int groestl512_2way_full( groestl512_2way_context*,  void*,
                          const void*, uint64_t );


#endif   // VAES
#endif   // GROESTL512_HASH_4WAY_H__
