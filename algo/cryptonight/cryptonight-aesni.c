#include <x86intrin.h>
#include <memory.h>
#include "cryptonight.h"
#include "miner.h"
#include "crypto/c_keccak.h"
#include <immintrin.h>
//#include "avxdefs.h"

void aesni_parallel_noxor(uint8_t *long_state, uint8_t *text, uint8_t *ExpandedKey);
void aesni_parallel_xor(uint8_t *text, uint8_t *ExpandedKey, uint8_t *long_state);
void that_fucking_loop(uint8_t a[16], uint8_t b[16], uint8_t *long_state);

static inline void ExpandAESKey256_sub1(__m128i *tmp1, __m128i *tmp2)
{
	__m128i tmp4;
	*tmp2 = _mm_shuffle_epi32(*tmp2, 0xFF);
	tmp4 = _mm_slli_si128(*tmp1, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	*tmp1 = _mm_xor_si128(*tmp1, *tmp2);
}

static inline void ExpandAESKey256_sub2(__m128i *tmp1, __m128i *tmp3)
{
#ifndef NO_AES_NI
	__m128i tmp2, tmp4;
	
	tmp4 = _mm_aeskeygenassist_si128(*tmp1, 0x00);
	tmp2 = _mm_shuffle_epi32(tmp4, 0xAA);
	tmp4 = _mm_slli_si128(*tmp3, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	*tmp3 = _mm_xor_si128(*tmp3, tmp2);
#endif
}

// Special thanks to Intel for helping me
// with ExpandAESKey256() and its subroutines
static inline void ExpandAESKey256(char *keybuf)
{
#ifndef NO_AES_NI
	__m128i tmp1, tmp2, tmp3, *keys;
	
	keys = (__m128i *)keybuf;
	
	tmp1 = _mm_load_si128((__m128i *)keybuf);
	tmp3 = _mm_load_si128((__m128i *)(keybuf+0x10));
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[2] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[3] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[4] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[5] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[6] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[7] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[8] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[9] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[10] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[11] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[12] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[13] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[14] = tmp1;
#endif
}

// align to 64 byte cache line
typedef struct 
{
    uint8_t long_state[MEMORY] __attribute((aligned(64)));
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE] __attribute((aligned(64)));
    uint64_t a[AES_BLOCK_SIZE >> 3] __attribute__((aligned(64)));
    uint64_t b[AES_BLOCK_SIZE >> 3] __attribute__((aligned(64)));
    uint8_t c[AES_BLOCK_SIZE] __attribute__((aligned(64)));
} cryptonight_ctx;

static __thread cryptonight_ctx ctx;

void cryptonight_hash_aes( void *restrict output, const void *input, int len )
{
#ifndef NO_AES_NI

    uint8_t ExpandedKey[256] __attribute__((aligned(64)));
    __m128i *longoutput, *expkey, *xmminput;
    size_t i, j;
    
    keccak( (const uint8_t*)input, 76, (char*)&ctx.state.hs.b, 200 );
    memcpy( ExpandedKey, ctx.state.hs.b, AES_KEY_SIZE );
    ExpandAESKey256( ExpandedKey );
    memcpy( ctx.text, ctx.state.init, INIT_SIZE_BYTE );
    
    longoutput = (__m128i*)ctx.long_state;
    xmminput   = (__m128i*)ctx.text;
    expkey     = (__m128i*)ExpandedKey;
    
    // prefetch expkey, xmminput and enough longoutput for 4 iterations
    _mm_prefetch( xmminput,     _MM_HINT_T0 );
    _mm_prefetch( xmminput + 4, _MM_HINT_T0 );
    _mm_prefetch( expkey,     _MM_HINT_T0 );
    _mm_prefetch( expkey + 4, _MM_HINT_T0 );
    _mm_prefetch( expkey + 8, _MM_HINT_T0 );
    for ( i = 0; i < 64; i += 16 )
    {
        __builtin_prefetch( longoutput + i,      1, 0 );
        __builtin_prefetch( longoutput + i +  4, 1, 0 );
        __builtin_prefetch( longoutput + i +  8, 1, 0 );
        __builtin_prefetch( longoutput + i + 12, 1, 0 );
    }

    // n-4 iterations
    for ( i = 0; likely( i < MEMORY_M128I - 4*INIT_SIZE_M128I );
                         i += INIT_SIZE_M128I )
    {
        // prefetch 4 iterations ahead.
        __builtin_prefetch( longoutput + i + 64, 1, 0 );
        __builtin_prefetch( longoutput + i + 68, 1, 0 );

	for ( j = 0; j < 10; j++ )
	{
		xmminput[0] = _mm_aesenc_si128( xmminput[0], expkey[j] );
		xmminput[1] = _mm_aesenc_si128( xmminput[1], expkey[j] );
		xmminput[2] = _mm_aesenc_si128( xmminput[2], expkey[j] );
		xmminput[3] = _mm_aesenc_si128( xmminput[3], expkey[j] );
		xmminput[4] = _mm_aesenc_si128( xmminput[4], expkey[j] );
		xmminput[5] = _mm_aesenc_si128( xmminput[5], expkey[j] );
		xmminput[6] = _mm_aesenc_si128( xmminput[6], expkey[j] );
		xmminput[7] = _mm_aesenc_si128( xmminput[7], expkey[j] );
	}
	_mm_store_si128( &( longoutput[i  ] ), xmminput[0] );
	_mm_store_si128( &( longoutput[i+1] ), xmminput[1] );
	_mm_store_si128( &( longoutput[i+2] ), xmminput[2] );
	_mm_store_si128( &( longoutput[i+3] ), xmminput[3] );
	_mm_store_si128( &( longoutput[i+4] ), xmminput[4] );
	_mm_store_si128( &( longoutput[i+5] ), xmminput[5] );
	_mm_store_si128( &( longoutput[i+6] ), xmminput[6] );
	_mm_store_si128( &( longoutput[i+7] ), xmminput[7] );
    }
    // last 4 iterations
    for ( ; likely( i < MEMORY_M128I ); i += INIT_SIZE_M128I )
    {
        for ( j = 0; j < 10; j++ )
        {
                xmminput[0] = _mm_aesenc_si128( xmminput[0], expkey[j] );
                xmminput[1] = _mm_aesenc_si128( xmminput[1], expkey[j] );
                xmminput[2] = _mm_aesenc_si128( xmminput[2], expkey[j] );
                xmminput[3] = _mm_aesenc_si128( xmminput[3], expkey[j] );
                xmminput[4] = _mm_aesenc_si128( xmminput[4], expkey[j] );
                xmminput[5] = _mm_aesenc_si128( xmminput[5], expkey[j] );
                xmminput[6] = _mm_aesenc_si128( xmminput[6], expkey[j] );
                xmminput[7] = _mm_aesenc_si128( xmminput[7], expkey[j] );
        }
        _mm_store_si128( &( longoutput[i  ] ), xmminput[0] );
        _mm_store_si128( &( longoutput[i+1] ), xmminput[1] );
        _mm_store_si128( &( longoutput[i+2] ), xmminput[2] );
        _mm_store_si128( &( longoutput[i+3] ), xmminput[3] );
        _mm_store_si128( &( longoutput[i+4] ), xmminput[4] );
        _mm_store_si128( &( longoutput[i+5] ), xmminput[5] );
        _mm_store_si128( &( longoutput[i+6] ), xmminput[6] );
        _mm_store_si128( &( longoutput[i+7] ), xmminput[7] );
    }

    ctx.a[0] = ((uint64_t *)ctx.state.k)[0] ^ ((uint64_t *)ctx.state.k)[4];
    ctx.b[0] = ((uint64_t *)ctx.state.k)[2] ^ ((uint64_t *)ctx.state.k)[6];
    ctx.a[1] = ((uint64_t *)ctx.state.k)[1] ^ ((uint64_t *)ctx.state.k)[5];
    ctx.b[1] = ((uint64_t *)ctx.state.k)[3] ^ ((uint64_t *)ctx.state.k)[7];

    uint64_t a[2] __attribute((aligned(16))),
             b[2] __attribute((aligned(16))),
             c[2] __attribute((aligned(16)));
    a[0] = ctx.a[0];
    a[1] = ctx.a[1];
    __m128i b_x = _mm_load_si128( (__m128i*)ctx.b );
    __m128i a_x = _mm_load_si128( (__m128i*)a );
    __m128i* lsa = (__m128i*)&ctx.long_state[ a[0] & 0x1FFFF0 ];
    __m128i c_x = _mm_load_si128( lsa );
    uint64_t *nextblock;
    uint64_t hi, lo;

    // n-1 iterations
    for( i = 0; __builtin_expect( i < 0x7ffff, 1 ); i++ )
    {	  
	c_x = _mm_aesenc_si128( c_x, a_x );
	_mm_store_si128( (__m128i*)c, c_x );
        b_x = _mm_xor_si128( b_x, c_x );
        nextblock = (uint64_t *)&ctx.long_state[c[0] & 0x1FFFF0];
	_mm_store_si128( lsa, b_x );
	b[0] = nextblock[0];
	b[1] = nextblock[1];

        // hi,lo = 64bit x 64bit multiply of c[0] and b[0]
	__asm__( "mulq %3\n\t"
	         : "=d" ( hi ),
	           "=a" ( lo )
	         : "%a" ( c[0] ),
	           "rm" ( b[0] )
		 : "cc" );

        b_x = c_x;
        nextblock[0] = a[0] + hi;
        nextblock[1] = a[1] + lo;
        a[0] = b[0] ^ nextblock[0];
        a[1] = b[1] ^ nextblock[1];
        lsa = (__m128i*)&ctx.long_state[ a[0] & 0x1FFFF0 ];
        a_x = _mm_load_si128( (__m128i*)a );
        c_x = _mm_load_si128( lsa );
    }
    // abreviated nth iteration
    c_x = _mm_aesenc_si128( c_x, a_x );
    _mm_store_si128( (__m128i*)c, c_x );
    b_x = _mm_xor_si128( b_x, c_x );
    nextblock = (uint64_t *)&ctx.long_state[c[0] & 0x1FFFF0];
    _mm_store_si128( lsa, b_x );
    b[0] = nextblock[0];
    b[1] = nextblock[1];

    __asm__( "mulq %3\n\t"
             : "=d" ( hi ),
               "=a" ( lo )
             : "%a" ( c[0] ),
               "rm" ( b[0] )
             : "cc" );

    nextblock[0] = a[0] + hi;
    nextblock[1] = a[1] + lo;

    memcpy( ExpandedKey, &ctx.state.hs.b[32], AES_KEY_SIZE );
    ExpandAESKey256( ExpandedKey );
    memcpy( ctx.text, ctx.state.init, INIT_SIZE_BYTE );
    
    // prefetch expkey, all of xmminput and enough longoutput for 4 loops
    _mm_prefetch( xmminput,     _MM_HINT_T0 );
    _mm_prefetch( xmminput + 4, _MM_HINT_T0 );
    for ( i = 0; i < 64; i += 16 )
    {
       _mm_prefetch( longoutput + i,      _MM_HINT_T0 );
       _mm_prefetch( longoutput + i +  4, _MM_HINT_T0 );
       _mm_prefetch( longoutput + i +  8, _MM_HINT_T0 );
       _mm_prefetch( longoutput + i + 12, _MM_HINT_T0 );
    }
    _mm_prefetch( expkey,     _MM_HINT_T0 );
    _mm_prefetch( expkey + 4, _MM_HINT_T0 );
    _mm_prefetch( expkey + 8, _MM_HINT_T0 );

    // n-4 iterations
    for ( i = 0; likely( i < MEMORY_M128I - 4*INIT_SIZE_M128I );
                         i += INIT_SIZE_M128I )
    {
        // stay 4 iterations ahead.
        _mm_prefetch( longoutput + i + 64, _MM_HINT_T0 );
        _mm_prefetch( longoutput + i + 68, _MM_HINT_T0 );

        xmminput[0] = _mm_xor_si128( longoutput[i  ], xmminput[0] );
        xmminput[1] = _mm_xor_si128( longoutput[i+1], xmminput[1] );
        xmminput[2] = _mm_xor_si128( longoutput[i+2], xmminput[2] );
        xmminput[3] = _mm_xor_si128( longoutput[i+3], xmminput[3] );
        xmminput[4] = _mm_xor_si128( longoutput[i+4], xmminput[4] );
        xmminput[5] = _mm_xor_si128( longoutput[i+5], xmminput[5] );
        xmminput[6] = _mm_xor_si128( longoutput[i+6], xmminput[6] );
        xmminput[7] = _mm_xor_si128( longoutput[i+7], xmminput[7] );
		
        for( j = 0; j < 10; j++ )
        {
            xmminput[0] = _mm_aesenc_si128( xmminput[0], expkey[j] );
	    xmminput[1] = _mm_aesenc_si128( xmminput[1], expkey[j] );
	    xmminput[2] = _mm_aesenc_si128( xmminput[2], expkey[j] );
	    xmminput[3] = _mm_aesenc_si128( xmminput[3], expkey[j] );
	    xmminput[4] = _mm_aesenc_si128( xmminput[4], expkey[j] );
	    xmminput[5] = _mm_aesenc_si128( xmminput[5], expkey[j] );
	    xmminput[6] = _mm_aesenc_si128( xmminput[6], expkey[j] );
	    xmminput[7] = _mm_aesenc_si128( xmminput[7], expkey[j] );
        }
    }
    // last 4 iterations 
    for ( ; likely( i < MEMORY_M128I ); i += INIT_SIZE_M128I )
    {
        xmminput[0] = _mm_xor_si128( longoutput[i  ], xmminput[0] );
        xmminput[1] = _mm_xor_si128( longoutput[i+1], xmminput[1] );
        xmminput[2] = _mm_xor_si128( longoutput[i+2], xmminput[2] );
        xmminput[3] = _mm_xor_si128( longoutput[i+3], xmminput[3] );
        xmminput[4] = _mm_xor_si128( longoutput[i+4], xmminput[4] );
        xmminput[5] = _mm_xor_si128( longoutput[i+5], xmminput[5] );
        xmminput[6] = _mm_xor_si128( longoutput[i+6], xmminput[6] );
        xmminput[7] = _mm_xor_si128( longoutput[i+7], xmminput[7] );

        for( j = 0; j < 10; j++ )
        {
            xmminput[0] = _mm_aesenc_si128( xmminput[0], expkey[j] );
            xmminput[1] = _mm_aesenc_si128( xmminput[1], expkey[j] );
            xmminput[2] = _mm_aesenc_si128( xmminput[2], expkey[j] );
            xmminput[3] = _mm_aesenc_si128( xmminput[3], expkey[j] );
            xmminput[4] = _mm_aesenc_si128( xmminput[4], expkey[j] );
            xmminput[5] = _mm_aesenc_si128( xmminput[5], expkey[j] );
            xmminput[6] = _mm_aesenc_si128( xmminput[6], expkey[j] );
            xmminput[7] = _mm_aesenc_si128( xmminput[7], expkey[j] );
        }
    }

    memcpy( ctx.state.init, ctx.text, INIT_SIZE_BYTE);
    keccakf( (uint64_t*)&ctx.state.hs.w, 24 );
    extra_hashes[ctx.state.hs.b[0] & 3](&ctx.state, 200, output);

#endif
}
