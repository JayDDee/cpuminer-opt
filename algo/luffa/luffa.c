#include "algo-gate-api.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sph_luffa.h"
#if !defined(__arm__)
#include "sse2/luffa_for_sse2.h"
#endif

void luffahash(void *output, const void *input)
{
	unsigned char _ALIGN(128) hash[64];
	sph_luffa512_context ctx_luffa;

	sph_luffa512_init(&ctx_luffa);
	sph_luffa512 (&ctx_luffa, input, 80);
	sph_luffa512_close(&ctx_luffa, (void*) hash);

	memcpy(output, hash, 32);
}

int scanhash_luffa(int thr_id, struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

        for (int i=0; i < 19; i++) 
                be32enc(&endiandata[i], pdata[i]);

	do {
		be32enc(&endiandata[19], n);
		luffahash(hash64, endiandata);
		if (hash64[7] < Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}

bool register_luffa_algo( algo_gate_t* gate )
{
    gate->scanhash = (void*)&scanhash_luffa;
    gate->hash     = (void*)&luffahash;
    return true;
};

#if !defined(__arm__)
HashReturn init_luffa(hashState_luffa *state, int hashbitlen)
{
	printf("USE UNDEFINED LUFFA\n");
	/*
    int i;
    state->hashbitlen = hashbitlen;
    // set the lower 32 bits to '1' 
    MASK= _mm_set_epi32(0x00000000, 0x00000000, 0x00000000, 0xffffffff);
    // set all bits to '1'
    ALLONE = _mm_set_epi32(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff);
    // set the 32-bit round constant values to the 128-bit data field 
    for ( i=0; i<32; i++ )
        CNS128[i] = _mm_load_si128( (__m128i*)&CNS_INIT[i*4] );
    for ( i=0; i<10; i++ ) 
	state->chainv[i] = _mm_load_si128( (__m128i*)&IV[i*4] );
    memset(state->buffer, 0, sizeof state->buffer );
    return SUCCESS;
    */
}

HashReturn update_luffa( hashState_luffa *state, const BitSequence *data,
                         size_t len )
{
	printf("USE UNDEFINED LUFFA\n");
/*
    int i;
    int blocks = (int)len / 32;
    state-> rembytes = (int)len % 32;

    // full blocks
    for ( i = 0; i < blocks; i++ )
    {
       rnd512( state, mm_byteswap_32( casti_m128i( data, 1 ) ),
                      mm_byteswap_32( casti_m128i( data, 0 ) ) );
       data += MSG_BLOCK_BYTE_LEN;
    }

    // 16 byte partial block exists for 80 byte len
    // store in buffer for transform in final for midstate to work
    if ( state->rembytes  )
    {
      // remaining data bytes
      casti_m128i( state->buffer, 0 ) = mm_byteswap_32( cast_m128i( data ) );
      // padding of partial block
      casti_m128i( state->buffer, 1 ) =
            _mm_set_epi8( 0,0,0,0, 0,0,0,0, 0,0,0,0, 0x80,0,0,0 );
    }

    return SUCCESS;
    */
}

HashReturn final_luffa(hashState_luffa *state, BitSequence *hashval) 
{
	printf("USE UNDEFINED LUFFA\n");

/*
    // transform pad block
    if ( state->rembytes )
    {
      // not empty, data is in buffer
      rnd512( state, casti_m128i( state->buffer, 1 ),
                     casti_m128i( state->buffer, 0 ) );
    }
    else
    {
      // empty pad block, constant data
     rnd512( state, _mm_setzero_si128(),
                       _mm_set_epi8( 0,0,0,0, 0,0,0,0, 0,0,0,0, 0x80,0,0,0 ) );
    }

    finalization512(state, (uint32*) hashval);
    if ( state->hashbitlen > 512 )
        finalization512( state, (uint32*)( hashval+128 ) );
    return SUCCESS;
    */
}

HashReturn update_and_final_luffa( hashState_luffa *state, BitSequence* output,
              const BitSequence* data, size_t inlen )
{
	printf("USE UNDEFINED LUFFA\n");
/*
// Optimized for integrals of 16 bytes, good for 64 and 80 byte len
    int i;
    int blocks = (int)( inlen / 32 );
    state->rembytes = inlen % 32;

    // full blocks
    for ( i = 0; i < blocks; i++ )
    {
       rnd512( state, mm_byteswap_32( casti_m128i( data, 1 ) ),
                      mm_byteswap_32( casti_m128i( data, 0 ) ) );
       data += MSG_BLOCK_BYTE_LEN;
    }

    // 16 byte partial block exists for 80 byte len
    if ( state->rembytes  )
    {
      // padding of partial block
      rnd512( state, _mm_set_epi8( 0,0,0,0, 0,0,0,0, 0,0,0,0, 0x80,0,0,0 ),
                      mm_byteswap_32( cast_m128i( data ) ) );
    }
    else
    {
      // empty pad block
     rnd512( state, _mm_setzero_si128(), 
                       _mm_set_epi8( 0,0,0,0, 0,0,0,0, 0,0,0,0, 0x80,0,0,0 ) );
    }

    finalization512( state, (uint32*) output );
    if ( state->hashbitlen > 512 )
        finalization512( state, (uint32*)( output+128 ) );

    return SUCCESS;
    */
}
#endif