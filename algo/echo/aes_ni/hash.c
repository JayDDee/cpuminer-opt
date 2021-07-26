/*
 * file        : echo_vperm.c
 * version     : 1.0.208
 * date        : 14.12.2010
 * 
 * - vperm and aes_ni implementations of hash function ECHO
 * - implements NIST hash api
 * - assumes that message lenght is multiple of 8-bits
 * - _ECHO_VPERM_ must be defined if compiling with ../main.c
 *
 * Cagdas Calik
 * ccalik@metu.edu.tr
 * Institute of Applied Mathematics, Middle East Technical University, Turkey.
 *
 */
#if defined(__AES__)

#include <memory.h>
#include "miner.h"
#include "hash_api.h"
//#include "vperm.h"
#include <immintrin.h>
#include "simd-utils.h"

MYALIGN const unsigned int _k_s0F[] = {0x0F0F0F0F, 0x0F0F0F0F, 0x0F0F0F0F, 0x0F0F0F0F};
MYALIGN const unsigned int _k_ipt[] = {0x5A2A7000, 0xC2B2E898, 0x52227808, 0xCABAE090, 0x317C4D00, 0x4C01307D, 0xB0FDCC81, 0xCD80B1FC};
MYALIGN const unsigned int _k_opt[] = {0xD6B66000, 0xFF9F4929, 0xDEBE6808, 0xF7974121, 0x50BCEC00, 0x01EDBD51, 0xB05C0CE0, 0xE10D5DB1};
MYALIGN const unsigned int _k_inv[] = {0x0D080180, 0x0E05060F, 0x0A0B0C02, 0x04070309, 0x0F0B0780, 0x01040A06, 0x02050809, 0x030D0E0C};
MYALIGN const unsigned int _k_sb1[] = {0xCB503E00, 0xB19BE18F, 0x142AF544, 0xA5DF7A6E, 0xFAE22300, 0x3618D415, 0x0D2ED9EF, 0x3BF7CCC1};
MYALIGN const unsigned int _k_sb2[] = {0x0B712400, 0xE27A93C6, 0xBC982FCD, 0x5EB7E955, 0x0AE12900, 0x69EB8840, 0xAB82234A, 0xC2A163C8};
MYALIGN const unsigned int _k_sb3[] = {0xC0211A00, 0x53E17249, 0xA8B2DA89, 0xFB68933B, 0xF0030A00, 0x5FF35C55, 0xA6ACFAA5, 0xF956AF09};
MYALIGN const unsigned int _k_sb4[] = {0x3FD64100, 0xE1E937A0, 0x49087E9F, 0xA876DE97, 0xC393EA00, 0x3D50AED7, 0x876D2914, 0xBA44FE79};
MYALIGN const unsigned int _k_sb5[] = {0xF4867F00, 0x5072D62F, 0x5D228BDB, 0x0DA9A4F9, 0x3971C900, 0x0B487AC2, 0x8A43F0FB, 0x81B332B8};
MYALIGN const unsigned int _k_sb7[] = {0xFFF75B00, 0xB20845E9, 0xE1BAA416, 0x531E4DAC, 0x3390E000, 0x62A3F282, 0x21C1D3B1, 0x43125170};
MYALIGN const unsigned int _k_sbo[] = {0x6FBDC700, 0xD0D26D17, 0xC502A878, 0x15AABF7A, 0x5FBB6A00, 0xCFE474A5, 0x412B35FA, 0x8E1E90D1};
MYALIGN const unsigned int _k_h63[] = {0x63636363, 0x63636363, 0x63636363, 0x63636363};
MYALIGN const unsigned int _k_hc6[] = {0xc6c6c6c6, 0xc6c6c6c6, 0xc6c6c6c6, 0xc6c6c6c6};
MYALIGN const unsigned int _k_h5b[] = {0x5b5b5b5b, 0x5b5b5b5b, 0x5b5b5b5b, 0x5b5b5b5b};
MYALIGN const unsigned int _k_h4e[] = {0x4e4e4e4e, 0x4e4e4e4e, 0x4e4e4e4e, 0x4e4e4e4e};
MYALIGN const unsigned int _k_h0e[] = {0x0e0e0e0e, 0x0e0e0e0e, 0x0e0e0e0e, 0x0e0e0e0e};
MYALIGN const unsigned int _k_h15[] = {0x15151515, 0x15151515, 0x15151515, 0x15151515};
MYALIGN const unsigned int _k_aesmix1[] = {0x0f0a0500, 0x030e0904, 0x07020d08, 0x0b06010c};
MYALIGN const unsigned int _k_aesmix2[] = {0x000f0a05, 0x04030e09, 0x0807020d, 0x0c0b0601};
MYALIGN const unsigned int _k_aesmix3[] = {0x05000f0a, 0x0904030e, 0x0d080702, 0x010c0b06};
MYALIGN const unsigned int _k_aesmix4[] = {0x0a05000f, 0x0e090403, 0x020d0807, 0x06010c0b};


MYALIGN const unsigned int 	const1[]		= {0x00000001, 0x00000000, 0x00000000, 0x00000000};
MYALIGN const unsigned int	mul2mask[]		= {0x00001b00, 0x00000000, 0x00000000, 0x00000000};
MYALIGN const unsigned int	lsbmask[]		= {0x01010101, 0x01010101, 0x01010101, 0x01010101};
MYALIGN const unsigned int	invshiftrows[]	= {0x070a0d00, 0x0b0e0104, 0x0f020508, 0x0306090c};
MYALIGN const unsigned int	zero[]			= {0x00000000, 0x00000000, 0x00000000, 0x00000000};
MYALIGN const unsigned int	mul2ipt[]		= {0x728efc00, 0x6894e61a, 0x3fc3b14d, 0x25d9ab57, 0xfd5ba600, 0x2a8c71d7, 0x1eb845e3, 0xc96f9234};


#define ECHO_SUBBYTES4(state, j) \
   state[0][j] = _mm_aesenc_si128(state[0][j], k1);\
   k1 = _mm_add_epi32(k1, M128(const1));\
   state[1][j] = _mm_aesenc_si128(state[1][j], k1);\
   k1 = _mm_add_epi32(k1, M128(const1));\
   state[2][j] = _mm_aesenc_si128(state[2][j], k1);\
   k1 = _mm_add_epi32(k1, M128(const1));\
   state[3][j] = _mm_aesenc_si128(state[3][j], k1);\
   k1 = _mm_add_epi32(k1, M128(const1));\
   state[0][j] = _mm_aesenc_si128(state[0][j], m128_zero ); \
   state[1][j] = _mm_aesenc_si128(state[1][j], m128_zero ); \
   state[2][j] = _mm_aesenc_si128(state[2][j], m128_zero ); \
   state[3][j] = _mm_aesenc_si128(state[3][j], m128_zero )

#define ECHO_SUBBYTES(state, i, j) \
	state[i][j] = _mm_aesenc_si128(state[i][j], k1);\
   k1 = _mm_add_epi32(k1, M128(const1));\
	state[i][j] = _mm_aesenc_si128(state[i][j], M128(zero))

#define ECHO_MIXBYTES(state1, state2, j, t1, t2, s2) \
	s2 = _mm_add_epi8(state1[0][j], state1[0][j]);\
	t1 = _mm_srli_epi16(state1[0][j], 7);\
	t1 = _mm_and_si128(t1, M128(lsbmask));\
	t2 = _mm_shuffle_epi8(M128(mul2mask), t1);\
	s2 = _mm_xor_si128(s2, t2);\
	state2[0][j] = s2;\
	state2[1][j] = state1[0][j];\
	state2[2][j] = state1[0][j];\
	state2[3][j] = _mm_xor_si128(s2, state1[0][j]);\
	s2 = _mm_add_epi8(state1[1][(j + 1) & 3], state1[1][(j + 1) & 3]);\
	t1 = _mm_srli_epi16(state1[1][(j + 1) & 3], 7);\
	t1 = _mm_and_si128(t1, M128(lsbmask));\
	t2 = _mm_shuffle_epi8(M128(mul2mask), t1);\
	s2 = _mm_xor_si128(s2, t2);\
	state2[0][j] = mm128_xor3(state2[0][j], s2, state1[1][(j + 1) & 3] );\
	state2[1][j] = _mm_xor_si128(state2[1][j], s2);\
	state2[2][j] = _mm_xor_si128(state2[2][j], state1[1][(j + 1) & 3]);\
	state2[3][j] = _mm_xor_si128(state2[3][j], state1[1][(j + 1) & 3]);\
	s2 = _mm_add_epi8(state1[2][(j + 2) & 3], state1[2][(j + 2) & 3]);\
	t1 = _mm_srli_epi16(state1[2][(j + 2) & 3], 7);\
	t1 = _mm_and_si128(t1, M128(lsbmask));\
	t2 = _mm_shuffle_epi8(M128(mul2mask), t1);\
	s2 = _mm_xor_si128(s2, t2);\
	state2[0][j] = _mm_xor_si128(state2[0][j], state1[2][(j + 2) & 3]);\
	state2[1][j] = mm128_xor3(state2[1][j], s2, state1[2][(j + 2) & 3] );\
	state2[2][j] = _mm_xor_si128(state2[2][j], s2);\
	state2[3][j] = _mm_xor_si128(state2[3][j], state1[2][(j + 2) & 3]);\
	s2 = _mm_add_epi8(state1[3][(j + 3) & 3], state1[3][(j + 3) & 3]);\
	t1 = _mm_srli_epi16(state1[3][(j + 3) & 3], 7);\
	t1 = _mm_and_si128(t1, M128(lsbmask));\
	t2 = _mm_shuffle_epi8(M128(mul2mask), t1);\
	s2 = _mm_xor_si128(s2, t2);\
	state2[0][j] = _mm_xor_si128(state2[0][j], state1[3][(j + 3) & 3]);\
	state2[1][j] = _mm_xor_si128(state2[1][j], state1[3][(j + 3) & 3]);\
	state2[2][j] = mm128_xor3(state2[2][j], s2, state1[3][(j + 3) & 3] );\
	state2[3][j] = _mm_xor_si128(state2[3][j], s2)


#define ECHO_ROUND_UNROLL2 \
   ECHO_SUBBYTES4(_state, 0);\
   ECHO_SUBBYTES4(_state, 1);\
   ECHO_SUBBYTES4(_state, 2);\
   ECHO_SUBBYTES4(_state, 3);\
   ECHO_MIXBYTES(_state, _state2, 0, t1, t2, s2);\
   ECHO_MIXBYTES(_state, _state2, 1, t1, t2, s2);\
   ECHO_MIXBYTES(_state, _state2, 2, t1, t2, s2);\
   ECHO_MIXBYTES(_state, _state2, 3, t1, t2, s2);\
   ECHO_SUBBYTES4(_state2, 0);\
   ECHO_SUBBYTES4(_state2, 1);\
   ECHO_SUBBYTES4(_state2, 2);\
   ECHO_SUBBYTES4(_state2, 3);\
   ECHO_MIXBYTES(_state2, _state, 0, t1, t2, s2);\
   ECHO_MIXBYTES(_state2, _state, 1, t1, t2, s2);\
   ECHO_MIXBYTES(_state2, _state, 2, t1, t2, s2);\
   ECHO_MIXBYTES(_state2, _state, 3, t1, t2, s2)

/*
#define ECHO_ROUND_UNROLL2 \
	ECHO_SUBBYTES(_state, 0, 0);\
	ECHO_SUBBYTES(_state, 1, 0);\
	ECHO_SUBBYTES(_state, 2, 0);\
	ECHO_SUBBYTES(_state, 3, 0);\
	ECHO_SUBBYTES(_state, 0, 1);\
	ECHO_SUBBYTES(_state, 1, 1);\
	ECHO_SUBBYTES(_state, 2, 1);\
	ECHO_SUBBYTES(_state, 3, 1);\
	ECHO_SUBBYTES(_state, 0, 2);\
	ECHO_SUBBYTES(_state, 1, 2);\
	ECHO_SUBBYTES(_state, 2, 2);\
	ECHO_SUBBYTES(_state, 3, 2);\
	ECHO_SUBBYTES(_state, 0, 3);\
	ECHO_SUBBYTES(_state, 1, 3);\
	ECHO_SUBBYTES(_state, 2, 3);\
	ECHO_SUBBYTES(_state, 3, 3);\
	ECHO_MIXBYTES(_state, _state2, 0, t1, t2, s2);\
	ECHO_MIXBYTES(_state, _state2, 1, t1, t2, s2);\
	ECHO_MIXBYTES(_state, _state2, 2, t1, t2, s2);\
	ECHO_MIXBYTES(_state, _state2, 3, t1, t2, s2);\
	ECHO_SUBBYTES(_state2, 0, 0);\
	ECHO_SUBBYTES(_state2, 1, 0);\
	ECHO_SUBBYTES(_state2, 2, 0);\
	ECHO_SUBBYTES(_state2, 3, 0);\
	ECHO_SUBBYTES(_state2, 0, 1);\
	ECHO_SUBBYTES(_state2, 1, 1);\
	ECHO_SUBBYTES(_state2, 2, 1);\
	ECHO_SUBBYTES(_state2, 3, 1);\
	ECHO_SUBBYTES(_state2, 0, 2);\
	ECHO_SUBBYTES(_state2, 1, 2);\
	ECHO_SUBBYTES(_state2, 2, 2);\
	ECHO_SUBBYTES(_state2, 3, 2);\
	ECHO_SUBBYTES(_state2, 0, 3);\
	ECHO_SUBBYTES(_state2, 1, 3);\
	ECHO_SUBBYTES(_state2, 2, 3);\
	ECHO_SUBBYTES(_state2, 3, 3);\
	ECHO_MIXBYTES(_state2, _state, 0, t1, t2, s2);\
	ECHO_MIXBYTES(_state2, _state, 1, t1, t2, s2);\
	ECHO_MIXBYTES(_state2, _state, 2, t1, t2, s2);\
	ECHO_MIXBYTES(_state2, _state, 3, t1, t2, s2)
*/


#define SAVESTATE(dst, src)\
	dst[0][0] = src[0][0];\
	dst[0][1] = src[0][1];\
	dst[0][2] = src[0][2];\
	dst[0][3] = src[0][3];\
	dst[1][0] = src[1][0];\
	dst[1][1] = src[1][1];\
	dst[1][2] = src[1][2];\
	dst[1][3] = src[1][3];\
	dst[2][0] = src[2][0];\
	dst[2][1] = src[2][1];\
	dst[2][2] = src[2][2];\
	dst[2][3] = src[2][3];\
	dst[3][0] = src[3][0];\
	dst[3][1] = src[3][1];\
	dst[3][2] = src[3][2];\
	dst[3][3] = src[3][3]


void Compress(hashState_echo *ctx, const unsigned char *pmsg, unsigned int uBlockCount)
{
   unsigned int r, b, i, j;
   __m128i t1, t2, s2, k1;
   __m128i _state[4][4], _state2[4][4], _statebackup[4][4]; 

   for(i = 0; i < 4; i++)
	for(j = 0; j < ctx->uHashSize / 256; j++)
		_state[i][j] = ctx->state[i][j];

   for(b = 0; b < uBlockCount; b++)
   {
   	ctx->k = _mm_add_epi64(ctx->k, ctx->const1536);

   	// load message
	   for(j = ctx->uHashSize / 256; j < 4; j++)
	   {
	      for(i = 0; i < 4; i++)
	      {
		     _state[i][j] = _mm_load_si128((__m128i*)pmsg + 4 * (j - (ctx->uHashSize / 256)) + i);
	      }
	   }

	   // save state
	   SAVESTATE(_statebackup, _state);

	   k1 = ctx->k;

	   for(r = 0; r < ctx->uRounds / 2; r++)
   	{
	   	ECHO_ROUND_UNROLL2;
	   }
		
	   if(ctx->uHashSize == 256)
	   {
	      for(i = 0; i < 4; i++)
	      {
		      _state[i][0] = _mm_xor_si128(_state[i][0], _state[i][1]);
		      _state[i][0] = _mm_xor_si128(_state[i][0], _state[i][2]);
		      _state[i][0] = _mm_xor_si128(_state[i][0], _state[i][3]);
		      _state[i][0] = _mm_xor_si128(_state[i][0], _statebackup[i][0]);
		      _state[i][0] = _mm_xor_si128(_state[i][0], _statebackup[i][1]);
		      _state[i][0] = _mm_xor_si128(_state[i][0], _statebackup[i][2]);
		      _state[i][0] = _mm_xor_si128(_state[i][0], _statebackup[i][3]);
	      }
	   }
	   else
    	{
	      for(i = 0; i < 4; i++)
	      {
      		_state[i][0] = _mm_xor_si128(_state[i][0], _state[i][2]);
		      _state[i][1] = _mm_xor_si128(_state[i][1], _state[i][3]);
		      _state[i][0] = _mm_xor_si128(_state[i][0], _statebackup[i][0]);
		      _state[i][0] = _mm_xor_si128(_state[i][0], _statebackup[i][2]);
		      _state[i][1] = _mm_xor_si128(_state[i][1], _statebackup[i][1]);
		      _state[i][1] = _mm_xor_si128(_state[i][1], _statebackup[i][3]);
         }
   	}
	   pmsg += ctx->uBlockLength;
   }
	SAVESTATE(ctx->state, _state);

}



HashReturn init_echo(hashState_echo *ctx, int nHashSize)
{
	int i, j;

        ctx->k = _mm_setzero_si128(); 
	ctx->processed_bits = 0;
	ctx->uBufferBytes = 0;

	switch(nHashSize)
	{
		case 256:
			ctx->uHashSize = 256;
			ctx->uBlockLength = 192;
			ctx->uRounds = 8;
			ctx->hashsize = _mm_set_epi32(0, 0, 0, 0x00000100);
			ctx->const1536 = _mm_set_epi32(0x00000000, 0x00000000, 0x00000000, 0x00000600);
			break;

		case 512:
			ctx->uHashSize = 512;
			ctx->uBlockLength = 128;
			ctx->uRounds = 10;
			ctx->hashsize = _mm_set_epi32(0, 0, 0, 0x00000200);
			ctx->const1536 = _mm_set_epi32(0x00000000, 0x00000000, 0x00000000, 0x00000400);
			break;

		default:
			return BAD_HASHBITLEN;
	}


	for(i = 0; i < 4; i++)
		for(j = 0; j < nHashSize / 256; j++)
			ctx->state[i][j] = ctx->hashsize;

	for(i = 0; i < 4; i++)
		for(j = nHashSize / 256; j < 4; j++)
			ctx->state[i][j] = _mm_set_epi32(0, 0, 0, 0);

	return SUCCESS;
}

HashReturn update_echo(hashState_echo *state, const BitSequence *data, DataLength databitlen)
{
	unsigned int uByteLength, uBlockCount, uRemainingBytes;

	uByteLength = (unsigned int)(databitlen / 8);

	if((state->uBufferBytes + uByteLength) >= state->uBlockLength)
	{
		if(state->uBufferBytes != 0)
		{
			// Fill the buffer
			memcpy(state->buffer + state->uBufferBytes, (void*)data, state->uBlockLength - state->uBufferBytes);

			// Process buffer
			Compress(state, state->buffer, 1);
			state->processed_bits += state->uBlockLength * 8;

			data += state->uBlockLength - state->uBufferBytes;
			uByteLength -= state->uBlockLength - state->uBufferBytes;
		}

		// buffer now does not contain any unprocessed bytes

		uBlockCount = uByteLength / state->uBlockLength;
		uRemainingBytes = uByteLength % state->uBlockLength;

		if(uBlockCount > 0)
		{
			Compress(state, data, uBlockCount);

			state->processed_bits += uBlockCount * state->uBlockLength * 8;
			data += uBlockCount * state->uBlockLength;
		}

		if(uRemainingBytes > 0)
		{
			memcpy(state->buffer, (void*)data, uRemainingBytes);
		}

		state->uBufferBytes = uRemainingBytes;
	}
	else
	{
		memcpy(state->buffer + state->uBufferBytes, (void*)data, uByteLength);
		state->uBufferBytes += uByteLength;
	}

	return SUCCESS;
}

HashReturn final_echo(hashState_echo *state, BitSequence *hashval)
{
	__m128i remainingbits;

	// Add remaining bytes in the buffer
	state->processed_bits += state->uBufferBytes * 8;

	remainingbits = _mm_set_epi32(0, 0, 0, state->uBufferBytes * 8);

	// Pad with 0x80
	state->buffer[state->uBufferBytes++] = 0x80;
	
	// Enough buffer space for padding in this block?
	if((state->uBlockLength - state->uBufferBytes) >= 18)
	{
		// Pad with zeros
		memset(state->buffer + state->uBufferBytes, 0, state->uBlockLength - (state->uBufferBytes + 18));

		// Hash size
		*((unsigned short*)(state->buffer + state->uBlockLength - 18)) = state->uHashSize;

		// Processed bits
		*((DataLength*)(state->buffer + state->uBlockLength - 16)) = state->processed_bits;
		*((DataLength*)(state->buffer + state->uBlockLength - 8)) = 0;

		// Last block contains message bits?
		if(state->uBufferBytes == 1)
		{
			state->k = _mm_xor_si128(state->k, state->k);
			state->k = _mm_sub_epi64(state->k, state->const1536);
		}
		else
		{
			state->k = _mm_add_epi64(state->k, remainingbits);
			state->k = _mm_sub_epi64(state->k, state->const1536);
		}

		// Compress
		Compress(state, state->buffer, 1);
	}
	else
	{
		// Fill with zero and compress
		memset(state->buffer + state->uBufferBytes, 0, state->uBlockLength - state->uBufferBytes);
		state->k = _mm_add_epi64(state->k, remainingbits);
		state->k = _mm_sub_epi64(state->k, state->const1536);
		Compress(state, state->buffer, 1);

		// Last block
		memset(state->buffer, 0, state->uBlockLength - 18);

		// Hash size
		*((unsigned short*)(state->buffer + state->uBlockLength - 18)) = state->uHashSize;

		// Processed bits
		*((DataLength*)(state->buffer + state->uBlockLength - 16)) = state->processed_bits;
		*((DataLength*)(state->buffer + state->uBlockLength - 8)) = 0;

		// Compress the last block
		state->k = _mm_xor_si128(state->k, state->k);
		state->k = _mm_sub_epi64(state->k, state->const1536);
		Compress(state, state->buffer, 1);
	}

	// Store the hash value
	_mm_store_si128((__m128i*)hashval + 0, state->state[0][0]);
	_mm_store_si128((__m128i*)hashval + 1, state->state[1][0]);

	if(state->uHashSize == 512)
	{
		_mm_store_si128((__m128i*)hashval + 2, state->state[2][0]);
		_mm_store_si128((__m128i*)hashval + 3, state->state[3][0]);
	}

	return SUCCESS;
}

HashReturn update_final_echo( hashState_echo *state, BitSequence *hashval,
                              const BitSequence *data, DataLength databitlen )
{
   unsigned int uByteLength, uBlockCount, uRemainingBytes;

   uByteLength = (unsigned int)(databitlen / 8);

   if( (state->uBufferBytes + uByteLength) >= state->uBlockLength )
   {
        if( state->uBufferBytes != 0 )
        {
           // Fill the buffer
           memcpy( state->buffer + state->uBufferBytes,
                   (void*)data, state->uBlockLength - state->uBufferBytes );

           // Process buffer
           Compress( state, state->buffer, 1 );
           state->processed_bits += state->uBlockLength * 8;

           data += state->uBlockLength - state->uBufferBytes;
           uByteLength -= state->uBlockLength - state->uBufferBytes;
        }

        // buffer now does not contain any unprocessed bytes

        uBlockCount = uByteLength / state->uBlockLength;
        uRemainingBytes = uByteLength % state->uBlockLength;

        if( uBlockCount > 0 )
        {
           Compress( state, data, uBlockCount );
           state->processed_bits += uBlockCount * state->uBlockLength * 8;
           data += uBlockCount * state->uBlockLength;
        }

        if( uRemainingBytes > 0 )
        memcpy(state->buffer, (void*)data, uRemainingBytes);

        state->uBufferBytes = uRemainingBytes;
   }
   else
   {
        memcpy( state->buffer + state->uBufferBytes, (void*)data, uByteLength );
        state->uBufferBytes += uByteLength;
   }

   __m128i remainingbits;

   // Add remaining bytes in the buffer
   state->processed_bits += state->uBufferBytes * 8;

   remainingbits = _mm_set_epi32( 0, 0, 0, state->uBufferBytes * 8 );

   // Pad with 0x80
   state->buffer[state->uBufferBytes++] = 0x80;
   // Enough buffer space for padding in this block?
   if( (state->uBlockLength - state->uBufferBytes) >= 18 )
   {
        // Pad with zeros
        memset( state->buffer + state->uBufferBytes, 0, state->uBlockLength - (state->uBufferBytes + 18) );

        // Hash size
        *( (unsigned short*)(state->buffer + state->uBlockLength - 18) ) = state->uHashSize;

        // Processed bits
        *( (DataLength*)(state->buffer + state->uBlockLength - 16) ) =
                   state->processed_bits;
        *( (DataLength*)(state->buffer + state->uBlockLength - 8) ) = 0;

        // Last block contains message bits?
        if( state->uBufferBytes == 1 )
        {
           state->k = _mm_xor_si128( state->k, state->k );
           state->k = _mm_sub_epi64( state->k, state->const1536 );
        }
        else
        {
           state->k = _mm_add_epi64( state->k, remainingbits );
           state->k = _mm_sub_epi64( state->k, state->const1536 );
        }

        // Compress
        Compress( state, state->buffer, 1 );
   }
   else
   {
        // Fill with zero and compress
        memset( state->buffer + state->uBufferBytes, 0,
                state->uBlockLength - state->uBufferBytes );
        state->k = _mm_add_epi64( state->k, remainingbits );
        state->k = _mm_sub_epi64( state->k, state->const1536 );
        Compress( state, state->buffer, 1 );

        // Last block
        memset( state->buffer, 0, state->uBlockLength - 18 );

        // Hash size
        *( (unsigned short*)(state->buffer + state->uBlockLength - 18) ) =
                 state->uHashSize;

        // Processed bits
        *( (DataLength*)(state->buffer + state->uBlockLength - 16) ) =
                   state->processed_bits;
        *( (DataLength*)(state->buffer + state->uBlockLength - 8) ) = 0;
        // Compress the last block
        state->k = _mm_xor_si128( state->k, state->k );
        state->k = _mm_sub_epi64( state->k, state->const1536 );
        Compress( state, state->buffer, 1) ;
   }

   // Store the hash value
   _mm_store_si128( (__m128i*)hashval + 0, state->state[0][0] );
   _mm_store_si128( (__m128i*)hashval + 1, state->state[1][0] );

   if( state->uHashSize == 512 )
   {
        _mm_store_si128( (__m128i*)hashval + 2, state->state[2][0] );
        _mm_store_si128( (__m128i*)hashval + 3, state->state[3][0] );

   }
   return SUCCESS;
}

HashReturn echo_full( hashState_echo *state, BitSequence *hashval,
            int nHashSize, const BitSequence *data, DataLength datalen )
{
   int i, j;

   state->k = m128_zero;
   state->processed_bits = 0;
   state->uBufferBytes = 0;

   switch( nHashSize )
   {
      case 256:
         state->uHashSize = 256;
         state->uBlockLength = 192;
         state->uRounds = 8;
         state->hashsize = m128_const_64( 0, 0x100 );
         state->const1536 = m128_const_64( 0, 0x600 );
         break;

      case 512:
         state->uHashSize = 512;
         state->uBlockLength = 128;
         state->uRounds = 10;
         state->hashsize = m128_const_64( 0, 0x200 );
         state->const1536 = m128_const_64( 0, 0x400 );
         break;

      default:
         return BAD_HASHBITLEN;
   }

   for(i = 0; i < 4; i++)
      for(j = 0; j < nHashSize / 256; j++)
         state->state[i][j] = state->hashsize;

   for(i = 0; i < 4; i++)
      for(j = nHashSize / 256; j < 4; j++)
         state->state[i][j] = m128_zero;


   unsigned int uBlockCount, uRemainingBytes;

   if( (state->uBufferBytes + datalen) >= state->uBlockLength )
   {
        if( state->uBufferBytes != 0 )
        {
           // Fill the buffer
           memcpy( state->buffer + state->uBufferBytes,
                   (void*)data, state->uBlockLength - state->uBufferBytes );

           // Process buffer
           Compress( state, state->buffer, 1 );
           state->processed_bits += state->uBlockLength * 8;

           data += state->uBlockLength - state->uBufferBytes;
           datalen -= state->uBlockLength - state->uBufferBytes;
        }

        // buffer now does not contain any unprocessed bytes

        uBlockCount = datalen / state->uBlockLength;
        uRemainingBytes = datalen % state->uBlockLength;

        if( uBlockCount > 0 )
        {
           Compress( state, data, uBlockCount );
           state->processed_bits += uBlockCount * state->uBlockLength * 8;
           data += uBlockCount * state->uBlockLength;
        }

        if( uRemainingBytes > 0 )
        memcpy(state->buffer, (void*)data, uRemainingBytes);

        state->uBufferBytes = uRemainingBytes;
   }
   else
   {
        memcpy( state->buffer + state->uBufferBytes, (void*)data, datalen );
        state->uBufferBytes += datalen;
   }

   __m128i remainingbits;

   // Add remaining bytes in the buffer
   state->processed_bits += state->uBufferBytes * 8;

   remainingbits = _mm_set_epi32( 0, 0, 0, state->uBufferBytes * 8 );

   // Pad with 0x80
   state->buffer[state->uBufferBytes++] = 0x80;
   // Enough buffer space for padding in this block?
   if( (state->uBlockLength - state->uBufferBytes) >= 18 )
   {
        // Pad with zeros
        memset( state->buffer + state->uBufferBytes, 0, state->uBlockLength - (state->uBufferBytes + 18) );

        // Hash size
        *( (unsigned short*)(state->buffer + state->uBlockLength - 18) ) = state->uHashSize;

        // Processed bits
        *( (DataLength*)(state->buffer + state->uBlockLength - 16) ) =
                   state->processed_bits;
        *( (DataLength*)(state->buffer + state->uBlockLength - 8) ) = 0;

        // Last block contains message bits?
        if( state->uBufferBytes == 1 )
        {
           state->k = _mm_xor_si128( state->k, state->k );
           state->k = _mm_sub_epi64( state->k, state->const1536 );
        }
        else
        {
           state->k = _mm_add_epi64( state->k, remainingbits );
           state->k = _mm_sub_epi64( state->k, state->const1536 );
        }

        // Compress
        Compress( state, state->buffer, 1 );
   }
   else
   {
        // Fill with zero and compress
        memset( state->buffer + state->uBufferBytes, 0,
                state->uBlockLength - state->uBufferBytes );
        state->k = _mm_add_epi64( state->k, remainingbits );
        state->k = _mm_sub_epi64( state->k, state->const1536 );
        Compress( state, state->buffer, 1 );

        // Last block
        memset( state->buffer, 0, state->uBlockLength - 18 );

        // Hash size
        *( (unsigned short*)(state->buffer + state->uBlockLength - 18) ) =
                 state->uHashSize;

        // Processed bits
        *( (DataLength*)(state->buffer + state->uBlockLength - 16) ) =
                   state->processed_bits;
        *( (DataLength*)(state->buffer + state->uBlockLength - 8) ) = 0;
        // Compress the last block
        state->k = _mm_xor_si128( state->k, state->k );
        state->k = _mm_sub_epi64( state->k, state->const1536 );
        Compress( state, state->buffer, 1) ;
   }

   // Store the hash value
   _mm_store_si128( (__m128i*)hashval + 0, state->state[0][0] );
   _mm_store_si128( (__m128i*)hashval + 1, state->state[1][0] );

   if( state->uHashSize == 512 )
   {
        _mm_store_si128( (__m128i*)hashval + 2, state->state[2][0] );
        _mm_store_si128( (__m128i*)hashval + 3, state->state[3][0] );

   }
   return SUCCESS;
}



HashReturn hash_echo(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
	HashReturn hRet;
	hashState_echo hs;

	/////
	/*
	__m128i a, b, c, d, t[4], u[4], v[4];

	a = _mm_set_epi32(0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
	b = _mm_set_epi32(0x1f1e1d1c, 0x1b1a1918, 0x17161514, 0x13121110);
	c = _mm_set_epi32(0x2f2e2d2c, 0x2b2a2928, 0x27262524, 0x23222120);
	d = _mm_set_epi32(0x3f3e3d3c, 0x3b3a3938, 0x37363534, 0x33323130);

	t[0] = _mm_unpacklo_epi8(a, b);
	t[1] = _mm_unpackhi_epi8(a, b);
	t[2] = _mm_unpacklo_epi8(c, d);
	t[3] = _mm_unpackhi_epi8(c, d);

	u[0] = _mm_unpacklo_epi16(t[0], t[2]);
	u[1] = _mm_unpackhi_epi16(t[0], t[2]);
	u[2] = _mm_unpacklo_epi16(t[1], t[3]);
	u[3] = _mm_unpackhi_epi16(t[1], t[3]);


	t[0] = _mm_unpacklo_epi16(u[0], u[1]);
	t[1] = _mm_unpackhi_epi16(u[0], u[1]);
	t[2] = _mm_unpacklo_epi16(u[2], u[3]);
	t[3] = _mm_unpackhi_epi16(u[2], u[3]);

	u[0] = _mm_unpacklo_epi8(t[0], t[1]);
	u[1] = _mm_unpackhi_epi8(t[0], t[1]);
	u[2] = _mm_unpacklo_epi8(t[2], t[3]);
	u[3] = _mm_unpackhi_epi8(t[2], t[3]);

	a = _mm_unpacklo_epi8(u[0], u[1]);
	b = _mm_unpackhi_epi8(u[0], u[1]);
	c = _mm_unpacklo_epi8(u[2], u[3]);
	d = _mm_unpackhi_epi8(u[2], u[3]);
	*/
	/////

	hRet = init_echo(&hs, hashbitlen);
	if(hRet != SUCCESS)
		return hRet;

	hRet = update_echo(&hs, data, databitlen);
	if(hRet != SUCCESS)
		return hRet;

	hRet = final_echo(&hs, hashval);
	if(hRet != SUCCESS)
		return hRet;

	return SUCCESS;
}

#endif
