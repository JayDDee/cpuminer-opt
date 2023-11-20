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

#if defined(__AES__) || defined(__ARM_FEATURE_AES)

#include <memory.h>
#include "miner.h"
#include "hash_api.h"
#include "simd-utils.h"

const uint32_t	const1[]	      __attribute__ ((aligned (32))) =
   { 0x00000001, 0x00000000, 0x00000000, 0x00000000 };
const uint32_t	mul2mask[]     __attribute__ ((aligned (16))) =
   { 0x00001b00, 0x00000000, 0x00000000, 0x00000000 };
const uint32_t	lsbmask[]      __attribute__ ((aligned (16))) =
   { 0x01010101, 0x01010101, 0x01010101, 0x01010101 };
const uint32_t	invshiftrows[]	__attribute__ ((aligned (16))) =
   { 0x070a0d00, 0x0b0e0104, 0x0f020508, 0x0306090c };

#define ECHO_SUBBYTES4( state, j ) \
   state[0][j] = v128_aesenc( state[0][j], k1 ); \
   k1 = v128_add32( k1, cast_v128(const1) ); \
   state[1][j] = v128_aesenc( state[1][j], k1 ); \
   k1 = v128_add32( k1, cast_v128(const1) ); \
   state[2][j] = v128_aesenc( state[2][j], k1 ); \
   k1 = v128_add32( k1, cast_v128(const1) ); \
   state[3][j] = v128_aesenc( state[3][j], k1 ); \
   k1 = v128_add32( k1, cast_v128(const1) ); \
   state[0][j] = v128_aesenc_nokey( state[0][j] ); \
   state[1][j] = v128_aesenc_nokey( state[1][j] ); \
   state[2][j] = v128_aesenc_nokey( state[2][j] ); \
   state[3][j] = v128_aesenc_nokey( state[3][j] )

#define ECHO_SUBBYTES( state, i, j ) \
	state[i][j] = v128_aesenc( state[i][j], k1 ); \
   k1 = v128_add32( k1, cast_v128(const1) ); \
	state[i][j] = v128_aesenc_nokey( state[i][j] )

#define ECHO_MIXBYTES( state1, state2, j, t1, t2, s2 ) \
	s2 = v128_add8( state1[0][j], state1[0][j] ); \
	t1 = v128_sr16( state1[0][j], 7 ); \
	t1 = v128_and( t1, cast_v128(lsbmask) ); \
	t2 = v128_shuffle8( cast_v128(mul2mask), t1 ); \
	s2 = v128_xor( s2, t2 ); \
	state2[0][j] = s2; \
	state2[1][j] = state1[0][j]; \
	state2[2][j] = state1[0][j]; \
	state2[3][j] = v128_xor(s2, state1[0][j] ); \
	s2 = v128_add8( state1[1][(j + 1) & 3], state1[1][(j + 1) & 3] ); \
	t1 = v128_sr16( state1[1][(j + 1) & 3], 7 ); \
	t1 = v128_and( t1, cast_v128(lsbmask) ); \
	t2 = v128_shuffle8( cast_v128(mul2mask), t1 ); \
	s2 = v128_xor( s2, t2 ); \
	state2[0][j] = v128_xor3( state2[0][j], s2, state1[1][(j + 1) & 3] );\
	state2[1][j] = v128_xor( state2[1][j], s2 ); \
	state2[2][j] = v128_xor( state2[2][j], state1[1][(j + 1) & 3] ); \
	state2[3][j] = v128_xor( state2[3][j], state1[1][(j + 1) & 3] ); \
	s2 = v128_add8( state1[2][(j + 2) & 3], state1[2][(j + 2) & 3] ); \
	t1 = v128_sr16( state1[2][(j + 2) & 3], 7 ); \
	t1 = v128_and( t1, cast_v128(lsbmask) ); \
	t2 = v128_shuffle8( cast_v128(mul2mask), t1 ); \
	s2 = v128_xor( s2, t2 ); \
	state2[0][j] = v128_xor( state2[0][j], state1[2][(j + 2) & 3] ); \
	state2[1][j] = v128_xor3( state2[1][j], s2, state1[2][(j + 2) & 3] ); \
	state2[2][j] = v128_xor( state2[2][j], s2 ); \
	state2[3][j] = v128_xor( state2[3][j], state1[2][(j + 2) & 3] ); \
	s2 = v128_add8( state1[3][(j + 3) & 3], state1[3][(j + 3) & 3] ); \
	t1 = v128_sr16( state1[3][(j + 3) & 3], 7 ); \
	t1 = v128_and( t1, cast_v128(lsbmask) ); \
	t2 = v128_shuffle8( cast_v128(mul2mask), t1 ); \
	s2 = v128_xor( s2, t2 ); \
	state2[0][j] = v128_xor( state2[0][j], state1[3][(j + 3) & 3] ); \
	state2[1][j] = v128_xor( state2[1][j], state1[3][(j + 3) & 3] ); \
	state2[2][j] = v128_xor3( state2[2][j], s2, state1[3][(j + 3) & 3] ); \
	state2[3][j] = v128_xor( state2[3][j], s2 )


#define ECHO_ROUND_UNROLL2 \
{ \
   ECHO_SUBBYTES4( _state, 0 ); \
   ECHO_SUBBYTES4( _state, 1 ); \
   ECHO_SUBBYTES4( _state, 2 ); \
   ECHO_SUBBYTES4( _state, 3 ); \
   ECHO_MIXBYTES( _state, _state2, 0, t1, t2, s2 ); \
   ECHO_MIXBYTES( _state, _state2, 1, t1, t2, s2 ); \
   ECHO_MIXBYTES( _state, _state2, 2, t1, t2, s2 ); \
   ECHO_MIXBYTES( _state, _state2, 3, t1, t2, s2 ); \
   ECHO_SUBBYTES4( _state2, 0 ); \
   ECHO_SUBBYTES4( _state2, 1 ); \
   ECHO_SUBBYTES4( _state2, 2 ); \
   ECHO_SUBBYTES4( _state2, 3 ); \
   ECHO_MIXBYTES( _state2, _state, 0, t1, t2, s2 ); \
   ECHO_MIXBYTES( _state2, _state, 1, t1, t2, s2 ); \
   ECHO_MIXBYTES( _state2, _state, 2, t1, t2, s2 ); \
   ECHO_MIXBYTES( _state2, _state, 3, t1, t2, s2 ); \
}

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
   v128_t t1, t2, s2, k1;
   v128_t _state[4][4], _state2[4][4], _statebackup[4][4]; 

   for(i = 0; i < 4; i++)
	for(j = 0; j < ctx->uHashSize / 256; j++)
		_state[i][j] = ctx->state[i][j];

   for(b = 0; b < uBlockCount; b++)
   {
   	ctx->k = v128_add64(ctx->k, ctx->const1536);

   	// load message
	   for(j = ctx->uHashSize / 256; j < 4; j++)
	   {
	      for(i = 0; i < 4; i++)
	      {
		     _state[i][j] = v128_load((v128_t*)pmsg + 4 * (j - (ctx->uHashSize / 256)) + i);
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
		      _state[i][0] = v128_xor(_state[i][0], _state[i][1]);
		      _state[i][0] = v128_xor(_state[i][0], _state[i][2]);
		      _state[i][0] = v128_xor(_state[i][0], _state[i][3]);
		      _state[i][0] = v128_xor(_state[i][0], _statebackup[i][0]);
		      _state[i][0] = v128_xor(_state[i][0], _statebackup[i][1]);
		      _state[i][0] = v128_xor(_state[i][0], _statebackup[i][2]);
		      _state[i][0] = v128_xor(_state[i][0], _statebackup[i][3]);
	      }
	   }
	   else
    	{
	      for(i = 0; i < 4; i++)
	      {
      		_state[i][0] = v128_xor(_state[i][0], _state[i][2]);
		      _state[i][1] = v128_xor(_state[i][1], _state[i][3]);
		      _state[i][0] = v128_xor(_state[i][0], _statebackup[i][0]);
		      _state[i][0] = v128_xor(_state[i][0], _statebackup[i][2]);
		      _state[i][1] = v128_xor(_state[i][1], _statebackup[i][1]);
		      _state[i][1] = v128_xor(_state[i][1], _statebackup[i][3]);
         }
   	}
	   pmsg += ctx->uBlockLength;
   }
	SAVESTATE(ctx->state, _state);

}

HashReturn init_echo( hashState_echo *ctx, int nHashSize )
{
	int i, j;

        ctx->k = v128_zero; 
	ctx->processed_bits = 0;
	ctx->uBufferBytes = 0;

	switch(nHashSize)
	{
		case 256:
			ctx->uHashSize = 256;
			ctx->uBlockLength = 192;
			ctx->uRounds = 8;
			ctx->hashsize = v128_set32(0, 0, 0, 0x00000100);
			ctx->const1536 = v128_set32(0x00000000, 0x00000000, 0x00000000, 0x00000600);
			break;

		case 512:
			ctx->uHashSize = 512;
			ctx->uBlockLength = 128;
			ctx->uRounds = 10;
			ctx->hashsize = v128_set32(0, 0, 0, 0x00000200);
			ctx->const1536 = v128_set32(0x00000000, 0x00000000, 0x00000000, 0x00000400);
			break;

		default:
			return BAD_HASHBITLEN;
	}


	for(i = 0; i < 4; i++)
		for(j = 0; j < nHashSize / 256; j++)
			ctx->state[i][j] = ctx->hashsize;

	for(i = 0; i < 4; i++)
		for(j = nHashSize / 256; j < 4; j++)
			ctx->state[i][j] = v128_set32(0, 0, 0, 0);

	return SUCCESS;
}

HashReturn update_echo( hashState_echo *state, const void *data,
                        uint32_t databitlen )
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

HashReturn final_echo( hashState_echo *state, void *hashval)
{
	v128_t remainingbits;

	// Add remaining bytes in the buffer
	state->processed_bits += state->uBufferBytes * 8;

	remainingbits = v128_set32(0, 0, 0, state->uBufferBytes * 8);

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
			state->k = v128_xor(state->k, state->k);
			state->k = v128_sub64(state->k, state->const1536);
		}
		else
		{
			state->k = v128_add64(state->k, remainingbits);
			state->k = v128_sub64(state->k, state->const1536);
		}

		// Compress
		Compress(state, state->buffer, 1);
	}
	else
	{
		// Fill with zero and compress
		memset(state->buffer + state->uBufferBytes, 0, state->uBlockLength - state->uBufferBytes);
		state->k = v128_add64(state->k, remainingbits);
		state->k = v128_sub64(state->k, state->const1536);
		Compress(state, state->buffer, 1);

		// Last block
		memset(state->buffer, 0, state->uBlockLength - 18);

		// Hash size
		*((unsigned short*)(state->buffer + state->uBlockLength - 18)) = state->uHashSize;

		// Processed bits
		*((DataLength*)(state->buffer + state->uBlockLength - 16)) = state->processed_bits;
		*((DataLength*)(state->buffer + state->uBlockLength - 8)) = 0;

		// Compress the last block
		state->k = v128_xor(state->k, state->k);
		state->k = v128_sub64(state->k, state->const1536);
		Compress(state, state->buffer, 1);
	}

	// Store the hash value
	v128_store((v128_t*)hashval + 0, state->state[0][0]);
	v128_store((v128_t*)hashval + 1, state->state[1][0]);

	if(state->uHashSize == 512)
	{
		v128_store((v128_t*)hashval + 2, state->state[2][0]);
		v128_store((v128_t*)hashval + 3, state->state[3][0]);
	}

	return SUCCESS;
}

HashReturn update_final_echo( hashState_echo *state, void *hashval,
                              const void *data, uint32_t databitlen )
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

   v128_t remainingbits;

   // Add remaining bytes in the buffer
   state->processed_bits += state->uBufferBytes * 8;

   remainingbits = v128_set32( 0, 0, 0, state->uBufferBytes * 8 );

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
           state->k = v128_xor( state->k, state->k );
           state->k = v128_sub64( state->k, state->const1536 );
        }
        else
        {
           state->k = v128_add64( state->k, remainingbits );
           state->k = v128_sub64( state->k, state->const1536 );
        }

        // Compress
        Compress( state, state->buffer, 1 );
   }
   else
   {
        // Fill with zero and compress
        memset( state->buffer + state->uBufferBytes, 0,
                state->uBlockLength - state->uBufferBytes );
        state->k = v128_add64( state->k, remainingbits );
        state->k = v128_sub64( state->k, state->const1536 );
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
        state->k = v128_xor( state->k, state->k );
        state->k = v128_sub64( state->k, state->const1536 );
        Compress( state, state->buffer, 1) ;
   }

   // Store the hash value
   v128_store( (v128_t*)hashval + 0, state->state[0][0] );
   v128_store( (v128_t*)hashval + 1, state->state[1][0] );

   if( state->uHashSize == 512 )
   {
        v128_store( (v128_t*)hashval + 2, state->state[2][0] );
        v128_store( (v128_t*)hashval + 3, state->state[3][0] );

   }
   return SUCCESS;
}

HashReturn echo_full( hashState_echo *state, void *hashval,
            int nHashSize, const void *data, uint32_t datalen )
{
   int i, j;

   state->k = v128_zero;
   state->processed_bits = 0;
   state->uBufferBytes = 0;

   switch( nHashSize )
   {
      case 256:
         state->uHashSize = 256;
         state->uBlockLength = 192;
         state->uRounds = 8;
         state->hashsize = v128_set64( 0, 0x100 );
         state->const1536 = v128_set64( 0, 0x600 );
         break;

      case 512:
         state->uHashSize = 512;
         state->uBlockLength = 128;
         state->uRounds = 10;
         state->hashsize = v128_set64( 0, 0x200 );
         state->const1536 = v128_set64( 0, 0x400 );
         break;

      default:
         return BAD_HASHBITLEN;
   }

   for(i = 0; i < 4; i++)
      for(j = 0; j < nHashSize / 256; j++)
         state->state[i][j] = state->hashsize;

   for(i = 0; i < 4; i++)
      for(j = nHashSize / 256; j < 4; j++)
         state->state[i][j] = v128_zero;


   unsigned int uBlockCount, uRemainingBytes;

   if( (state->uBufferBytes + datalen) >= state->uBlockLength )
   {
        if( state->uBufferBytes != 0 )
        {
           // Fill the buffer
           memcpy( state->buffer + state->uBufferBytes,
                   data, state->uBlockLength - state->uBufferBytes );

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
        memcpy(state->buffer, data, uRemainingBytes);

        state->uBufferBytes = uRemainingBytes;
   }
   else
   {
        memcpy( state->buffer + state->uBufferBytes, (void*)data, datalen );
        state->uBufferBytes += datalen;
   }

   v128_t remainingbits;

   // Add remaining bytes in the buffer
   state->processed_bits += state->uBufferBytes * 8;

   remainingbits = v128_set32( 0, 0, 0, state->uBufferBytes * 8 );

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
           state->k = v128_xor( state->k, state->k );
           state->k = v128_sub64( state->k, state->const1536 );
        }
        else
        {
           state->k = v128_add64( state->k, remainingbits );
           state->k = v128_sub64( state->k, state->const1536 );
        }

        // Compress
        Compress( state, state->buffer, 1 );
   }
   else
   {
        // Fill with zero and compress
        memset( state->buffer + state->uBufferBytes, 0,
                state->uBlockLength - state->uBufferBytes );
        state->k = v128_add64( state->k, remainingbits );
        state->k = v128_sub64( state->k, state->const1536 );
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
        state->k = v128_xor( state->k, state->k );
        state->k = v128_sub64( state->k, state->const1536 );
        Compress( state, state->buffer, 1) ;
   }

   // Store the hash value
   v128_store( (v128_t*)hashval + 0, state->state[0][0] );
   v128_store( (v128_t*)hashval + 1, state->state[1][0] );

   if( state->uHashSize == 512 )
   {
        v128_store( (v128_t*)hashval + 2, state->state[2][0] );
        v128_store( (v128_t*)hashval + 3, state->state[3][0] );

   }
   return SUCCESS;
}


#if 0
HashReturn hash_echo(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
	HashReturn hRet;
	hashState_echo hs;

	/////
	/*
	v128_t a, b, c, d, t[4], u[4], v[4];

	a = v128_set32(0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100);
	b = v128_set32(0x1f1e1d1c, 0x1b1a1918, 0x17161514, 0x13121110);
	c = v128_set32(0x2f2e2d2c, 0x2b2a2928, 0x27262524, 0x23222120);
	d = v128_set32(0x3f3e3d3c, 0x3b3a3938, 0x37363534, 0x33323130);

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

#endif
