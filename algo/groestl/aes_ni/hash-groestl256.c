/* hash.c     Aug 2011
 *
 * Groestl implementation for different versions.
 * Author: Krystian Matusiewicz, Günther A. Roland, Martin Schläffer
 *
 * This code is placed in the public domain
 */

#include <memory.h>
#include "hash-groestl256.h"
#include "miner.h"
#include "avxdefs.h"

#ifndef NO_AES_NI

#include "groestl-version.h"

#ifdef TASM
  #ifdef VAES
    #include "groestl256-asm-aes.h"
  #else
    #ifdef VAVX
      #include "groestl256-asm-avx.h"
    #else
      #ifdef VVPERM
        #include "groestl256-asm-vperm.h"
      #else
        #error NO VERSION SPECIFIED (-DV[AES/AVX/VVPERM])
      #endif
    #endif
  #endif
#else
  #ifdef TINTR
    #ifdef VAES
      #include "groestl256-intr-aes.h"
    #else
      #ifdef VAVX
        #include "groestl256-intr-avx.h"
      #else
        #ifdef VVPERM
          #include "groestl256-intr-vperm.h"
        #else
          #error NO VERSION SPECIFIED (-DV[AES/AVX/VVPERM])
        #endif
      #endif
    #endif
  #else
    #error NO TYPE SPECIFIED (-DT[ASM/INTR])
  #endif
#endif


/* digest up to len bytes of input (full blocks only) */
void Transform256(hashState_groestl256 *ctx,
	       const u8 *in, 
	       unsigned long long len) {
    /* increment block counter */
    ctx->block_counter += len/SIZE;

    /* digest message, one block at a time */
    for (; len >= SIZE; len -= SIZE, in += SIZE)
      TF512((u64*)ctx->chaining, (u64*)in);

    asm volatile ("emms");
}

/* given state h, do h <- P(h)+h */
void OutputTransformation256(hashState_groestl256 *ctx) {
    /* determine variant */
    OF512((u64*)ctx->chaining);

    asm volatile ("emms");
}

/* initialise context */
HashReturn_gr init_groestl256( hashState_groestl256* ctx, int hashlen )
{
  u8 i = 0;

  ctx->hashlen = hashlen;

  SET_CONSTANTS();

  for (i=0; i<SIZE/8; i++)
    ctx->chaining[i] = 0;
  for (i=0; i<SIZE; i++)
    ctx->buffer[i] = 0;

  if (ctx->chaining == NULL || ctx->buffer == NULL)
    return FAIL_GR;

  /* set initial value */
  ctx->chaining[COLS-1] = U64BIG((u64)256);

  INIT256(ctx->chaining);

  /* set other variables */
  ctx->buf_ptr = 0;
  ctx->block_counter = 0;

  return SUCCESS_GR;
}

HashReturn_gr reinit_groestl256(hashState_groestl256* ctx)
 {
  int i;
  for (i=0; i<SIZE/8; i++)
    ctx->chaining[i] = 0;
  for (i=0; i<SIZE; i++)
    ctx->buffer[i] = 0;

  if (ctx->chaining == NULL || ctx->buffer == NULL)
    return FAIL_GR;

  /* set initial value */
  ctx->chaining[COLS-1] = 256;

  INIT256(ctx->chaining);

  /* set other variables */
  ctx->buf_ptr = 0;
  ctx->block_counter = 0;

  return SUCCESS_GR;
}

HashReturn_gr update_groestl256( hashState_groestl256* ctx,
                   const BitSequence_gr* input, DataLength_gr databitlen )
{
  const int msglen = (int)(databitlen/8);  // bytes
  int i;

  /* digest bulk of message */
  Transform256( ctx, input, msglen );

  /* store remaining data in buffer */
  i = ( msglen / SIZE ) * SIZE;
  while ( i < msglen )
     ctx->buffer[(int)ctx->buf_ptr++] = input[i++];

  return SUCCESS_GR;
}

HashReturn_gr final_groestl256( hashState_groestl256* ctx,
                                BitSequence_gr* output )
{
  ctx->buffer[(int)ctx->buf_ptr++] = 0x80;

  /* pad with '0'-bits */
  if ( ctx->buf_ptr > SIZE - LENGTHFIELDLEN )
  {
    /* padding requires two blocks */
    while ( ctx->buf_ptr < SIZE )
      ctx->buffer[(int)ctx->buf_ptr++] = 0;
    /* digest first padding block */
    Transform256( ctx, ctx->buffer, SIZE );
    ctx->buf_ptr = 0;
  }
  while ( ctx->buf_ptr < SIZE - LENGTHFIELDLEN )
    ctx->buffer[(int)ctx->buf_ptr++] = 0;

  /* length padding */
  ctx->block_counter++;
  ctx->buf_ptr = SIZE;
  while ( ctx->buf_ptr > SIZE - LENGTHFIELDLEN )
  {
    ctx->buffer[(int)--ctx->buf_ptr] = (u8)ctx->block_counter;
    ctx->block_counter >>= 8;
  }

  /* digest final padding block */
  Transform256( ctx, ctx->buffer, SIZE );
  /* perform output transformation */
  OutputTransformation256( ctx );

  /* store hash result in output */
  for ( int i = ( (SIZE - ctx->hashlen) / 16 ), j = 0; i < SIZE/16; i++, j++ )
       casti_m128i( output, j ) = casti_m128i( ctx->chaining, i );

  return SUCCESS_GR;
}

HashReturn_gr update_and_final_groestl256( hashState_groestl256* ctx,
                   BitSequence_gr* output,  const BitSequence_gr* input,
                   DataLength_gr databitlen )
{
  const int msglen = (int)(databitlen/8);  // bytes
  int i, j;

  /* digest bulk of message */
  Transform256( ctx, input, msglen );

  /* store remaining data in buffer */
  i = ( msglen / SIZE ) * SIZE;
  while ( i < msglen )
     ctx->buffer[(int)ctx->buf_ptr++] = input[i++];

  // start of final
  ctx->buffer[(int)ctx->buf_ptr++] = 0x80;

  /* pad with '0'-bits */
  if ( ctx->buf_ptr > SIZE - LENGTHFIELDLEN )
  {
    /* padding requires two blocks */
    while ( ctx->buf_ptr < SIZE )
      ctx->buffer[(int)ctx->buf_ptr++] = 0;
    /* digest first padding block */
    Transform256( ctx, ctx->buffer, SIZE );
    ctx->buf_ptr = 0;
  }
  while ( ctx->buf_ptr < SIZE - LENGTHFIELDLEN )
    ctx->buffer[(int)ctx->buf_ptr++] = 0;

  /* length padding */
  ctx->block_counter++;
  ctx->buf_ptr = SIZE;
  while ( ctx->buf_ptr > SIZE - LENGTHFIELDLEN )
  {
    ctx->buffer[(int)--ctx->buf_ptr] = (u8)ctx->block_counter;
    ctx->block_counter >>= 8;
  }

  /* digest final padding block */
  Transform256( ctx, ctx->buffer, SIZE );
  /* perform output transformation */
  OutputTransformation256( ctx );

  /* store hash result in output */
  for ( i = ( (SIZE - ctx->hashlen) / 16 ), j = 0; i < SIZE/16; i++, j++ )
       casti_m128i( output, j ) = casti_m128i( ctx->chaining, i );

  return SUCCESS_GR;
}

/* hash bit sequence */
HashReturn_gr hash_groestl256(int hashbitlen,
                const BitSequence_gr* data,
                DataLength_gr databitlen,
                BitSequence_gr* hashval) {
  HashReturn_gr ret;
  hashState_groestl256 context;

  /* initialise */
  if ((ret = init_groestl256(&context, hashbitlen/8)) != SUCCESS_GR)
    return ret;

  /* process message */
  if ((ret = update_groestl256(&context, data, databitlen)) != SUCCESS_GR)
    return ret;

  /* finalise */
  ret = final_groestl256(&context, hashval);

  return ret;
}

/* eBash API */
//#ifdef crypto_hash_BYTES
//int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen)
//{
//  if (hash_groestl(crypto_hash_BYTES * 8, in, inlen * 8,out) == SUCCESS_GR) return 0;
//  return -1;
//}
//#endif

#endif
