/* hash.c     Aug 2011
 *
 * Groestl implementation for different versions.
 * Author: Krystian Matusiewicz, Günther A. Roland, Martin Schläffer
 *
 * This code is placed in the public domain
 */

#include "hash-groestl256.h"
#include "miner.h"

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
HashReturn_gr init_groestl256(hashState_groestl256* ctx) {
  u8 i = 0;
  /* output size (in bits) must be a positive integer less than or
     equal to 512, and divisible by 8 */

  /* set number of state columns and state size depending on
     variant */
  ctx->columns = COLS;
  ctx->statesize = SIZE;
    ctx->v = SHoRT;

  SET_CONSTANTS();

  for (i=0; i<SIZE/8; i++)
    ctx->chaining[i] = 0;
  for (i=0; i<SIZE; i++)
    ctx->buffer[i] = 0;

  if (ctx->chaining == NULL || ctx->buffer == NULL)
    return FAIL_GR;

  /* set initial value */
  ctx->chaining[ctx->columns-1] = U64BIG((u64)256);

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
  ctx->chaining[ctx->columns-1] = 256;

  INIT256(ctx->chaining);

  /* set other variables */
  ctx->buf_ptr = 0;
  ctx->block_counter = 0;

  return SUCCESS_GR;
}


/* update state with databitlen bits of input */
HashReturn_gr update_groestl256( hashState_groestl256* ctx,
		                 const BitSequence_gr* input,
		                 DataLength_gr databitlen )
{
  int index = 0;
  int msglen = (int)(databitlen/8);
  int rem = (int)(databitlen%8);

  /* digest bulk of message */
  Transform256( ctx, input+index, msglen-index );

  index += ((msglen-index)/ctx->statesize)*ctx->statesize;

  /* store remaining data in buffer */
  while (index < msglen)
    ctx->buffer[(int)ctx->buf_ptr++] = input[index++];

  return SUCCESS_GR;
}


/* finalise: process remaining data (including padding), perform
   output transformation, and write hash result to 'output' */
HashReturn_gr final_groestl256( hashState_groestl256* ctx,
		                BitSequence_gr* output )
{
  int i, j = 0, hashbytelen = 256/8;
  u8 *s = (BitSequence_gr*)ctx->chaining;

  ctx->buffer[(int)ctx->buf_ptr++] = 0x80;

  /* pad with '0'-bits */
  if ( ctx->buf_ptr > ctx->statesize-LENGTHFIELDLEN )
  {
    /* padding requires two blocks */
    while ( ctx->buf_ptr < ctx->statesize )
      ctx->buffer[(int)ctx->buf_ptr++] = 0;
    /* digest first padding block */
    Transform256( ctx, ctx->buffer, ctx->statesize );
    ctx->buf_ptr = 0;
  }
  while ( ctx->buf_ptr < ctx->statesize-LENGTHFIELDLEN )
    ctx->buffer[(int)ctx->buf_ptr++] = 0;

  /* length padding */
  ctx->block_counter++;
  ctx->buf_ptr = ctx->statesize;
  while ( ctx->buf_ptr > ctx->statesize-LENGTHFIELDLEN )
  {
    ctx->buffer[(int)--ctx->buf_ptr] = (u8)ctx->block_counter;
    ctx->block_counter >>= 8;
  }

  /* digest final padding block */
  Transform256(ctx, ctx->buffer, ctx->statesize);
  /* perform output transformation */
  OutputTransformation256(ctx);

  /* store hash result in output */
  for ( i = ctx->statesize-hashbytelen; i < ctx->statesize; i++,j++ )
    output[j] = s[i];

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
  if ((ret = init_groestl256(&context)) != SUCCESS_GR)
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
