/**
 * Implementation of the Lyra2 Password Hashing Scheme (PHS).
 *
 * Author: The Lyra PHC team (http://www.lyra-kdf.net/) -- 2014.
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mm_malloc.h>
#include "compat.h"
#include "lyra2.h"
#include "sponge.h"

/**
 * Executes Lyra2 based on the G function from Blake2b. This version supports salts and passwords
 * whose combined length is smaller than the size of the memory matrix, (i.e., (nRows x nCols x b) bits,
 * where "b" is the underlying sponge's bitrate). In this implementation, the "basil" is composed by all
 * integer parameters (treated as type "unsigned int") in the order they are provided, plus the value
 * of nCols, (i.e., basil = kLen || pwdlen || saltlen || timeCost || nRows || nCols).
 *
 * @param K The derived key to be output by the algorithm
 * @param kLen Desired key length
 * @param pwd User password
 * @param pwdlen Password length
 * @param salt Salt
 * @param saltlen Salt length
 * @param timeCost Parameter to determine the processing time (T)
 * @param nRows Number or rows of the memory matrix (R)
 * @param nCols Number of columns of the memory matrix (C)
 *
 * @return 0 if the key is generated correctly; -1 if there is an error (usually due to lack of memory for allocation)
 */

#if 0
int LYRA2REV2( uint64_t* wholeMatrix, void *K, uint64_t kLen, const void *pwd,
               const uint64_t pwdlen, const void *salt, const uint64_t saltlen,
               const uint64_t timeCost, const uint64_t nRows,
               const uint64_t nCols )
{
   //====================== Basic variables ============================//
   uint64_t _ALIGN(256) state[16];
   int64_t row = 2; //index of row to be processed
   int64_t prev = 1; //index of prev (last row ever computed/modified)
   int64_t rowa = 0; //index of row* (a previous row, deterministically picked during Setup and randomly picked while Wandering)
   int64_t tau; //Time Loop iterator
   int64_t step = 1; //Visitation step (used during Setup and Wandering phases)
   int64_t window = 2; //Visitation window (used to define which rows can be revisited during Setup)
   int64_t gap = 1; //Modifier to the step, assuming the values 1 or -1
//   int64_t i; //auxiliary iteration counter
   int64_t v64; // 64bit var for memcpy
   //====================================================================/

   //=== Initializing the Memory Matrix and pointers to it =============//
   //Tries to allocate enough space for the whole memory matrix

   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * nCols;
//   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;
   // for Lyra2REv2, nCols = 4, v1 was using 8
   const int64_t BLOCK_LEN = (nCols == 4) ? BLOCK_LEN_BLAKE2_SAFE_INT64
                                          : BLOCK_LEN_BLAKE2_SAFE_BYTES;
   uint64_t *ptrWord = wholeMatrix;

//   memset( wholeMatrix, 0, ROW_LEN_BYTES * nRows );

   //=== Getting the password + salt + basil padded with 10*1 ==========//
   //OBS.:The memory matrix will temporarily hold the password: not for saving memory,
   //but this ensures that the password copied locally will be overwritten as soon as possible

   //First, we clean enough blocks for the password, salt, basil and padding
   int64_t nBlocksInput = ( ( saltlen + pwdlen + 6 * sizeof(uint64_t) )
                              / BLOCK_LEN_BLAKE2_SAFE_BYTES ) + 1;

   byte *ptrByte = (byte*) wholeMatrix;

   //Prepends the password
   memcpy(ptrByte, pwd, pwdlen);
   ptrByte += pwdlen;

   //Concatenates the salt
   memcpy(ptrByte, salt, saltlen);
   ptrByte += saltlen;

   memset( ptrByte, 0, nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES
                       - (saltlen + pwdlen) );

   //Concatenates the basil: every integer passed as parameter, in the order they are provided by the interface
   memcpy(ptrByte, &kLen, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);
   v64 = pwdlen;
   memcpy(ptrByte, &v64, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);
   v64 = saltlen;
   memcpy(ptrByte, &v64, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);
   v64 = timeCost;
   memcpy(ptrByte, &v64, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);
   v64 = nRows;
   memcpy(ptrByte, &v64, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);
   v64 = nCols;
   memcpy(ptrByte, &v64, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);

   //Now comes the padding
   *ptrByte = 0x80; //first byte of padding: right after the password
   ptrByte = (byte*) wholeMatrix; //resets the pointer to the start of the memory matrix
   ptrByte += nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1; //sets the pointer to the correct position: end of incomplete block
   *ptrByte ^= 0x01; //last byte of padding: at the end of the last incomplete block

// from here on it's all simd acces to state and matrix
// define vector pointers and adjust sizes and pointer offsets

   //================= Initializing the Sponge State ====================//
   //Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)

//   initState( state );

   //========================= Setup Phase =============================//
   //Absorbing salt, password and basil: this is the only place in which the block length is hard-coded to 512 bits
   
   ptrWord = wholeMatrix;

   absorbBlockBlake2Safe( state, ptrWord, nBlocksInput, BLOCK_LEN );
/*
   for (i = 0; i < nBlocksInput; i++)
   {
       absorbBlockBlake2Safe( state, ptrWord ); //absorbs each block of pad(pwd || salt || basil)
       ptrWord += BLOCK_LEN; //goes to next block of pad(pwd || salt || basil)
   }
*/

   //Initializes M[0] and M[1]
   reducedSqueezeRow0( state, &wholeMatrix[0], nCols ); //The locally copied password is most likely overwritten here

   reducedDuplexRow1( state, &wholeMatrix[0], &wholeMatrix[ROW_LEN_INT64],
                      nCols);

   do
   {
      //M[row] = rand; //M[row*] = M[row*] XOR rotW(rand)

      reducedDuplexRowSetup( state, &wholeMatrix[prev*ROW_LEN_INT64],
                             &wholeMatrix[rowa*ROW_LEN_INT64],
                             &wholeMatrix[row*ROW_LEN_INT64], nCols );

      //updates the value of row* (deterministically picked during Setup))
      rowa = (rowa + step) & (window - 1);
      //update prev: it now points to the last row ever computed

      prev = row;
      //updates row: goes to the next row to be computed
      row++;

      //Checks if all rows in the window where visited.
      if (rowa == 0)
      {
         step = window + gap; //changes the step: approximately doubles its value
         window *= 2; //doubles the size of the re-visitation window
         gap = -gap; //inverts the modifier to the step
      }

   } while (row < nRows);

   //===================== Wandering Phase =============================//
   row = 0; //Resets the visitation to the first row of the memory matrix
   for (tau = 1; tau <= timeCost; tau++)
   {
       //Step is approximately half the number of all rows of the memory matrix for an odd tau; otherwise, it is -1
       step = (tau % 2 == 0) ? -1 : nRows / 2 - 1;
       do
       {
           //Selects a pseudorandom index row*
           //-----------------------------------------------
           rowa = state[0] & (unsigned int)(nRows-1);  //(USE THIS IF nRows IS A POWER OF 2)

           //rowa = state[0] % nRows; //(USE THIS FOR THE "GENERIC" CASE)
           //-------------------------------------------

           //Performs a reduced-round duplexing operation over M[row*] XOR M[prev], updating both M[row*] and M[row]
           reducedDuplexRow( state, &wholeMatrix[prev*ROW_LEN_INT64],
                             &wholeMatrix[rowa*ROW_LEN_INT64],
                             &wholeMatrix[row*ROW_LEN_INT64], nCols );
           //update prev: it now points to the last row ever computed
           prev = row;

           //updates row: goes to the next row to be computed
           //----------------------------------------------------
           row = (row + step) & (unsigned int)(nRows-1); //(USE THIS IF nRows IS A POWER OF 2)
           //row = (row + step) % nRows; //(USE THIS FOR THE "GENERIC" CASE)
           //----------------------------------------------------

       } while (row != 0);
   }

   //===================== Wrap-up Phase ===============================//
   //Absorbs the last block of the memory matrix
   absorbBlock(state, &wholeMatrix[rowa*ROW_LEN_INT64]);
   //Squeezes the key
   squeeze(state, K, (unsigned int) kLen);

   return 0;
}

#endif

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// This version is currently only used by REv3 and has some hard coding
// specific to v3 such as input data size of 32 bytes.
//
// Similarly with REv2. Thedifference with REv3 isn't clear and maybe
// they can be merged.
//
// RE is used by RE, allium. The main difference between RE and REv2
// in the matrix size.
//
// Z also needs to support 80 byte input as well as 32 byte, and odd
// matrix sizes like 330 rows. It is used by lyra2z330, lyra2z, lyra2h.


/////////////////////////////////////////////////

// 2 way 256
// drop salt, salt len arguments, hard code some others.
// Data is interleaved 2x256.

//int LYRA2REV3_2WAY( uint64_t* wholeMatrix, void *K, uint64_t kLen,
//                    const void *pwd, uint64_t pwdlen, uint64_t timeCost,
//                    uint64_t nRows, uint64_t nCols )

// hard coded for 32 byte input as well as matrix size.
// Other required versions include 80 byte input and different block
// sizez

int LYRA2REV3_2WAY( uint64_t* wholeMatrix, void *K, uint64_t kLen,
      const void *pwd, const uint64_t pwdlen, const void *salt,
      const uint64_t saltlen, const uint64_t timeCost, const uint64_t nRows,
      const uint64_t nCols )
{
   //====================== Basic variables ============================//
   uint64_t _ALIGN(256) state[32];
   int64_t row = 2; 
   int64_t prev = 1;
   int64_t rowa0 = 0;
   int64_t rowa1 = 0;
   int64_t tau; 
   int64_t step = 1;
   int64_t window = 2;
   int64_t gap = 1; 
//   int64_t i; //auxiliary iteration counter
//   int64_t v64; // 64bit var for memcpy
   uint64_t instance0 = 0;
   uint64_t instance1 = 0;
   //====================================================================/

   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * nCols;
   const int64_t BLOCK_LEN = BLOCK_LEN_BLAKE2_SAFE_INT64;

   uint64_t *ptrWord = wholeMatrix;

//  2 way 256 rewrite. Salt always == password, and data is interleaved,
//  need to build in parallel as pw isalready interleaved.

   
//  {   password,    (64 or 80 bytes)
//      salt,        (64 or 80 bytes) =  same as password
//      Klen,        (u64)  = 32 bytes
//      pwdlen,      (u64)
//      saltlen,     (u64)
//      timecost,    (u64)
//      nrows,       (u64)
//      ncols,       (u64)
//      0x80,        (byte)
//      { 0 .. 0 },
//      1            (byte)
//   }
   
// It's all u64 so don't use byte


// input is usually 32 maybe 64, both are aligned to 256 bit vector.
// 80 byte inpput is not aligned complicating matters for lyra2z.   

   int64_t nBlocksInput = ( ( saltlen + pwdlen + 6 * sizeof(uint64_t) )
                              / BLOCK_LEN_BLAKE2_SAFE_BYTES ) + 1;
   
   uint64_t *ptr = wholeMatrix;
   uint64_t *pw = (uint64_t*)pwd;

   memcpy( ptr, pw, 2*pwdlen ); // password 
   ptr += pwdlen>>2;
   memcpy( ptr, pw, 2*pwdlen ); // password lane 1
   ptr += pwdlen>>2;
 
// now build the rest interleaving on the fly.

   ptr[0] = ptr[ 4] = kLen;
   ptr[1] = ptr[ 5] = pwdlen;
   ptr[2] = ptr[ 6] = pwdlen;   // saltlen
   ptr[3] = ptr[ 7] = timeCost;
   ptr[8] = ptr[12] = nRows;
   ptr[9] = ptr[13] = nCols;
   ptr[10] = ptr[14] = 0x80;
   ptr[11] = ptr[15] = 0x0100000000000000;

   ptr = wholeMatrix;

/* 
   // do it the old way to compare.
  
   uint64_t pb[512];
   byte* ptrByte = (byte*)pb;

   //Prepends the password (use salt for testing)
   memcpy( ptrByte, salt, saltlen );
   ptrByte += saltlen;

   //Concatenates the salt
   memcpy(ptrByte, salt, saltlen);
   ptrByte += saltlen;

   memset( ptrByte, 0, nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES
                       - (saltlen + pwdlen) );

   memcpy(ptrByte, &kLen, 8);
   ptrByte += 8;
   memcpy(ptrByte, &pwdlen, 8);
   ptrByte += 8;
   memcpy(ptrByte, &saltlen, 8);
   ptrByte += 8;
   memcpy(ptrByte, &timeCost, 8);
   ptrByte += 8;
   memcpy(ptrByte, &nRows, 8);
   ptrByte += 8;
   memcpy(ptrByte, &nCols, 8);
   ptrByte += 8;


   //Now comes the padding
   *ptrByte = 0x80; //first byte of padding: right after the password
   ptrByte = (byte*) pb; //resets the pointer to the start of the memory matrix

   ptrByte += nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1; //sets the pointer to the correct position: end of incomplete block
   *ptrByte ^= 0x01; //last byte of padding: at the end of the last incomplete block
*/


// display the data
printf("LYRA2REV3 data, blocks= %d\n", nBlocksInput);
/*
uint64_t* m = (uint64_t*)wholeMatrix;

printf("Lyra2v3 1: blocklensafe %d\n", BLOCK_LEN_BLAKE2_SAFE_BYTES);
printf("pb: %016lx %016lx %016lx %016lx\n",pb[0],pb[1],pb[2],pb[3]);
printf("pb: %016lx %016lx %016lx %016lx\n",pb[4],pb[5],pb[6],pb[7]);
printf("pb: %016lx %016lx %016lx %016lx\n",pb[8],pb[8],pb[10],pb[11]);
printf("pb: %016lx %016lx %016lx %016lx\n",pb[12],pb[13],pb[14],pb[15]);

printf("data V:  %016lx %016lx %016lx %016lx\n",m[0],m[1],m[2],m[3]);
printf("data V:  %016lx %016lx %016lx %016lx\n",m[4],m[5],m[6],m[7]);
printf("data V:  %016lx %016lx %016lx %016lx\n",m[8],m[8],m[10],m[11]);
printf("data V:  %016lx %016lx %016lx %016lx\n",m[12],m[13],m[14],m[15]);
printf("data V:  %016lx %016lx %016lx %016lx\n",m[16],m[17],m[18],m[19]);
printf("data V:  %016lx %016lx %016lx %016lx\n",m[20],m[21],m[22],m[23]);
printf("data V:  %016lx %016lx %016lx %016lx\n",m[24],m[25],m[26],m[27]);
printf("data V:  %016lx %016lx %016lx %016lx\n",m[28],m[29],m[30],m[31]);
*/

// from here on it's all simd acces to state and matrix
// define vector pointers and adjust sizes and pointer offsets

uint64_t _ALIGN(256) st[16];


   ptrWord = wholeMatrix;

   absorbBlockBlake2Safe_2way( state, ptrWord, nBlocksInput, BLOCK_LEN );

uint64_t *p = wholeMatrix;
printf("wholematrix[0]\n");
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
p = &wholeMatrix[2*ROW_LEN_INT64];
printf("wholematrix[1]\n");
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
p = &wholeMatrix[4*ROW_LEN_INT64];
printf("wholematrix[2]\n");
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
p = &wholeMatrix[6*ROW_LEN_INT64];
printf("wholematrix[3]\n");
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV1 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
   
//printf("SV1: %016lx %016lx %016lx %016lx\n",state[0],state[1],state[2],state[3]);
   
/*
   absorbBlockBlake2Safe( st, pb, nBlocksInput, BLOCK_LEN );

   
printf("SV: %016lx %016lx %016lx %016lx\n",state[0],state[1],state[2],state[3]);
printf("SS: %016lx %016lx %016lx %016lx\n",st[0],st[1],st[2],st[3]);
*/

   reducedSqueezeRow0_2way( state, &wholeMatrix[0], nCols );

// At this point the entire matrix should be filled but only col 0 is.
// The others are unchanged or the display offsets are wrong.
  
p = wholeMatrix;
printf("wholematrix[0]   %x\n",wholeMatrix);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[32],p[33],p[34],p[35]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[36],p[37],p[38],p[39]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[40],p[41],p[42],p[43]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[44],p[45],p[46],p[47]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[48],p[49],p[50],p[51]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[52],p[53],p[54],p[55]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[56],p[57],p[58],p[59]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[60],p[61],p[62],p[63]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[64],p[65],p[66],p[67]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[68],p[69],p[70],p[71]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[72],p[73],p[74],p[75]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[76],p[77],p[78],p[79]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[80],p[81],p[82],p[83]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[84],p[85],p[86],p[87]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[88],p[89],p[90],p[91]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[92],p[93],p[94],p[95]);




p = &wholeMatrix[2*ROW_LEN_INT64];
printf("wholematrix[1]   %x\n", &wholeMatrix[2*ROW_LEN_INT64]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
p = &wholeMatrix[4*ROW_LEN_INT64];
printf("wholematrix[2]   %x\n",&wholeMatrix[4*ROW_LEN_INT64]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
p = &wholeMatrix[6*ROW_LEN_INT64];
printf("wholematrix[3]   %x\n",&wholeMatrix[6*ROW_LEN_INT64]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV2 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
   
//printf("SV2 %016lx %016lx %016lx %016lx\n",state[0],state[1],state[2],state[3]);
/*
printf("SV2 %016lx %016lx %016lx %016lx\n",state[0],state[1],state[2],state[3]);
printf("SV2 %016lx %016lx %016lx %016lx\n",state[4],state[5],state[6],state[7]);
printf("SV2 %016lx %016lx %016lx %016lx\n",state[8],state[9],state[10],state[11]);
printf("SV2 %016lx %016lx %016lx %016lx\n",state[12],state[13],state[14],state[15]);
printf("SV2 %016lx %016lx %016lx %016lx\n",state[16],state[17],state[18],state[19]);
printf("SV2 %016lx %016lx %016lx %016lx\n",state[20],state[21],state[22],state[23]);
printf("SV2 %016lx %016lx %016lx %016lx\n",state[24],state[25],state[26],state[27]);
printf("SV2 %016lx %016lx %016lx %016lx\n",state[28],state[29],state[30],state[31]);
*/
   
   reducedDuplexRow1_2way( state, &wholeMatrix[0], &wholeMatrix[2*ROW_LEN_INT64],
                      nCols);


//printf("SV3 %016lx %016lx %016lx %016lx\n",state[0],state[1],state[2],state[3]);
/*
printf("SV3 %016lx %016lx %016lx %016lx\n",state[0],state[1],state[2],state[3]);
printf("SV3 %016lx %016lx %016lx %016lx\n",state[4],state[5],state[6],state[7]);
printf("SV3 %016lx %016lx %016lx %016lx\n",state[8],state[9],state[10],state[11]);
printf("SV3 %016lx %016lx %016lx %016lx\n",state[12],state[13],state[14],state[15]);
printf("SV3 %016lx %016lx %016lx %016lx\n",state[16],state[17],state[18],state[19]);
printf("SV3 %016lx %016lx %016lx %016lx\n",state[20],state[21],state[22],state[23]);
printf("SV3 %016lx %016lx %016lx %016lx\n",state[24],state[25],state[26],state[27]);
printf("SV3 %016lx %016lx %016lx %016lx\n",state[28],state[29],state[30],state[31]);
*/
p = wholeMatrix;
printf("wholematrix[0]\n");
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
p = &wholeMatrix[2*ROW_LEN_INT64];
printf("wholematrix[1]\n");
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
p = &wholeMatrix[4*ROW_LEN_INT64];
printf("wholematrix[2]\n");
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
p = &wholeMatrix[6*ROW_LEN_INT64];
printf("wholematrix[3]\n");
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV3 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);


   do
   {

      reducedDuplexRowSetup_2way( state, &wholeMatrix[2*prev*ROW_LEN_INT64],
                             &wholeMatrix[2*rowa0*ROW_LEN_INT64],
                             &wholeMatrix[2*row*ROW_LEN_INT64], nCols );

      rowa0 = (rowa0 + step) & (window - 1);

      prev = row;
      row++;

      if (rowa0 == 0)
      {
         step = window + gap; //changes the step: approximately doubles its value
         window *= 2; //doubles the size of the re-visitation window
         gap = -gap; //inverts the modifier to the step
      }

   } while (row < nRows);


p = wholeMatrix;
printf("wholematrix[0]\n");
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
p = &wholeMatrix[2*ROW_LEN_INT64];
printf("wholematrix[1]\n");
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
p = &wholeMatrix[4*ROW_LEN_INT64];
printf("wholematrix[2]\n");
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
p = &wholeMatrix[6*ROW_LEN_INT64];
printf("wholematrix[3]\n");
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);



//printf("SV5 prev= %d\n",prev);
/*
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV4 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);


printf("SV4 S %016lx %016lx %016lx %016lx\n",state[0],state[1],state[2],state[3]);
printf("SV4 S %016lx %016lx %016lx %016lx\n",state[4],state[5],state[6],state[7]);
printf("SV4 S %016lx %016lx %016lx %016lx\n",state[8],state[9],state[10],state[11]);
printf("SV4 S %016lx %016lx %016lx %016lx\n",state[12],state[13],state[14],state[15]);
printf("SV4 S %016lx %016lx %016lx %016lx\n",state[16],state[17],state[18],state[19]);
printf("SV4 S %016lx %016lx %016lx %016lx\n",state[20],state[21],state[22],state[23]);
printf("SV4 S %016lx %016lx %016lx %016lx\n",state[24],state[25],state[26],state[27]);
printf("SV4 S %016lx %016lx %016lx %016lx\n",state[28],state[29],state[30],state[31]);
*/        
      
//printf("Lyra2v3 4\n");

uint64_t *ptr0 = wholeMatrix;    // base address for each lane
uint64_t *ptr1 = wholeMatrix + 4;

// convert a simple offset to an index into interleaved data.
// good for state and 4 row matrix. 
// index = ( int( off / 4 ) * 2 ) + ( off mod 4 )

#define offset_to_index( o ) \
   ( ( ( (uint64_t)( (o) & 0xf) / 4 ) * 8 ) + ( (o) % 4 ) )

   row = 0;
   for (tau = 1; tau <= timeCost; tau++)
   {
      step = ((tau & 1) == 0) ? -1 : (nRows >> 1) - 1;
      do
      {
        // This part is not parallel, rowa will be different for each lane.
        // state (u64[16]) is interleaved 2x256, need to extract seperately
        // and figure out where the data is when interleaved.
        // &state[0] (or matrix) is the start of lane 0, while &state[4]
        // is the start of lane 1. From there there are 4 consecutive elements
        // followed by 4 elements from the other lane that must be skipped.

        povly ptr;
        ptr.u64 = wholeMatrix;

/*        
printf("SV4a %016lx %016lx %016lx %016lx\n",state[0],state[1],state[2],state[3]);
printf("SV4a %016lx %016lx %016lx %016lx\n",state[4],state[5],state[6],state[7]);
printf("SV4a %016lx %016lx %016lx %016lx\n",state[8],state[9],state[10],state[11]);
printf("SV4a %016lx %016lx %016lx %016lx\n",state[12],state[13],state[14],state[15]);
printf("SV4a %016lx %016lx %016lx %016lx\n",state[16],state[17],state[18],state[19]);
printf("SV4a %016lx %016lx %016lx %016lx\n",state[20],state[21],state[22],state[23]);
printf("SV4a %016lx %016lx %016lx %016lx\n",state[24],state[25],state[26],state[27]);
printf("SV4a %016lx %016lx %016lx %016lx\n",state[28],state[29],state[30],state[31]);
*        
//printf("SV4a o to i %016lx = %016lx\n", instance0, offset_to_index( instance0 ) );
*/
        instance0 = state[ offset_to_index( instance0 ) ];
        instance1 = (&state[4])[ offset_to_index( instance1 ) ];

printf("SV4b o to i %016lx = %016lx, state0 %016lx\n", instance0, offset_to_index( instance0 ), state[offset_to_index( instance0 )] );
printf("SV4b o to i %016lx = %016lx, state1 %016lx\n", instance1, offset_to_index( instance1 ), (state+4)[offset_to_index( instance1 )] );
        
//printf("SV4b lane 1 instance1 = %d, rowa1= %d\n",instance1,rowa1);

        rowa0 = state[ offset_to_index( instance0 )  ]
                & (unsigned int)(nRows-1);
        rowa1 = (state+4)[ offset_to_index( instance1 ) ]
                & (unsigned int)(nRows-1);

// matrix[prev] ie row 0,  is messed up after rdr for row 1. ok after rdr 0

//printf("SV5 lane 1 instance1= %016lx, rowa1= %d\n",instance1,rowa1);
printf("SV5 row= %d, step= %d\n",row,step);         
printf("SV5 instance0 %016lx, rowa0 %d, p0 %016lx\n",instance0,rowa0,ptr0[ 2* rowa0 * ROW_LEN_INT64 ]);
printf("SV5 instance1 %016lx, rowa1 %d, p1 %016lx\n",instance1,rowa1,ptr1[ 2* rowa1 * ROW_LEN_INT64 ]);
uint64_t *p = &wholeMatrix[2*rowa1*ROW_LEN_INT64];
printf("SV5 prev= %d\n",prev); 
/*
printf("SV5 M  %016lx %016lx %016lx %016lx\n",p[0],p[1],p[2],p[3]);
printf("SV5 M  %016lx %016lx %016lx %016lx\n",p[4],p[5],p[6],p[7]);
printf("SV5 M  %016lx %016lx %016lx %016lx\n",p[8],p[9],p[10],p[11]);
printf("SV5 M  %016lx %016lx %016lx %016lx\n",p[12],p[13],p[14],p[15]);
printf("SV5 M  %016lx %016lx %016lx %016lx\n",p[16],p[17],p[18],p[19]);
printf("SV5 M  %016lx %016lx %016lx %016lx\n",p[20],p[21],p[22],p[23]);
printf("SV5 M  %016lx %016lx %016lx %016lx\n",p[24],p[25],p[26],p[27]);
printf("SV5 M  %016lx %016lx %016lx %016lx\n",p[28],p[29],p[30],p[31]);
*/

        reducedDuplexRow_2way( state, ptr, prev, rowa0, rowa1, row, nCols );

/*
        reducedDuplexRow_2way( state, &wholeMatrix[ 2* prev * ROW_LEN_INT64 ],
                                      &ptr0[ 2* rowa0 * ROW_LEN_INT64 ],
                                      &ptr1[ 2* rowa1 * ROW_LEN_INT64 ],
                               &wholeMatrix[ 2* row*ROW_LEN_INT64], nCols );
*/

/*
printf("SV6 %016lx %016lx %016lx %016lx\n",state[0],state[1],state[2],state[3]);
printf("SV6 %016lx %016lx %016lx %016lx\n",state[4],state[5],state[6],state[7]);
printf("SV6 %016lx %016lx %016lx %016lx\n",state[8],state[9],state[10],state[11]);
printf("SV6 %016lx %016lx %016lx %016lx\n",state[12],state[13],state[14],state[15]);
printf("SV6 %016lx %016lx %016lx %016lx\n",state[16],state[17],state[18],state[19]);
printf("SV6 %016lx %016lx %016lx %016lx\n",state[20],state[21],state[22],state[23]);
printf("SV6 %016lx %016lx %016lx %016lx\n",state[24],state[25],state[26],state[271]);
printf("SV6 %016lx %016lx %016lx %016lx\n",state[28],state[29],state[30],state[31]);
*/        
        
/*
           instance = state[instance & 0xF];
           rowa = state[instance & 0xF] & (unsigned int)(nRows-1);

           reducedDuplexRow( state, &wholeMatrix[prev*ROW_LEN_INT64],
                             &wholeMatrix[rowa*ROW_LEN_INT64],
                             &wholeMatrix[row*ROW_LEN_INT64], nCols );
*/
        // End of divergence.

        prev = row;
        row = (row + step) & (unsigned int)(nRows-1); 

       } while ( row != 0 );
   }

printf("SV7 %016lx %016lx %016lx %016lx\n",state[0],state[1],state[2],state[3]);


// rowa mismatches here so need to do a split read
   absorbBlock_2way( state, &wholeMatrix[2*rowa0*ROW_LEN_INT64] );

   squeeze_2way( state, K, (unsigned int) kLen );

   return 0;
}

#undef offset_to_index

#endif // AVX512

#if 0

//////////////////////////////////////////////////
int LYRA2Z( uint64_t* wholeMatrix, void *K, uint64_t kLen, const void *pwd,
            const uint64_t pwdlen, const void *salt, const uint64_t saltlen,
            const uint64_t timeCost, const uint64_t nRows,
            const uint64_t nCols )
{
    //========================== Basic variables ============================//
    uint64_t _ALIGN(256) state[16];
    int64_t row = 2; //index of row to be processed
    int64_t prev = 1; //index of prev (last row ever computed/modified)
    int64_t rowa = 0; //index of row* (a previous row, deterministically picked during Setup and randomly picked while Wandering)
    int64_t tau; //Time Loop iterator
    int64_t step = 1; //Visitation step (used during Setup and Wandering phases)
    int64_t window = 2; //Visitation window (used to define which rows can be revisited during Setup)
    int64_t gap = 1; //Modifier to the step, assuming the values 1 or -1
//    int64_t i; //auxiliary iteration counter
    //=======================================================================/

    //======= Initializing the Memory Matrix and pointers to it =============//
    //Tries to allocate enough space for the whole memory matrix

    const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * nCols;
//    const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

//    memset( wholeMatrix, 0, ROW_LEN_BYTES * nRows );

    //==== Getting the password + salt + basil padded with 10*1 ============//
    //OBS.:The memory matrix will temporarily hold the password: not for saving memory,
    //but this ensures that the password copied locally will be overwritten as soon as possible

    //First, we clean enough blocks for the password, salt, basil and padding
    uint64_t nBlocksInput = ( ( saltlen + pwdlen + 6 *
                       sizeof (uint64_t) ) / BLOCK_LEN_BLAKE2_SAFE_BYTES ) + 1;
    byte *ptrByte = (byte*) wholeMatrix;
    memset( ptrByte, 0, nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES );

    //Prepends the password
    memcpy(ptrByte, pwd, pwdlen);
    ptrByte += pwdlen;

    //Concatenates the salt
    memcpy(ptrByte, salt, saltlen);
    ptrByte += saltlen;
    //Concatenates the basil: every integer passed as parameter, in the order they are provided by the interface
    memcpy(ptrByte, &kLen, sizeof (uint64_t));
    ptrByte += sizeof (uint64_t);
    memcpy(ptrByte, &pwdlen, sizeof (uint64_t));
    ptrByte += sizeof (uint64_t);
    memcpy(ptrByte, &saltlen, sizeof (uint64_t));
    ptrByte += sizeof (uint64_t);
    memcpy(ptrByte, &timeCost, sizeof (uint64_t));
    ptrByte += sizeof (uint64_t);
    memcpy(ptrByte, &nRows, sizeof (uint64_t));
    ptrByte += sizeof (uint64_t);
    memcpy(ptrByte, &nCols, sizeof (uint64_t));
    ptrByte += sizeof (uint64_t);

    //Now comes the padding
    *ptrByte = 0x80; //first byte of padding: right after the password
    ptrByte = (byte*) wholeMatrix; //resets the pointer to the start of the memory matrix
    ptrByte += nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1; //sets the pointer to the correct position: end of incomplete block
    *ptrByte ^= 0x01; //last byte of padding: at the end of the last incomplete block

    //=================== Initializing the Sponge State ====================//
    //Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
//        uint64_t *state = _mm_malloc(16 * sizeof(uint64_t), 32);
//        if (state == NULL) {
//                return -1;
//        }
//    initState( state );

    //============================== Setup Phase =============================//
    //Absorbing salt, password and basil: this is the only place in which the block length is hard-coded to 512 bits
    uint64_t *ptrWord = wholeMatrix;

    absorbBlockBlake2Safe( state, ptrWord, nBlocksInput,
                           BLOCK_LEN_BLAKE2_SAFE_INT64 );
/*
    for ( i = 0; i < nBlocksInput; i++ )
    {
      absorbBlockBlake2Safe( state, ptrWord ); //absorbs each block of pad(pwd || salt || basil)
      ptrWord += BLOCK_LEN_BLAKE2_SAFE_INT64; //goes to next block of pad(pwd || salt || basil)
    }
*/
    //Initializes M[0] and M[1]
        reducedSqueezeRow0(state, &wholeMatrix[0], nCols); //The locally copied password is most likely overwritten here
        reducedDuplexRow1(state, &wholeMatrix[0], &wholeMatrix[ROW_LEN_INT64], nCols);

        do {
                //M[row] = rand; //M[row*] = M[row*] XOR rotW(rand)
                reducedDuplexRowSetup(state, &wholeMatrix[prev*ROW_LEN_INT64], &wholeMatrix[rowa*ROW_LEN_INT64], &wholeMatrix[row*ROW_LEN_INT64], nCols);

                //updates the value of row* (deterministically picked during Setup))
                rowa = (rowa + step) & (window - 1);
                //update prev: it now points to the last row ever computed
                prev = row;
                //updates row: goes to the next row to be computed
                row++;

                //Checks if all rows in the window where visited.
                if (rowa == 0) {
                        step = window + gap; //changes the step: approximately doubles its value
                        window *= 2; //doubles the size of the re-visitation window
                        gap = -gap; //inverts the modifier to the step
                }

        } while (row < nRows);

    //======================== Wandering Phase =============================//
    row = 0; //Resets the visitation to the first row of the memory matrix
    for ( tau = 1; tau <= timeCost; tau++ )
    {
        //Step is approximately half the number of all rows of the memory matrix for an odd tau; otherwise, it is -1
        step = (tau % 2 == 0) ? -1 : nRows / 2 - 1;
        do {
        //Selects a pseudorandom index row*
        //----------------------------------------------------------------------
        //rowa = ((unsigned int)state[0]) & (nRows-1);  //(USE THIS IF nRows IS A POWER OF 2)
        rowa = ((uint64_t) (state[0])) % nRows; //(USE THIS FOR THE "GENERIC" CASE)
        //-----------------------------------------------------------------

        //Performs a reduced-round duplexing operation over M[row*] XOR M[prev], updating both M[row*] and M[row]
                reducedDuplexRow(state, &wholeMatrix[prev*ROW_LEN_INT64], &wholeMatrix[rowa*ROW_LEN_INT64], &wholeMatrix[row*ROW_LEN_INT64], nCols);

        //update prev: it now points to the last row ever computed
        prev = row;

        //updates row: goes to the next row to be computed
        //---------------------------------------------------------------
        //row = (row + step) & (nRows-1);       //(USE THIS IF nRows IS A POWER OF 2)
        row = (row + step) % nRows; //(USE THIS FOR THE "GENERIC" CASE)
        //--------------------------------------------------------------------

      } while (row != 0);
    }

    //========================= Wrap-up Phase ===============================//
    //Absorbs the last block of the memory matrix
    absorbBlock(state, &wholeMatrix[rowa*ROW_LEN_INT64]);

    //Squeezes the key
    squeeze( state, K, kLen );

    return 0;
}

// Lyra2RE doesn't like the new wholeMatrix implementation
int LYRA2RE( void *K, uint64_t kLen, const void *pwd, const uint64_t pwdlen,
             const void *salt, const uint64_t saltlen, const uint64_t timeCost,
             const uint64_t nRows, const uint64_t nCols )
{
   //====================== Basic variables ============================//
   uint64_t _ALIGN(256) state[16];
   int64_t row = 2; //index of row to be processed
   int64_t prev = 1; //index of prev (last row ever computed/modified)
   int64_t rowa = 0; //index of row* (a previous row, deterministically picked during Setup and randomly picked while Wandering)
   int64_t tau; //Time Loop iterator
   int64_t step = 1; //Visitation step (used during Setup and Wandering phases)
   int64_t window = 2; //Visitation window (used to define which rows can be revisited during Setup)
   int64_t gap = 1; //Modifier to the step, assuming the values 1 or -1
   int64_t i; //auxiliary iteration counter
   int64_t v64; // 64bit var for memcpy
   //====================================================================/

   //=== Initializing the Memory Matrix and pointers to it =============//
   //Tries to allocate enough space for the whole memory matrix

   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * nCols;
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;
   // for Lyra2REv2, nCols = 4, v1 was using 8
   const int64_t BLOCK_LEN = (nCols == 4) ? BLOCK_LEN_BLAKE2_SAFE_INT64
                                          : BLOCK_LEN_BLAKE2_SAFE_BYTES;

   i = (int64_t)ROW_LEN_BYTES * nRows;
   uint64_t *wholeMatrix = _mm_malloc( i, 64 );
   if (wholeMatrix == NULL)
      return -1;

#if defined(__AVX2__)
   memset_zero_256( (__m256i*)wholeMatrix, i>>5 );
#elif defined(__SSE2__)
   memset_zero_128( (__m128i*)wholeMatrix, i>>4 );   
#else
   memset( wholeMatrix, 0, i );
#endif

   uint64_t *ptrWord = wholeMatrix;

   //=== Getting the password + salt + basil padded with 10*1 ==========//
   //OBS.:The memory matrix will temporarily hold the password: not for saving memory,
   //but this ensures that the password copied locally will be overwritten as soon as possible

   //First, we clean enough blocks for the password, salt, basil and padding
   int64_t nBlocksInput = ( ( saltlen + pwdlen + 6 * sizeof(uint64_t) )
                              / BLOCK_LEN_BLAKE2_SAFE_BYTES ) + 1;

   byte *ptrByte = (byte*) wholeMatrix;

   //Prepends the password
   memcpy(ptrByte, pwd, pwdlen);
   ptrByte += pwdlen;

   //Concatenates the salt
   memcpy(ptrByte, salt, saltlen);
   ptrByte += saltlen;

//   memset( ptrByte, 0, nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES
//                       - (saltlen + pwdlen) );

   //Concatenates the basil: every integer passed as parameter, in the order they are provided by the interface
   memcpy(ptrByte, &kLen, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);
   v64 = pwdlen;
   memcpy(ptrByte, &v64, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);
   v64 = saltlen;
   memcpy(ptrByte, &v64, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);
   v64 = timeCost;
   memcpy(ptrByte, &v64, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);
   v64 = nRows;
   memcpy(ptrByte, &v64, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);
   v64 = nCols;
   memcpy(ptrByte, &v64, sizeof(int64_t));
   ptrByte += sizeof(uint64_t);

   //Now comes the padding
   *ptrByte = 0x80; //first byte of padding: right after the password
   ptrByte = (byte*) wholeMatrix; //resets the pointer to the start of the memory matrix
   ptrByte += nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1; //sets the pointer to the correct position: end of incomplete block
   *ptrByte ^= 0x01; //last byte of padding: at the end of the last incomplete block

   //================= Initializing the Sponge State ====================//
   //Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)

//   initState( state );

   //========================= Setup Phase =============================//
   //Absorbing salt, password and basil: this is the only place in which the block length is hard-coded to 512 bits

   ptrWord = wholeMatrix;

   absorbBlockBlake2Safe( state, ptrWord, nBlocksInput, BLOCK_LEN );
/*
   for (i = 0; i < nBlocksInput; i++)
   {
       absorbBlockBlake2Safe( state, ptrWord ); //absorbs each block of pad(pwd || salt || basil)
       ptrWord += BLOCK_LEN; //goes to next block of pad(pwd || salt || basil)
   }
*/
   //Initializes M[0] and M[1]
   reducedSqueezeRow0( state, &wholeMatrix[0], nCols ); //The locally copied password is most likely overwritten here

   reducedDuplexRow1( state, &wholeMatrix[0], &wholeMatrix[ROW_LEN_INT64],
                      nCols);

   do
   {
      //M[row] = rand; //M[row*] = M[row*] XOR rotW(rand)

      reducedDuplexRowSetup( state, &wholeMatrix[prev*ROW_LEN_INT64],
                             &wholeMatrix[rowa*ROW_LEN_INT64],
                             &wholeMatrix[row*ROW_LEN_INT64], nCols );

      //updates the value of row* (deterministically picked during Setup))
      rowa = (rowa + step) & (window - 1);
      //update prev: it now points to the last row ever computed

      prev = row;
      //updates row: goes to the next row to be computed
      row++;

      //Checks if all rows in the window where visited.
      if (rowa == 0)
      {
         step = window + gap; //changes the step: approximately doubles its value
         window *= 2; //doubles the size of the re-visitation window
         gap = -gap; //inverts the modifier to the step
      }

   } while (row < nRows);

   //===================== Wandering Phase =============================//
   row = 0; //Resets the visitation to the first row of the memory matrix
   for (tau = 1; tau <= timeCost; tau++)
   {
       //Step is approximately half the number of all rows of the memory matrix for an odd tau; otherwise, it is -1
       step = (tau % 2 == 0) ? -1 : nRows / 2 - 1;
       do
       {
           //Selects a pseudorandom index row*
           //-----------------------------------------------
           rowa = state[0] & (unsigned int)(nRows-1);  //(USE THIS IF nRows IS A POWER OF 2)

           //rowa = state[0] % nRows; //(USE THIS FOR THE "GENERIC" CASE)
           //-------------------------------------------

           //Performs a reduced-round duplexing operation over M[row*] XOR M[prev], updating both M[row*] and M[row]
           reducedDuplexRow( state, &wholeMatrix[prev*ROW_LEN_INT64],
                             &wholeMatrix[rowa*ROW_LEN_INT64],
                             &wholeMatrix[row*ROW_LEN_INT64], nCols );
           //update prev: it now points to the last row ever computed
           prev = row;

           //updates row: goes to the next row to be computed
           //----------------------------------------------------
           row = (row + step) & (unsigned int)(nRows-1); //(USE THIS IF nRows IS A POWER OF 2)
           //row = (row + step) % nRows; //(USE THIS FOR THE "GENERIC" CASE)
           //----------------------------------------------------

       } while (row != 0);
   }

   //===================== Wrap-up Phase ===============================//
   //Absorbs the last block of the memory matrix
   absorbBlock(state, &wholeMatrix[rowa*ROW_LEN_INT64]);
   //Squeezes the key
   squeeze(state, K, (unsigned int) kLen);

   //================== Freeing the memory =============================//
   _mm_free(wholeMatrix);

   return 0;
}

#endif
