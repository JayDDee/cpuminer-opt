/*
Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _KeccakP_800_SnP_h_
#define _KeccakP_800_SnP_h_

/** For the documentation, see SnP-documentation.h.
 */

#define KeccakP800_implementation      "32-bit reference implementation"
#define KeccakP800_stateSizeInBytes    100
#define KeccakP800_stateAlignment      4

#ifdef KeccakReference
void KeccakP800_StaticInitialize( void );
#else
#define KeccakP800_StaticInitialize()
#endif
void KeccakP800_Initialize(void *state);
void KeccakP800_AddByte(void *state, unsigned char data, unsigned int offset);
void KeccakP800_AddBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP800_OverwriteBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP800_OverwriteWithZeroes(void *state, unsigned int byteCount);
void KeccakP800_Permute_12rounds(void *state);
void KeccakP800_Permute_22rounds(void *state);
void KeccakP800_ExtractBytes(const void *state, unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP800_ExtractAndAddBytes(const void *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);

#endif
