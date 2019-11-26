#ifndef SWIFFTX_SHA3_H
#define SWIFFTX_SHA3_H

#include "sha3_interface.h"
#include "stdbool.h"
#include "stdint.h"

class Swifftx : public SHA3 {

#define SWIFFTX_INPUT_BLOCK_SIZE 256
#define SWIFFTX_OUTPUT_BLOCK_SIZE 65
#define SWIF_HAIFA_SALT_SIZE 8
#define SWIF_HAIFA_NUM_OF_BITS_SIZE 8
#define SWIF_HAIFA_INPUT_BLOCK_SIZE (SWIFFTX_INPUT_BLOCK_SIZE - SWIFFTX_OUTPUT_BLOCK_SIZE \
							  - SWIF_HAIFA_NUM_OF_BITS_SIZE - SWIF_HAIFA_SALT_SIZE)

	typedef unsigned char BitSequence;
//const DataLength SWIF_SALT_VALUE;

#define SWIF_HAIFA_IV 0

/*const BitSequence SWIF_HAIFA_IV_224[SWIFFTX_OUTPUT_BLOCK_SIZE];
const BitSequence SWIF_HAIFA_IV_256[SWIFFTX_OUTPUT_BLOCK_SIZE];
const BitSequence SWIF_HAIFA_IV_384[SWIFFTX_OUTPUT_BLOCK_SIZE];
const BitSequence SWIF_HAIFA_IV_512[SWIFFTX_OUTPUT_BLOCK_SIZE];*/

typedef enum 
{ 
	SUCCESS = 0,
	FAIL = 1,
	BAD_HASHBITLEN = 2,
	BAD_SALT_SIZE = 3,
	SET_SALT_VALUE_FAILED = 4,
	INPUT_DATA_NOT_ALIGNED = 5
} HashReturn;

typedef struct hashState {
	unsigned short hashbitlen;

	// The data remained after the recent call to 'Update()'. 
	BitSequence remaining[SWIF_HAIFA_INPUT_BLOCK_SIZE + 1];

	// The size of the remaining data in bits.
	// Is 0 in case there is no remaning data at all.
	unsigned int remainingSize;

	// The current output of the compression function. At the end will contain the final digest
	// (which may be needed to be truncated, depending on hashbitlen).
	BitSequence currOutputBlock[SWIFFTX_OUTPUT_BLOCK_SIZE];

	// The value of '#bits hashed so far' field in HAIFA, in base 256.
	BitSequence numOfBitsChar[SWIF_HAIFA_NUM_OF_BITS_SIZE];

	// The salt value currently in use:
	BitSequence salt[SWIF_HAIFA_SALT_SIZE];

	// Indicates whether a single 'Update()' occured. 
	// Ater a call to 'Update()' the key and the salt values cannot be changed.
	bool wasUpdated;
} hashState;

private:
int swifftxNumRounds;
hashState swifftxState;


public:
int Init(int hashbitlen);
int Update(const BitSequence *data, DataLength databitlen);
int Final(BitSequence *hashval);
int Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, 
				BitSequence *hashval);

private:
static void AddToCurrInBase256(BitSequence value[SWIF_HAIFA_NUM_OF_BITS_SIZE], unsigned short toAdd);

};

#endif