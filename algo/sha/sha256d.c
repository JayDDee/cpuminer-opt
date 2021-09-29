#include "sha256d.h"

void sha256d( void *hash, const void *data, int len )
{
   sha256_full( hash, data, len );
   sha256_full( hash, hash,  32 );
}

