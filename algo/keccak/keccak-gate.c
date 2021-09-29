#include "keccak-gate.h"
#include "sph_keccak.h"
#include "algo/sha/sha256d.h"

int hard_coded_eb = 1;

// KECCAK

bool register_keccak_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT | AVX512_OPT;
  gate->gen_merkle_root = (void*)&SHA256_gen_merkle_root;
  opt_target_factor = 128.0;
#if defined (KECCAK_8WAY)
  gate->scanhash  = (void*)&scanhash_keccak_8way;
  gate->hash      = (void*)&keccakhash_8way;
#elif defined (KECCAK_4WAY)
  gate->scanhash  = (void*)&scanhash_keccak_4way;
  gate->hash      = (void*)&keccakhash_4way;
#else
  gate->scanhash  = (void*)&scanhash_keccak;
  gate->hash      = (void*)&keccakhash;
#endif
  return true;
};

// KECCAKC

bool register_keccakc_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT | AVX512_OPT;
  gate->gen_merkle_root = (void*)&sha256d_gen_merkle_root;
  opt_target_factor = 256.0;
#if defined (KECCAK_8WAY)
  gate->scanhash  = (void*)&scanhash_keccak_8way;
  gate->hash      = (void*)&keccakhash_8way;
#elif defined (KECCAK_4WAY)
  gate->scanhash  = (void*)&scanhash_keccak_4way;
  gate->hash      = (void*)&keccakhash_4way;
#else
  gate->scanhash  = (void*)&scanhash_keccak;
  gate->hash      = (void*)&keccakhash;
#endif
  return true;
};

// SHA3D

void sha3d( void *state, const void *input, int len )
{
	uint32_t _ALIGN(64) buffer[16], hash[16];
	sph_keccak_context ctx_keccak;

	sph_keccak256_init( &ctx_keccak );
	sph_keccak256 ( &ctx_keccak, input, len );
	sph_keccak256_close( &ctx_keccak, (void*) buffer );

   sph_keccak256_init( &ctx_keccak );
	sph_keccak256 ( &ctx_keccak, buffer, 32 );
	sph_keccak256_close( &ctx_keccak, (void*) hash );

	memcpy(state, hash, 32);
}

void sha3d_gen_merkle_root( char* merkle_root, struct stratum_ctx* sctx )
{
  sha3d( merkle_root, sctx->job.coinbase, (int) sctx->job.coinbase_size );
  for ( int i = 0; i < sctx->job.merkle_count; i++ )
  {
     memcpy( merkle_root + 32, sctx->job.merkle[i], 32 );
     sha256d( merkle_root, merkle_root, 64 );
  }
}

bool register_sha3d_algo( algo_gate_t* gate )
{
  hard_coded_eb = 6;
//  opt_extranonce = false;
  gate->optimizations = AVX2_OPT | AVX512_OPT;
  gate->gen_merkle_root = (void*)&sha3d_gen_merkle_root;
#if defined (KECCAK_8WAY)
  gate->scanhash  = (void*)&scanhash_sha3d_8way;
  gate->hash      = (void*)&sha3d_hash_8way;
#elif defined (KECCAK_4WAY)
  gate->scanhash  = (void*)&scanhash_sha3d_4way;
  gate->hash      = (void*)&sha3d_hash_4way;
#else
  gate->scanhash  = (void*)&scanhash_sha3d;
  gate->hash      = (void*)&sha3d_hash;
#endif
  return true;
};

