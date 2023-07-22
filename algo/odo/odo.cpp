extern "C" {
#include "algo-gate-api.h"
}
#include "odocrypt.h"
#include "KeccakP-800-SnP.h"

static uint32_t OdoKey(uint32_t nOdoShapechangeInterval, uint32_t nTime)
{
  uint32_t nShapechangeInterval = nOdoShapechangeInterval;
  return nTime - nTime % nShapechangeInterval;
}

extern "C" bool odo_miner_thread_init( int thr_id )
{
  return true;
}

extern "C" int scanhash_odo( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
  static constexpr uint32_t OdoShapechangeInterval = 1*24*60*60;

  uint32_t throughput = 1;
  int thr_id = mythr->id;
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  uint32_t n = pdata[19] - 1;
  uint32_t data[20];
  volatile uint8_t *restart = &(work_restart[thr_id].restart);

  for (unsigned i = 0; i < 20; i++)
    data[i] = __builtin_bswap32(pdata[i]);

  char cipher[KeccakP800_stateSizeInBytes];
  uint32_t key = OdoKey(OdoShapechangeInterval, data[17]);
  size_t len = 80;

  do {
    data[19] = __builtin_bswap32(++n);

    // Calculate odocrypt
    memset(cipher, 0, sizeof(cipher));
    memcpy(cipher, data, len);
    cipher[len] = 1;
    OdoCrypt(key).Encrypt(cipher, cipher);
    KeccakP800_Permute_12rounds(cipher);
    if ( unlikely( valid_hash( cipher, ptarget ) ) ) {
      pdata[19] = __builtin_bswap32(data[19]);
      submit_solution( work, cipher, mythr );
    }
  } while ( likely( ( n < ( max_nonce - 1 ) ) && !(*restart) ) );

  *hashes_done = n - pdata[19];
  pdata[19] = n;
  return 0;
}

extern "C" bool register_odo_algo( algo_gate_t* gate )
{
  gate->miner_thread_init = &odo_miner_thread_init;
  gate->scanhash         = &scanhash_odo;
  return true;
};
