extern int scanhash_hodl( int thr_id, struct work* work, uint32_t max_nonce,
    uint64_t *hashes_done );

extern void GetPsuedoRandomData( char* mainMemoryPsuedoRandomData,
                  uint32_t *pdata, int thr_id );

void hodl_set_target( struct work* work, double diff );

void hodl_copy_workdata( struct work* work, struct work* g_work );


