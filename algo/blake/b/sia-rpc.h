#include <miner.h>

char* sia_getheader(CURL *curl, struct pool_infos *pool);
bool sia_work_decode(const char *hexdata, struct work *work);
bool sia_submit(CURL *curl, struct pool_infos *pool, struct work *work);

