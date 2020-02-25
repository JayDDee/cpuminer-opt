#ifdef __SSE2__
#include "opt.c"
#elif defined(__aarch64__)
#include "opt.c"
#else
#include "ref.c"
#endif
