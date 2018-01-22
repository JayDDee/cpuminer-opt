#ifdef __SSE2__
#include "yescrypt-simd.c"
#elif defined(__aarch64__)
#include "yescrypt-neon.c"
#else
#include "yescrypt-opt.c"
#endif
