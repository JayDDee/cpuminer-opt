#define _mm_malloc(size, al) aligned_alloc(al, size)
#define _mm_free(ptr) free(ptr)