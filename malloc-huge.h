#if !(defined(MALLOC_HUGE__))
#define MALLOC_HUGE__

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __unix__
#include <sys/mman.h>
#endif

#if defined(MAP_HUGETLB)

// Minimum block size 6 MiB to use huge pages
#define HUGEPAGE_MIN_ALLOC    (6 * 1024 * 1024)

#endif

// Attempt to allocate memory backed by 2 MiB pages, returns NULL on failure.
void *malloc_hugepages( size_t size );

// Release a block from malloc_hugepages(). This is mmap'd memory, NOT malloc'd:
// free() on it is undefined. Pass the ORIGINAL requested size, the page
// rounding is repeated here. Callers must remember which allocator they got
// their block from -- the pointer does not say.
void free_hugepages( void *p, size_t size );

#endif

