#include "malloc-huge.h"
#include "miner.h"

#define HUGEPAGE_SIZE_2M  (2 * 1024 * 1024)

void *malloc_hugepages( size_t size )
{
#if !(defined(MAP_HUGETLB) && defined(MAP_ANON))
//   applog( LOG_WARNING, "Huge pages not available",size);
   return NULL;
#else

   if ( size < HUGEPAGE_MIN_ALLOC )
   {
//	   applog( LOG_WARNING, "Block too small for huge pages: %lu bytes",size);
	   return NULL;
   }

   const size_t hugepage_mask = (size_t)HUGEPAGE_SIZE_2M - 1;
   void *p = NULL;
   int flags =
   #ifdef MAP_NOCORE
                MAP_NOCORE |
   #endif
		          MAP_HUGETLB | MAP_ANON | MAP_PRIVATE;

   // round size up to next page boundary
   size = ( size + hugepage_mask ) & (~hugepage_mask);
   
   p = mmap( NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0 );
   if ( p == MAP_FAILED )
      p = NULL;
   return p;
#endif
}

