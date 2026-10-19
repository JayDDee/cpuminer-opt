/*-
 * Copyright 2013-2018 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef __unix__
#include <sys/mman.h>
#endif

#define HUGEPAGE_THRESHOLD		(12 * 1024 * 1024)

/* aarch64 with the usual 4 KiB granule has the same 2 MiB PMD as x86-64; it
 * was excluded here only because upstream never targeted it. Wrong for a
 * 16/64 KiB granule kernel (PMD 32 MiB / 512 MiB), which then simply keeps its
 * base pages -- i.e. the behaviour it has today anyway. */
#if defined(__x86_64__) || defined(__aarch64__)
#define HUGEPAGE_SIZE			(2 * 1024 * 1024)
#else
#undef HUGEPAGE_SIZE
#endif

static void *alloc_region(yespower_region_t *region, size_t size)
{
	size_t base_size = size;
	uint8_t *base, *aligned;
#ifdef MAP_ANON
	int flags =
#ifdef MAP_NOCORE
	    MAP_NOCORE |
#endif
	    MAP_ANON | MAP_PRIVATE;
#if defined(MAP_HUGETLB) && defined(HUGEPAGE_SIZE)
   size_t new_size = size;
	const size_t hugepage_mask = (size_t)HUGEPAGE_SIZE - 1;
	if (size >= HUGEPAGE_THRESHOLD && size + hugepage_mask >= size) {
		flags |= MAP_HUGETLB;
/*
 * Linux's munmap() fails on MAP_HUGETLB mappings if size is not a multiple of
 * huge page size, so let's round up to huge page size here.
 */
		new_size = size + hugepage_mask;
		new_size &= ~hugepage_mask;
	}
	/* Only attempt the reserved-huge-page mapping when it is even eligible; do
	 * not take a plain mapping here, or the THP path below is skipped. */
	base = MAP_FAILED;
	if (flags & MAP_HUGETLB)
		base = mmap(NULL, new_size, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (base != MAP_FAILED) {
		base_size = new_size;

	} else {
		/* Must run whenever MAP_HUGETLB backing was not obtained, which on a
		 * stock box is always. Keep it out of an `else if (flags & MAP_HUGETLB)`
		 * arm: MAP_HUGETLB is only attempted above HUGEPAGE_THRESHOLD, so every
		 * variant below that would silently keep 4 KiB pages. */
		flags &= ~MAP_HUGETLB;
/*
 * MAP_HUGETLB only succeeds where pages were reserved in advance
 * (vm.nr_hugepages), which is 0 on a stock system, so this is the path
 * essentially every miner takes. Transparent huge pages need no privileges;
 * take them rather than settle for 4 KiB. The kernel can only promote a
 * 2 MiB-ALIGNED range and mmap does not guarantee one, so over-map by a huge
 * page and align forward. Only whole huge pages are advised; the tail stays
 * 4 KiB, which is harmless. Worth a few percent, and it also removes a large
 * run-to-run variance caused by where the physical 4 KiB pages happen to land.
 */
#if defined(MADV_HUGEPAGE) && defined(HUGEPAGE_SIZE) && !defined(YP_NO_THP)
		if (size >= (size_t)HUGEPAGE_SIZE &&
		    size + hugepage_mask > size) {
			size_t s2 = size + hugepage_mask;
			base = mmap(NULL, s2, PROT_READ | PROT_WRITE, flags, -1, 0);
			if (base != MAP_FAILED) {
				base_size = s2;
				aligned = (uint8_t *)(((uintptr_t)base + hugepage_mask)
				                      & ~(uintptr_t)hugepage_mask);
				/* Advisory: a failure here costs speed, not correctness. */
				madvise(aligned, size & ~hugepage_mask, MADV_HUGEPAGE);
				region->base = base;
				region->aligned = aligned;
				region->base_size = base_size;
				region->aligned_size = size;
				return aligned;
			}
		}
#endif
		base = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
	}

#else
	base = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
#endif
	if (base == MAP_FAILED)
		base = NULL;
	aligned = base;
#elif defined(HAVE_POSIX_MEMALIGN)
	if ((errno = posix_memalign((void **)&base, 64, size)) != 0)
		base = NULL;
	aligned = base;
#else
	base = aligned = NULL;
	if (size + 63 < size) {
		errno = ENOMEM;
	} else if ((base = malloc(size + 63)) != NULL) {
		aligned = base + 63;
		aligned -= (uintptr_t)aligned & 63;
	}
#endif
	region->base = base;
	region->aligned = aligned;
	region->base_size = base ? base_size : 0;
	region->aligned_size = base ? size : 0;
	return aligned;
}

static inline void init_region(yespower_region_t *region)
{
	region->base = region->aligned = NULL;
	region->base_size = region->aligned_size = 0;
}

static int free_region(yespower_region_t *region)
{
	if (region->base) {
#ifdef MAP_ANON
		if (munmap(region->base, region->base_size))
			return -1;
#else
		free(region->base);
#endif
	}
	init_region(region);
	return 0;
}
