#pragma once

/*
	The pool allocator
*/

#if DBG
#undef  __PALLOC_DEBUG_
#define __PALLOC_DEBUG_
#endif

#ifdef __PALLOC_DEBUG_
#define PALLOC_ASSERT(exp) \
		((!(exp)) ? (RtlAssert(#exp, __FILE__, __LINE__, NULL), FALSE) : TRUE)
#else
#define PALLOC_ASSERT(exp)	ASSERT(exp)	
#endif

typedef struct _POOL_ALLOCATOR_PAGE  POOL_ALLOCATOR_PAGE,  *PPOOL_ALLOCATOR_PAGE;
typedef struct _POOL_ALLOCATOR_CHUNK POOL_ALLOCATOR_CHUNK, *PPOOL_ALLOCATOR_CHUNK;

struct _POOL_ALLOCATOR_CHUNK {
	SLIST_ENTRY		Entry;
};

struct _POOL_ALLOCATOR_PAGE {
	SLIST_ENTRY				Entry;
	POOL_ALLOCATOR_CHUNK	Chunks[1];
};

typedef struct _POOL_ALLOCATOR {
	ULONG			ChunkSize;
	POOL_TYPE		PoolType;
	ULONG			Tag;

	SLIST_HEADER	PageList;
	SLIST_HEADER	FreeList;

// Debug counters
#ifdef __PALLOC_DEBUG_
	LONG			Pages;
	LONG			Allocated;
#endif
} POOL_ALLOCATOR, *PPOOL_ALLOCATOR;

#define POOL_ALLOCATOR_PAGE_SZ         PAGE_SIZE
#define POOL_ALLOCATOR_PAGE_OVERHEAD   FIELD_OFFSET(POOL_ALLOCATOR_PAGE, Chunks)
#define POOL_ALLOCATOR_MAX_CHUNK       (POOL_ALLOCATOR_PAGE_SZ - POOL_ALLOCATOR_PAGE_OVERHEAD)
#define POOL_ALLOCATOR_CHUNK_ALIGNMENT MEMORY_ALLOCATION_ALIGNMENT
#define POOL_ALLOCATOR_CHUNK_ALIGN(sz) ((sz+POOL_ALLOCATOR_CHUNK_ALIGNMENT-1)&(~(POOL_ALLOCATOR_CHUNK_ALIGNMENT-1)))

C_ASSERT(FIELD_OFFSET(POOL_ALLOCATOR_PAGE,  Entry) == 0);
C_ASSERT(FIELD_OFFSET(POOL_ALLOCATOR_CHUNK, Entry) == 0);

FORCEINLINE
VOID PoolInitialize(
		IN PPOOL_ALLOCATOR Pool,
		IN ULONG ChunkSize,
		IN POOL_TYPE PoolType,
		IN ULONG Tag
	)
{
	ChunkSize = POOL_ALLOCATOR_CHUNK_ALIGN(ChunkSize);

	PALLOC_ASSERT(ChunkSize && ChunkSize <= POOL_ALLOCATOR_MAX_CHUNK);

	RtlZeroMemory(Pool, sizeof(*Pool));
	
	Pool->ChunkSize	= ChunkSize;
	Pool->PoolType	= PoolType;
	Pool->Tag		= Tag;

	InitializeSListHead(&Pool->PageList);
	InitializeSListHead(&Pool->FreeList);
}

FORCEINLINE
VOID PoolRelease(PPOOL_ALLOCATOR Pool)
{
	PSLIST_ENTRY page;
	while (page = InterlockedPopEntrySList(&Pool->PageList)) 
		ExFreePoolWithTag(page, Pool->Tag);

#ifdef __PALLOC_DEBUG_
	PALLOC_ASSERT(!Pool->Allocated);
	RtlZeroMemory(Pool, sizeof(*Pool));	
#endif
}

FORCEINLINE
PVOID PoolAllocateChunk(PPOOL_ALLOCATOR Pool)
{
	PVOID chunk;
	for (;;) {
		if (!(chunk = InterlockedPopEntrySList(&Pool->FreeList))) {
#pragma prefast(suppress:8139, "arguments exactly match required types")
			PPOOL_ALLOCATOR_PAGE page = (PPOOL_ALLOCATOR_PAGE)ExAllocatePoolWithTag(Pool->PoolType, POOL_ALLOCATOR_PAGE_SZ, Pool->Tag);
			if (!page)
				return 0;
			else {
				PPOOL_ALLOCATOR_CHUNK ptr;
				ULONG size = POOL_ALLOCATOR_PAGE_SZ - POOL_ALLOCATOR_PAGE_OVERHEAD;
				for (
					ptr = page->Chunks; 
					size >= Pool->ChunkSize; 
					ptr = (PPOOL_ALLOCATOR_CHUNK)((char*)ptr + Pool->ChunkSize), size -= Pool->ChunkSize
				) 
					InterlockedPushEntrySList(&Pool->FreeList, &ptr->Entry);

#ifdef __PALLOC_DEBUG_
				InterlockedIncrement(&Pool->Pages);	
#endif
				InterlockedPushEntrySList(&Pool->PageList, &page->Entry);
			}
		} else
			break;
	}
#ifdef __PALLOC_DEBUG_
	InterlockedIncrement(&Pool->Allocated);	
#endif
	return chunk;
}

FORCEINLINE
VOID PoolFreeChunk(PPOOL_ALLOCATOR Pool, PVOID Chunk)
{
#ifdef __PALLOC_DEBUG_
	LONG allocated = InterlockedDecrement(&Pool->Allocated);	
	PALLOC_ASSERT(allocated >= 0);
#endif
	InterlockedPushEntrySList(&Pool->FreeList, (PSLIST_ENTRY)Chunk);
}

