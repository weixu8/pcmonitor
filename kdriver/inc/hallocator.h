#pragma once
#include <inc/drvmain.h>

typedef struct _HALLOCATOR {
	ULONG			ChunkSize;
	ULONG			SegmentSize;
	ULONG			Tag;
	LONG			PreAllocChunksCount;
	SLIST_HEADER	SegmentList;
	SLIST_HEADER	FreeList;
	volatile LONG	SegmentListDepth;
	volatile LONG	FreeListDepth;
	KDPC			GrowDpc;
	volatile LONG	Releasing;
} HALLOCATOR, *PHALLOCATOR;

#define HALLOCATOR_DBG 0

#define HALLOCATOR_CHUNK_SIGNATURE 0xBEDABEDA

typedef struct _HALLOCATOR_CHUNK {
	SLIST_ENTRY		ListEntry;
#if HALLOCATOR_DBG
	LONG			Signature;
#endif
} HALLOCATOR_CHUNK, *PHALLOCATOR_CHUNK;

typedef struct _HALLOCATOR_SEGMENT{
	SLIST_ENTRY				ListEntry;
	HALLOCATOR_CHUNK		Chunks[1];
} HALLOCATOR_SEGMENT, *PHALLOCATOR_SEGMENT;

#define HALLOCATOR_CHUNK_ALIGNMENT MEMORY_ALLOCATION_ALIGNMENT
#define HALLOCATOR_CHUNK_ALIGN(sz) ((sz+HALLOCATOR_CHUNK_ALIGNMENT-1)&(~(HALLOCATOR_CHUNK_ALIGNMENT-1)))

FORCEINLINE
VOID
	HAllocatorGrow(
		PHALLOCATOR Allocator
		)
{
	PHALLOCATOR_SEGMENT Segment = NULL;
	PHALLOCATOR_CHUNK Chunk = NULL;

	Segment = (PHALLOCATOR_SEGMENT)ExAllocatePoolWithTag(NonPagedPool, Allocator->SegmentSize, Allocator->Tag);
	if (Segment == NULL) {
		__debugbreak();
		return;
	}
#if HALLOCATOR_DBG
	DbgPrint("HALLOC: alloc segment=%p size= %x\n", Segment, Allocator->SegmentSize);
#endif

	InterlockedPushEntrySList(&Allocator->SegmentList, &Segment->ListEntry);
	InterlockedIncrement(&Allocator->SegmentListDepth);

	Chunk = &Segment->Chunks[0];

	while (((ULONG_PTR)Chunk + Allocator->ChunkSize) <= ((ULONG_PTR)Segment + Allocator->SegmentSize)) {
#if HALLOCATOR_DBG
		DbgPrint("HALLOC: grow alloc chunk=%p, size= %x\n", Chunk, Allocator->ChunkSize);
		Chunk->Signature = HALLOCATOR_CHUNK_SIGNATURE;
#endif
		InterlockedPushEntrySList(&Allocator->FreeList, &Chunk->ListEntry);
		InterlockedIncrement(&Allocator->FreeListDepth);
		Chunk = (PHALLOCATOR_CHUNK)((ULONG_PTR)Chunk + Allocator->ChunkSize);
	}
}

FORCEINLINE
VOID
	HAllocatorFree(
		IN PHALLOCATOR Allocator,
		IN PVOID Ptr
		)
{
	PHALLOCATOR_CHUNK Chunk = (PHALLOCATOR_CHUNK)Ptr;
	if (Allocator->Releasing)
		return;

#if HALLOCATOR_DBG
	DbgPrint("HALLOC: free push chunk=%p, size= %x\n", Chunk, Allocator->ChunkSize);
	Chunk->Signature = HALLOCATOR_CHUNK_SIGNATURE;
#endif
	InterlockedPushEntrySList(&Allocator->FreeList, &Chunk->ListEntry);
	InterlockedIncrement(&Allocator->FreeListDepth);
}

FORCEINLINE
PVOID
	HAllocatorAlloc(
		IN PHALLOCATOR Allocator
		)
{
	PHALLOCATOR_CHUNK Chunk = NULL;
	if (Allocator->Releasing)
		return NULL;

	Chunk = (PHALLOCATOR_CHUNK)InterlockedPopEntrySList(&Allocator->FreeList);
#if HALLOCATOR_DBG
	DbgPrint("HALLOC: alloc pop chunk=%p, size= %x\n", Chunk, Allocator->ChunkSize);
#endif

	if (Chunk == NULL) {
#if HALLOCATOR_DBG
		DbgPrint("HALLOC: alloc failure\n");
#endif
		__debugbreak();
		return NULL;
	}

#if HALLOCATOR_DBG
	if (Chunk->Signature != HALLOCATOR_CHUNK_SIGNATURE) {
		DbgPrint("HALLOC: alloc pop chunk=%p, size= %x signature incorrect\n", Chunk, Allocator->ChunkSize);
		__debugbreak();
	}
#endif

	if ((InterlockedDecrement(&Allocator->FreeListDepth) < Allocator->PreAllocChunksCount) && (!Allocator->Releasing))
		KeInsertQueueDpc(&Allocator->GrowDpc, NULL, NULL);

	return Chunk;
}

FORCEINLINE
VOID 
	HAllocatorGrowDpc(
		PKDPC Dpc,
		PVOID DeferredContext,
		PVOID SystemArgument1,
		PVOID SystemArgument2
	)
{
	PHALLOCATOR Allocator = (PHALLOCATOR)DeferredContext;
	if (!Allocator->Releasing)
		HAllocatorGrow(Allocator);
}

FORCEINLINE
VOID
	HAllocatorInit(
		PHALLOCATOR Allocator,
		ULONG		ChunkSize,
		LONG		PreAllocChunksCount,
		ULONG		SegmentSize,
		ULONG		Tag)
{
	RtlZeroMemory(Allocator, sizeof(HALLOCATOR));

	Allocator->SegmentSize = SegmentSize;
	Allocator->Tag = Tag;
	Allocator->FreeListDepth = 0;
	Allocator->PreAllocChunksCount = PreAllocChunksCount;
	Allocator->ChunkSize = HALLOCATOR_CHUNK_ALIGN(ChunkSize + sizeof(HALLOCATOR_CHUNK));

	InitializeSListHead(&Allocator->SegmentList);
	InitializeSListHead(&Allocator->FreeList);
	KeInitializeDpc(&Allocator->GrowDpc, HAllocatorGrowDpc, Allocator);

#if HALLOCATOR_DBG
	DbgPrint("HALLOC: allocator=%p, FreeListDepth=%x, PreAllocChunksCount=%x chunksize=%x segmentsize=%x\n", Allocator, 
		Allocator->FreeListDepth, Allocator->PreAllocChunksCount, Allocator->ChunkSize, Allocator->SegmentSize);
#endif

	while (Allocator->FreeListDepth < Allocator->PreAllocChunksCount) {
#if HALLOCATOR_DBG
		DbgPrint("HALLOC: allocator=%p, FreeListDepth=%x, PreAllocChunksCount=%x\n", Allocator, 
			Allocator->FreeListDepth, Allocator->PreAllocChunksCount);
#endif
		HAllocatorGrow(Allocator);
	}

}

FORCEINLINE
VOID
HAllocatorRelease(
	PHALLOCATOR Allocator
	)
{
	PHALLOCATOR_SEGMENT Segment = NULL;
	
	Allocator->Releasing = 1;
	KeFlushQueuedDpcs();

	while ((Segment = (PHALLOCATOR_SEGMENT)InterlockedPopEntrySList(&Allocator->SegmentList)) != NULL) {
		ExFreePoolWithTag(Segment, Allocator->Tag);
	}
}
