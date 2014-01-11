#pragma once

/*
	The tree of hashes facilitating fast lookup and small memory footprint
	2-directional hash list version
*/

#include <inc\pallocator.h>
#include <inc\shrlock.h>

#if DBG
#undef  __THASH_DEBUG_
#define __THASH_DEBUG_
#endif

typedef struct _THASH       THASH,       *PTHASH;
typedef struct _THASH_ENTRY THASH_ENTRY, *PTHASH_ENTRY;
typedef struct _THASH_NODE  THASH_NODE,  *PTHASH_NODE;

// Data entry header.
// The data is always allocated by the clients.
// In case it has fixed size it always recommeded to use pool allocator
// since it is already used for nodes (see pallocator.h).
struct _THASH_ENTRY {
	PTHASH_ENTRY	Next;
	PTHASH_ENTRY	Prev;
};

// The tree node
struct _THASH_NODE {
	union {
		PTHASH_NODE		Child[2];	// Child node pointer
		PTHASH_ENTRY	Leaf[2];	// Leaf (linked entries list) pointer
	};
	union {
		LONG			LockCount;	// Node lock counter
		struct {
			UCHAR		Locked;		// Since we may lock node at and above DPC only
									// the lock count can't exceed the number of CPU
			UCHAR		ChildIndx;	// 0 or 1 depending at which side we are from the parent
			UCHAR		LeafSz[2];	// The number of entries in the leaf
		};
	};
#ifdef __THASH_DEBUG_
	UCHAR				Level;		// The distance from the tree root
#endif
};

C_ASSERT(FIELD_OFFSET(THASH_NODE,Locked) == FIELD_OFFSET(THASH_NODE,LockCount));

// In normal situation the list length shouldn't reach this limit.
// But even if it does we just stop incrementing counter and increment.
// Overflow counter in THASH struct.
#define THASH_LEAVES_OVERFLOW ((UCHAR)(~0))

#define THASH_ROOT_BITS       8
#define THASH_ROOT_BRANCHES   (1<<THASH_ROOT_BITS)
#define THASH_MAX_DEPTH       (32-THASH_ROOT_BITS)
#define THASH_TAG             'hsHT'

#ifdef __THASH_COMPACT_ // Compact but slow
#define LEAFS_SPLIT_THRESHOLD 16
#define LEAFS_JOIN_THRESHOLD  8
#else
#define LEAFS_SPLIT_THRESHOLD 8
#endif

// Hash function
typedef ULONG (NTAPI *PTHASH_HASH_FN)(PTHASH_ENTRY Entry);

// Comparison function, returns TRUE if Entry is equal to Key
typedef BOOLEAN (NTAPI *PTHASH_COMPARE_FN)(PTHASH_ENTRY Entry, PTHASH_ENTRY Key);

// Destructor called on entry deletion
typedef VOID (NTAPI *PTHASH_DESTROY_FN)(PTHASH_ENTRY Entry, PVOID Context);

// Table scan callback
typedef UCHAR (NTAPI *PTHASH_SCAN_FN)(PTHASH_ENTRY Entry, PVOID Context);

// Plain callback
typedef VOID (NTAPI *PTHASH_CALLBACK_FN)(PTHASH_ENTRY Entry, PVOID Context);

// Scan codes bits
typedef enum {
	tHashContinue	= 0,	// Go ahead with next entry
	tHashBreak		= 1,	// Stop scaning
	tHashRemove		= 2,	// Remove from the table
	tHashDestroy	= 4,	// Call destructor
	tHashRestart	= 8		// Restart enumeration
};

// The tree root with lock
typedef struct _THASH_BRANCH {
	THASH_NODE			Root;
	KSHARED_SPIN_LOCK	Lock;
} THASH_BRANCH, *PTHASH_BRANCH;

// The whole table
struct _THASH {
	THASH_BRANCH			Branch[THASH_ROOT_BRANCHES];
	POOL_ALLOCATOR			NodeAllocator;
	PTHASH_HASH_FN			HashFn;
	PTHASH_COMPARE_FN		CompareFn;
	PTHASH_DESTROY_FN		DestroyFn;
	PVOID					DestroyContext;
#ifdef __THASH_DEBUG_
	// Debug counters
	LONG					Entries;
	LONG					Nodes;
	LONG					MaxLevel;
	LONG					Overflow;
	LONG					FailedAllocations;
#endif
};

// The data structure keeping state for non recursive iteration and lookup
typedef struct _THASH_ITERATOR {
	PTHASH_NODE		nodes[THASH_MAX_DEPTH]; // The path in the tree
	UCHAR			level;		// The distance from the root
	UCHAR			index;		// 0,1 depending at which side we are from the node
	PTHASH_ENTRY*	leafHead;	// Pointer to the leaf entry list header
	PUCHAR			leafSz;		// Pointer to the entry list size
} THASH_ITERATOR, *PTHASH_ITERATOR;

// We always allocate iterators on the stack
#ifdef __THASH_DEBUG_
#define THASH_ITERATOR_INITIALIZER(Branch) {{&(Branch)->Root, 0}, ~0, ~0, 0, 0}
#else
#define THASH_ITERATOR_INITIALIZER(Branch) {{&(Branch)->Root}}
#endif

//----------------- Helpers ---------------------------------------------

#ifdef __THASH_DEBUG_
#define THASH_ASSERT(exp) \
		((!(exp)) ? (__debugbreak(), FALSE) : TRUE)
#define THASH_FILL 0xcc
#else
#define THASH_ASSERT(exp)	ASSERT(exp)	
#endif

// Select tree based on the hash value
FORCEINLINE
PTHASH_BRANCH thashGetBranch(
		IN PTHASH Table,
		IN ULONG Hash
	)
{
	return &Table->Branch[Hash & ((1 << THASH_ROOT_BITS) - 1)];
}

// Lock individual tree
FORCEINLINE
VOID thashLockBranch(
		IN PTHASH_BRANCH Branch,
		IN BOOLEAN Exclusive,
		OUT PKIRQL pOldIrql
	)
{
	KIRQL Irql = KeGetCurrentIrql();
	if (Exclusive) {
		if (Irql >= DISPATCH_LEVEL) {
			KeAcquireSpinLockExclusiveAtDpcLevel(&Branch->Lock);
			*pOldIrql = Irql;
		} else {
			KeAcquireSpinLockExclusive(&Branch->Lock, pOldIrql);
		}
	} else {
		if (Irql >= DISPATCH_LEVEL) {
			KeAcquireSpinLockSharedAtDpcLevel(&Branch->Lock);
			*pOldIrql = Irql;
		} else {
			KeAcquireSpinLockShared(&Branch->Lock, pOldIrql);
		}
	}
}

// Unlock individual tree
FORCEINLINE
VOID thashUnlockBranch(
		IN PTHASH_BRANCH Branch,
		IN BOOLEAN Exclusive,
		IN KIRQL OldIrql
	)
{
	if (Exclusive) {
		if (OldIrql >= DISPATCH_LEVEL) {
			KeReleaseSpinLockExclusiveFromDpcLevel(&Branch->Lock);
		} else {
			KeReleaseSpinLockExclusive(&Branch->Lock, OldIrql);
		}
	} else {
		if (OldIrql >= DISPATCH_LEVEL) {
			KeReleaseSpinLockSharedFromDpcLevel(&Branch->Lock);
		} else {
			KeReleaseSpinLockShared(&Branch->Lock, OldIrql);
		}
	}
}

FORCEINLINE 
VOID thashLockNode(IN PTHASH_ITERATOR iter)
{
	PTHASH_NODE node = iter->nodes[iter->level];
	THASH_ASSERT(node->Locked < (UCHAR)(~0));
	InterlockedIncrement(&node->LockCount);
}

FORCEINLINE 
VOID thashUnlockNode(IN PTHASH_ITERATOR iter)
{
	PTHASH_NODE node = iter->nodes[iter->level];
	THASH_ASSERT(node->Locked > 0);
	InterlockedDecrement(&node->LockCount);
}

// Upgrade lock to exclusive
FORCEINLINE
VOID thashUpgradeBranchLock(
		IN PTHASH_BRANCH Branch,
		IN PTHASH_ITERATOR iter
	)
{
	THASH_ASSERT(KeGetCurrentIrql() >= DISPATCH_LEVEL);
	THASH_ASSERT(iter->nodes[0] == &Branch->Root);

	thashLockNode(iter);
	KeReleaseSpinLockSharedFromDpcLevel(&Branch->Lock);
	KeAcquireSpinLockExclusiveAtDpcLevel(&Branch->Lock);
	thashUnlockNode(iter);
}

// Find leftmost leaf
FORCEINLINE 
VOID thashLeftmostLeaf(
		IN OUT PTHASH_ITERATOR iter
	)
{
	UCHAR i = 0, l = iter->level;
	for (;; ++l) {
		// Has something to the left
		if (iter->nodes[l]->Leaf[0]) {
			// Its a leaf
			if (iter->nodes[l]->LeafSz[0]) {
				i = 0;
				break;
			} 
			// Its a branch
			else {
				THASH_ASSERT(l < THASH_MAX_DEPTH-1);
				iter->nodes[l+1] = iter->nodes[l]->Child[0];
				THASH_ASSERT(iter->nodes[l+1]->ChildIndx == 0);
				continue;
			}
		}
		// Has something to the right
		if (iter->nodes[l]->Leaf[1]) {
			// Its a leaf
			if (iter->nodes[l]->LeafSz[1]) {
				i = 1;
				break;
			} 
			// Its a branch
			else {
				THASH_ASSERT(l < THASH_MAX_DEPTH-1);
				iter->nodes[l+1] = iter->nodes[l]->Child[1];
				THASH_ASSERT(iter->nodes[l+1]->ChildIndx == 1);
				continue;
			}
		}
		// Return empty leaf 
		break;
	}
	THASH_ASSERT(iter->nodes[l]->Level == l);
	iter->level = l;
	iter->index = i;
	iter->leafHead = &iter->nodes[l]->Leaf[i];
	iter->leafSz   = &iter->nodes[l]->LeafSz[i];
}

// Iterator initialization
FORCEINLINE 
VOID thashFirstLeaf(
		IN OUT PTHASH_ITERATOR iter
	)
{
	iter->level = 0;
	thashLeftmostLeaf(iter);
}

// Iteration
FORCEINLINE 
BOOLEAN thashNextLeaf(
		IN OUT PTHASH_ITERATOR iter
	)
{
	UCHAR l = iter->level, i = iter->index;
	for (;;) {
		if (!i) { // We were on the left
			// Has something to the right
			if (iter->nodes[l]->Leaf[1]) {
				// Its a leaf
				if (iter->nodes[l]->LeafSz[1]) {
					THASH_ASSERT(iter->nodes[l]->Level == l);
					iter->level = l;
					iter->index = 1;
					iter->leafHead = &iter->nodes[l]->Leaf[1];
					iter->leafSz   = &iter->nodes[l]->LeafSz[1];
					return TRUE;
				}
				// Its a branch
				else {
					THASH_ASSERT(l < THASH_MAX_DEPTH-1);
					iter->nodes[iter->level=l+1] = iter->nodes[l]->Child[1];
					THASH_ASSERT(iter->nodes[l+1]->ChildIndx == 1);
					thashLeftmostLeaf(iter);
					return TRUE;
				}
			}
		}
		i = iter->nodes[l]->ChildIndx;
		if (!l)
			return FALSE;
		--l; // Goes up
	}
}

// Find leaf by hash
FORCEINLINE 
VOID thashLeafByHash(
		IN ULONG Hash,
		IN OUT PTHASH_ITERATOR iter
	)
{
	UCHAR l = 0;
	PTHASH_NODE node = iter->nodes[0];
	Hash >>= THASH_ROOT_BITS;
	for (;;) {
		UCHAR i = (UCHAR)(Hash & 1); 
		// If have the branch lets dive into it
		if (!node->LeafSz[i] && node->Child[i]) {
			node = node->Child[i];
			iter->nodes[++l] = node;
			Hash >>= 1;
			THASH_ASSERT(l < THASH_MAX_DEPTH);
			THASH_ASSERT(node->Level == l);
			THASH_ASSERT(node->ChildIndx == i);
		} else {
			// Stop otherwise
			iter->level = l;
			iter->index = i;
			iter->leafHead = &iter->nodes[l]->Leaf[i];
			iter->leafSz   = &iter->nodes[l]->LeafSz[i];
			break;
		}
	}
}

FORCEINLINE 
VOID thashLeafInsertEntry(PTHASH_ENTRY* leafHead, PTHASH_ENTRY Entry)
{
	Entry->Prev = (PTHASH_ENTRY)leafHead;
	if ((Entry->Next = *leafHead))
		Entry->Next->Prev = Entry;
	*leafHead = Entry;
}

FORCEINLINE 
VOID thashLeafRemoveEntry(PTHASH_ENTRY Entry)
{
	if ((Entry->Prev->Next = Entry->Next))
		Entry->Next->Prev = Entry->Prev;
}

FORCEINLINE 
VOID thashLeafRemoveEntry_(PTHASH_ENTRY Entry, PTHASH_ENTRY Next)
{
	if ((Entry->Prev->Next = Next))
		Next->Prev = Entry->Prev;
}

FORCEINLINE 
VOID thashLeafJoin(PTHASH_ENTRY leafA, PTHASH_ENTRY leafB, PTHASH_ENTRY* newHead)
{
	PTHASH_ENTRY tail = (PTHASH_ENTRY)newHead;
	if (leafA) {
		tail->Next = leafA;
		leafA->Prev = tail;
		while (tail->Next)
			tail = tail->Next;
	} 
	if ((tail->Next = leafB))
		leafB->Prev = tail;
}

// Balance node after entry addition maintaining the tree
// Here the node allocation takes place
FORCEINLINE 
VOID thashBalanceAdded(
		IN PTHASH Table,
		IN PTHASH_ITERATOR iter
	)
{
	UCHAR l = iter->level, i = iter->index;
	PTHASH_NODE node = iter->nodes[l];
	
	if (
		node->LeafSz[i] > LEAFS_SPLIT_THRESHOLD &&
		l < THASH_MAX_DEPTH-1 &&
		!node->Locked 
	) {
		// Split leaf list 
		PTHASH_NODE n = (PTHASH_NODE)PoolAllocateChunk(&Table->NodeAllocator);
		if (n) {
			PTHASH_ENTRY e, e_;
#ifdef __THASH_DEBUG_	
			InterlockedIncrement(&Table->Nodes);
#endif
			RtlZeroMemory(n, sizeof(*n));
			// Go next level down
			++l;
#ifdef __THASH_DEBUG_
			n->Level = l;  
#endif
			n->ChildIndx = i;
			for (e = node->Leaf[i]; e; e = e_) {
				UCHAR j = (UCHAR)((Table->HashFn(e) >> (l + THASH_ROOT_BITS)) & 1);
				e_ = e->Next;
				thashLeafInsertEntry(&n->Leaf[j], e);
				if (n->LeafSz[j] != THASH_LEAVES_OVERFLOW)
					++n->LeafSz[j];
			}
			node->LeafSz[i] = 0;
			node->Child[i]  = n;
		} else {
			// Not catastrophic failure
			// The code should work even in case all allocation will fail
#ifdef __THASH_DEBUG_	
			InterlockedIncrement(&Table->FailedAllocations);
#endif
		}
	}
#ifdef __THASH_DEBUG_
	for (;;) {
		LONG MaxLevel = (LONG)Table->MaxLevel;
		if (
			MaxLevel >= l ||
			MaxLevel == InterlockedCompareExchange(&Table->MaxLevel, l, MaxLevel)
		)
			break;
	}
	// Invalidate iterator
	RtlZeroMemory(iter->nodes, sizeof(iter->nodes));
#endif
}

#ifdef __THASH_COMPACT_ // Compact but slow

// Balance node after entry removed maintaining the tree
// Here the node deallocation takes place
FORCEINLINE 
VOID thashBalanceRemoved(
		IN PTHASH Table,
		IN PTHASH_ITERATOR iter
	)
{
	UCHAR l = iter->level, i = iter->index, c0, c1;
	PTHASH_NODE node = iter->nodes[l];

	if (
		l &&
		((c0 = node->LeafSz[0]) || !node->Child[0]) &&
		((c1 = node->LeafSz[1]) || !node->Child[1]) &&
		(ULONG)c0 + (ULONG)c1 < LEAFS_JOIN_THRESHOLD &&
		!node->Locked 
	) {
		// Join leaf lists
		PTHASH_ENTRY l0 = node->Leaf[0], l1 = node->Leaf[1];
		while (l) {
			i = node->ChildIndx;
			THASH_ASSERT(iter->nodes[l-1]->Child[i] == node);
			THASH_ASSERT(!iter->nodes[l-1]->LeafSz[i]);
			THASH_ASSERT(!node->Locked);
			// Free node
#ifdef __THASH_DEBUG_
			{
				LONG n = InterlockedDecrement(&Table->Nodes);
				THASH_ASSERT(n >= 0);
				RtlFillMemory(node, sizeof(*node), THASH_FILL);
			}
#endif
			PoolFreeChunk(&Table->NodeAllocator, node);
			// Go up
			node = iter->nodes[--l];
			// Has something to the other side or locked
			if (node->Child[i ^ 1] || node->Locked)
				break;
		}
		thashLeafJoin(l0, l1, &node->Leaf[i]);
		node->LeafSz[i] = c0 + c1;
	}
#ifdef __THASH_DEBUG_
	// Invalidate iterator
	RtlZeroMemory(iter->nodes, sizeof(iter->nodes));
#endif
}

#else
#define thashBalanceRemoved thashBalanceRemovedIterationSafe
#endif

// Balance tree after entry removal while iterating it
FORCEINLINE 
VOID thashBalanceRemovedIterationSafe(
		IN PTHASH Table,
		IN PTHASH_ITERATOR iter
	)
{
	UCHAR l = iter->level, i = iter->index;
	PTHASH_NODE node = iter->nodes[l];

	if (
		l && 
		!node->Child[0] && !node->Child[1] &&
		!node->Locked 
	) {
		// Just remove empty nodes
		while (l) {
			i = node->ChildIndx;
			THASH_ASSERT(iter->nodes[l-1]->Child[i] == node);
			THASH_ASSERT(!iter->nodes[l-1]->LeafSz[i]);
			THASH_ASSERT(!node->Locked);
			// Free node
#ifdef __THASH_DEBUG_
			{
				LONG n = InterlockedDecrement(&Table->Nodes);
				THASH_ASSERT(n >= 0);
				RtlFillMemory(node, sizeof(*node), THASH_FILL);
			}
#endif
			PoolFreeChunk(&Table->NodeAllocator, node);
			// Go up
			node = iter->nodes[--l];
			// Has something to the other side or locked
			if (node->Child[i ^ 1] || node->Locked)
				break;
		}
		node->Child[i] = 0;
		iter->level = l;
		iter->index = i;
#ifdef __THASH_DEBUG_
		// The iterator is only suitable for thashNextLeaf call
		iter->leafHead = 0;
		iter->leafSz   = 0;
#endif
	}
}

// Update counters on entry addition
FORCEINLINE 
VOID thashOnEntryAdded(
		IN PTHASH Table,
		IN PTHASH_ITERATOR iter
	)
{
	if (*iter->leafSz != THASH_LEAVES_OVERFLOW) 
		++*iter->leafSz;
	else {
#ifdef __THASH_DEBUG_	
		InterlockedIncrement(&Table->Overflow);
#endif					
	}
#ifdef __THASH_DEBUG_	
	InterlockedIncrement(&Table->Entries);
#endif					
}

// Update counters on entry removal
FORCEINLINE 
VOID thashOnEntryRemoved(
		PTHASH Table,
		IN PTHASH_ITERATOR iter
	)
{
#ifdef __THASH_DEBUG_	
	LONG entries = InterlockedDecrement(&Table->Entries);
	THASH_ASSERT(entries >= 0);
#endif					
	if (*iter->leafSz != THASH_LEAVES_OVERFLOW)
		--*iter->leafSz;
	else if (!*iter->leafHead)
		*iter->leafSz = 0;
	THASH_ASSERT(!*iter->leafSz == !*iter->leafHead);
}

//------------- Public interface --------------------------------------------

// Initialize table. Only hash callback is mandatory, other two may be omitted
// in case the functions using them are not supposed to be called.
FORCEINLINE
VOID THashInitialize(
			IN PTHASH Table,
			IN PTHASH_HASH_FN HashFn,
			IN PTHASH_COMPARE_FN CompareFn OPTIONAL,
			IN PTHASH_DESTROY_FN DestroyFn OPTIONAL,
			IN PVOID DestroyContext OPTIONAL
		)
{
	int i;
	RtlZeroMemory(Table, sizeof(*Table));
	PoolInitialize(
			&Table->NodeAllocator, 
			sizeof(THASH_NODE),
			NonPagedPool,
			THASH_TAG
		);
	Table->HashFn = HashFn;
	Table->CompareFn = CompareFn;
	Table->DestroyFn = DestroyFn;
	Table->DestroyContext = DestroyContext;
	for (i = 0; i < THASH_ROOT_BRANCHES; ++i)
		KeInitializeSharedSpinLock(&Table->Branch[i].Lock);
}

// Release memory allocated for the nodes.
// The caller is responsible for releasing all table content before this call.
FORCEINLINE
VOID THashRelease(IN PTHASH Table)
{
#ifdef __THASH_DEBUG_
	THASH_ASSERT(!Table->Nodes);
	THASH_ASSERT(!Table->Entries);
#endif
	PoolRelease(&Table->NodeAllocator);
}

// Fast insert function. Use caller supplied hash to avoid indirect call
// to hash function.
FORCEINLINE
PTHASH_ENTRY THashInsertByHash(
			IN PTHASH Table,
			IN PTHASH_ENTRY Entry,
			IN ULONG Hash
		)
{
	KIRQL OldIrql;
	PTHASH_BRANCH branch = thashGetBranch(Table, Hash);
	thashLockBranch(branch, TRUE, &OldIrql);
	{
		THASH_ITERATOR iter = THASH_ITERATOR_INITIALIZER(branch);
		thashLeafByHash(Hash, &iter);
		thashLeafInsertEntry(iter.leafHead, Entry);
		thashOnEntryAdded(Table, &iter);
		thashBalanceAdded(Table, &iter);
	}
	thashUnlockBranch(branch, TRUE, OldIrql);
	return Entry;
}

// Add new entry and returns pointer to it (== Entry).
FORCEINLINE
PTHASH_ENTRY THashInsert(
			IN PTHASH Table,
			IN PTHASH_ENTRY Entry
		)
{
	return THashInsertByHash(Table, Entry, Table->HashFn(Entry));
}

// Add new entry or returns pointer to existing.
// Use THashInsertUniqueByPtr for faster operation.
FORCEINLINE
PTHASH_ENTRY THashInsertUnique(
			IN PTHASH Table,
			IN PTHASH_ENTRY Entry,
			OUT PBOOLEAN Inserted OPTIONAL
		)
{
	KIRQL OldIrql;
	PTHASH_ENTRY ue = 0;
	ULONG Hash = Table->HashFn(Entry);
	PTHASH_BRANCH branch = thashGetBranch(Table, Hash);
	thashLockBranch(branch, TRUE, &OldIrql);
	{
		PTHASH_ENTRY e;
		THASH_ITERATOR iter = THASH_ITERATOR_INITIALIZER(branch);
		thashLeafByHash(Hash, &iter);
		for (e = *iter.leafHead; e; e = e->Next)
			if (Table->CompareFn(e, Entry)) {
				ue = e;
				break;
			}
		if (!ue) {
			thashLeafInsertEntry(iter.leafHead, Entry);
			thashOnEntryAdded(Table, &iter);
			thashBalanceAdded(Table, &iter);
			ue = Entry;
			if (Inserted)
				*Inserted = TRUE;
		} else {
			if (Inserted)
				*Inserted = FALSE;
		}
	}
	thashUnlockBranch(branch, TRUE, OldIrql);
	return ue;
}

// Found entry comparing it with key.
// Use caller supplied hash to avoid indirect call to hash function. 
FORCEINLINE
PTHASH_ENTRY THashLookupByHash(
			IN PTHASH Table,
			IN PTHASH_ENTRY Key,
			IN ULONG Hash,
			IN BOOLEAN bRemove,	  // Remove from table on return
			IN BOOLEAN bExclusive // Use exclusive locking
		)
{	
	KIRQL OldIrql;
	PTHASH_ENTRY found = 0;
	PTHASH_BRANCH branch = thashGetBranch(Table, Hash);
	thashLockBranch(branch, bExclusive, &OldIrql);
	{
		PTHASH_ENTRY e;
		THASH_ITERATOR iter = THASH_ITERATOR_INITIALIZER(branch);
		thashLeafByHash(Hash, &iter);
		for (e = *iter.leafHead; e; e = e->Next)
			if (Table->CompareFn(e, Key)) {
				found = e;
				break;
			}
		if (found && bRemove) {
			if (!bExclusive) {
				// Reacquire exclusive lock
				thashUpgradeBranchLock(branch, &iter);
				bExclusive = TRUE;
			}
			// Remove entry
			thashLeafRemoveEntry(found);
			thashOnEntryRemoved(Table, &iter);
			thashBalanceRemoved(Table, &iter);
		}
	}
	thashUnlockBranch(branch, bExclusive, OldIrql);
	return found;
}

// Found entry comparing it with key.
// This call is inherently slow, use THashLookupByPtr for fast operation.
FORCEINLINE
PTHASH_ENTRY THashLookup(
			IN PTHASH Table,
			IN PTHASH_ENTRY Key,
			IN BOOLEAN bRemove,	  // Remove from table on return
			IN BOOLEAN bExclusive // Use exclusive locking
		)
{	
	return THashLookupByHash(Table, Key, Table->HashFn(Key), bRemove, bExclusive);
}

// Found and remove entry previously located in the table. Use caller supplied hash to avoid indirect call
// to hash function. 
FORCEINLINE
VOID THashRemoveEntryByHash(
			IN PTHASH Table,
			IN PTHASH_ENTRY Entry,
			IN ULONG Hash
		)
{	
	KIRQL OldIrql;
	PTHASH_BRANCH branch = thashGetBranch(Table, Hash);
	thashLockBranch(branch, TRUE, &OldIrql);
	{
		THASH_ITERATOR iter = THASH_ITERATOR_INITIALIZER(branch);
		thashLeafByHash(Hash, &iter);
		thashLeafRemoveEntry(Entry);
		thashOnEntryRemoved(Table, &iter);
		thashBalanceRemoved(Table, &iter);
	}
	thashUnlockBranch(branch, TRUE, OldIrql);
}

// Found and delete entry comparing it with key.
// This call is inherently slow, use THashDeleteByPtr for fast operation.
FORCEINLINE
BOOLEAN THashDelete(
			IN PTHASH Table,
			IN PTHASH_ENTRY Key,
			IN BOOLEAN bExclusive	// Use exclusive locking
		)
{	
	PTHASH_ENTRY e = THashLookup(Table, Key, TRUE, bExclusive);
	if (!e)
		return FALSE;
	Table->DestroyFn(e, Table->DestroyContext);
	return TRUE;
}

// The following fast functions compare pointer located at specified offset with key 
// instead of calling comparison function. They use caller supplied hash to avoid indirect call
// to hash function.

// Add new entry or returns pointer to existing. 
// Optionally call callback passing pointer to existing entry.
// The main purpose of the callback is to facilitate reference counting.
FORCEINLINE
PTHASH_ENTRY THashInsertUniqueByPtrClb(
			IN PTHASH Table,
			IN PTHASH_ENTRY Entry,
			IN LONG KeyOffset,
			IN ULONG Hash,
			IN BOOLEAN bExclusive, // Use exclusive locking
			IN PTHASH_CALLBACK_FN Callback OPTIONAL,
			IN PVOID Context OPTIONAL,
			OUT PBOOLEAN Inserted OPTIONAL
		)
{
	KIRQL OldIrql;
	PTHASH_ENTRY ue = 0;
	ULONG_PTR Key = *(PULONG_PTR)((char*)Entry + KeyOffset);
	PTHASH_BRANCH branch = thashGetBranch(Table, Hash);
	thashLockBranch(branch, bExclusive, &OldIrql);
	{
		PTHASH_ENTRY e;
		THASH_ITERATOR iter = THASH_ITERATOR_INITIALIZER(branch);
		thashLeafByHash(Hash, &iter);
		for (e = *iter.leafHead; e; e = e->Next)
			if (*(PULONG_PTR)((char*)e + KeyOffset) == Key) {
				ue = e;
				break;
			}
		if (!ue) {
			if (!bExclusive) {
				// Reacquire exclusive lock
				thashUpgradeBranchLock(branch, &iter);
				bExclusive = TRUE;
			}
			// Insert new entry
			thashLeafInsertEntry(iter.leafHead, ue = Entry);
			thashOnEntryAdded(Table, &iter);
			thashBalanceAdded(Table, &iter);
			if (Inserted)
				*Inserted = TRUE;
		} else {
			if (Callback)
				Callback(ue, Context);
			if (Inserted)
				*Inserted = FALSE;
		}
	}
	thashUnlockBranch(branch, bExclusive, OldIrql);
	return ue;
}

// Found entry comparing it with key
FORCEINLINE
PTHASH_ENTRY THashLookupByPtr(
			IN PTHASH Table,
			IN ULONG_PTR Key,
			IN LONG KeyOffset,
			IN ULONG Hash,
			IN BOOLEAN bRemove,		// Remove from table on return
			IN BOOLEAN bExclusive	// Use exclusive locking
		)
{	
	KIRQL OldIrql;
	PTHASH_ENTRY found = 0;
	PTHASH_BRANCH branch = thashGetBranch(Table, Hash);
	thashLockBranch(branch, bExclusive, &OldIrql);
	{
		PTHASH_ENTRY e;
		THASH_ITERATOR iter = THASH_ITERATOR_INITIALIZER(branch);
		thashLeafByHash(Hash, &iter);
		for (e = *iter.leafHead; e; e = e->Next)
			if (*(PULONG_PTR)((char*)e + KeyOffset) == Key) {
				found = e;
				break;
			}
		if (found && bRemove) {
			if (!bExclusive) {
				// Reacquire exclusive lock
				thashUpgradeBranchLock(branch, &iter);
				bExclusive = TRUE;
			}
			// Remove entry
			thashLeafRemoveEntry(found);
			thashOnEntryRemoved(Table, &iter);
			thashBalanceRemoved(Table, &iter);
		}
	}
	thashUnlockBranch(branch, bExclusive, OldIrql);
	return found;
}

// Found entry comparing it with key
FORCEINLINE
PTHASH_ENTRY THashLookupByPtr2(
			IN PTHASH Table,
			IN ULONG_PTR Key,
			IN ULONG_PTR Key2,
			IN LONG KeyOffset, //ptr
			IN LONG KeyOffset2, //driver object
			IN LONG KeyFlag, //session pool
			IN ULONG Hash,
			IN BOOLEAN bRemove,		// Remove from table on return
			IN BOOLEAN bExclusive	// Use exclusive locking
		)
{	
	KIRQL OldIrql;
	PTHASH_ENTRY found = 0;
	PTHASH_BRANCH branch = thashGetBranch(Table, Hash);
	thashLockBranch(branch, bExclusive, &OldIrql);
	{
		PTHASH_ENTRY e;
		THASH_ITERATOR iter = THASH_ITERATOR_INITIALIZER(branch);
		thashLeafByHash(Hash, &iter);
		for (e = *iter.leafHead; e; e = e->Next)
			if ((*(PUCHAR)((char*)e + KeyFlag) == 1)){
				if ((*(PULONG_PTR)((char*)e + KeyOffset) == Key) &&
					(*(PULONG_PTR)((char*)e + KeyOffset2) == Key2))
				{
					found = e;
					break;
				}
			}else{
				if (*(PULONG_PTR)((char*)e + KeyOffset) == Key)
				{
					found = e;
					break;
				}
			}
		if (found && bRemove) {
			if (!bExclusive) {
				// Reacquire exclusive lock
				thashUpgradeBranchLock(branch, &iter);
				bExclusive = TRUE;
			}
			// Remove entry
			thashLeafRemoveEntry(found);
			thashOnEntryRemoved(Table, &iter);
			thashBalanceRemoved(Table, &iter);
		}
	}
	thashUnlockBranch(branch, bExclusive, OldIrql);
	return found;
}

// Found entry comparing it with key. Call callback and optionally remove or delete entry from the table. 
// The main purpose of the callback is to facilitate reference counting.
FORCEINLINE
PTHASH_ENTRY THashLookupByHashClb(
			IN PTHASH Table,
			IN PTHASH_ENTRY Key,
			IN ULONG Hash,
			IN BOOLEAN bExclusive, // Use exclusive locking
			IN PTHASH_SCAN_FN Callback,
			IN PVOID Context
		)
{	
	KIRQL OldIrql;
	UCHAR opCode = 0;
	PTHASH_ENTRY found = 0;
	PTHASH_BRANCH branch = thashGetBranch(Table, Hash);
	thashLockBranch(branch, bExclusive, &OldIrql);
	{
		PTHASH_ENTRY e;
		THASH_ITERATOR iter = THASH_ITERATOR_INITIALIZER(branch);
		thashLeafByHash(Hash, &iter);
		for (e = *iter.leafHead; e; e = e->Next)
			if (Table->CompareFn(e, Key)) {
				opCode = Callback(found = e, Context);				
				if (opCode & (tHashRemove | tHashDestroy)) {
					if (!bExclusive) {
						// Reacquire exclusive lock
						thashUpgradeBranchLock(branch, &iter);
						bExclusive = TRUE;
					}
					// Remove entry
					thashLeafRemoveEntry(found);
					thashOnEntryRemoved(Table, &iter);
					thashBalanceRemoved(Table, &iter);
				}
				break;
			}
	}
	thashUnlockBranch(branch, bExclusive, OldIrql);
	if (opCode & tHashDestroy)
		Table->DestroyFn(found, Table->DestroyContext);

	return found;
}

// Found entry comparing it with key. Call callback and optionally remove or delete entry from the table. 
// The main purpose of the callback is to facilitate reference counting.
FORCEINLINE
PTHASH_ENTRY THashLookupByPtrClb(
			IN PTHASH Table,
			IN ULONG_PTR Key,
			IN LONG KeyOffset,
			IN ULONG Hash,
			IN BOOLEAN bExclusive, // Use exclusive locking
			IN PTHASH_SCAN_FN Callback,
			IN PVOID Context
		)
{	
	KIRQL OldIrql;
	UCHAR opCode = 0;
	PTHASH_ENTRY found = 0;
	PTHASH_BRANCH branch = thashGetBranch(Table, Hash);
	thashLockBranch(branch, bExclusive, &OldIrql);
	{
		PTHASH_ENTRY e;
		THASH_ITERATOR iter = THASH_ITERATOR_INITIALIZER(branch);
		thashLeafByHash(Hash, &iter);
		for (e = *iter.leafHead; e; e = e->Next)
			if (*(PULONG_PTR)((char*)e + KeyOffset) == Key) {
				opCode = Callback(found = e, Context);				
				if (opCode & (tHashRemove | tHashDestroy)) {
					if (!bExclusive) {
						// Reacquire exclusive lock
						thashUpgradeBranchLock(branch, &iter);
						bExclusive = TRUE;
					}
					// Remove entry
					thashLeafRemoveEntry(found);
					thashOnEntryRemoved(Table, &iter);
					thashBalanceRemoved(Table, &iter);
				}
				break;
			}
	}
	thashUnlockBranch(branch, bExclusive, OldIrql);
	if (opCode & tHashDestroy)
		Table->DestroyFn(found, Table->DestroyContext);

	return found;
}

// Found and delete entry comparing it with key. 
FORCEINLINE
BOOLEAN THashDeleteByPtr(
			IN PTHASH Table,
			IN ULONG_PTR Key,
			IN LONG KeyOffset,
			IN ULONG Hash,
			IN BOOLEAN bExclusive	// Use exclusive locking
		)
{	
	PTHASH_ENTRY e = THashLookupByPtr(Table, Key, KeyOffset, Hash, TRUE, bExclusive);
	if (!e)
		return FALSE;
	Table->DestroyFn(e, Table->DestroyContext);
	return TRUE;
}

//----------------- Table scan functions --------------------------------

// Helper
FORCEINLINE
UCHAR thashScanBranch(
			IN PTHASH Table,
			IN PTHASH_BRANCH branch,
			IN PTHASH_SCAN_FN Callback,
			IN PVOID Context
		)
{
	UCHAR scanCode = 0;
	THASH_ITERATOR iter = THASH_ITERATOR_INITIALIZER(branch);
	thashFirstLeaf(&iter);
	do {
		PTHASH_ENTRY e = *iter.leafHead, deleted = 0;
		while (e) {
			PTHASH_ENTRY next = e->Next;
			scanCode = Callback(e, Context);
			if (scanCode & (tHashRemove | tHashDestroy)) {
				// Here the content of the entry may be already changed
				// So don't use it including Next field, use cached one
				deleted = e;
				thashLeafRemoveEntry_(deleted, next);
				thashOnEntryRemoved(Table, &iter);
			}
			if (scanCode & tHashDestroy)
				Table->DestroyFn(deleted, Table->DestroyContext);
			if (scanCode & (tHashBreak | tHashRestart))
				break;
			e = next;
		}
		if (deleted)
			thashBalanceRemovedIterationSafe(Table, &iter);
		if (scanCode & (tHashBreak | tHashRestart))
			break;
	} while (thashNextLeaf(&iter));
	return scanCode;
}

FORCEINLINE
VOID THashScan(
			IN PTHASH Table,
			IN PTHASH_SCAN_FN Callback,
			IN PVOID Context,
			IN BOOLEAN Lock,
			IN BOOLEAN Exclusive
		)
{
	UCHAR scanCode = 0;
	do {
		int b;
		for (b = 0; b < THASH_ROOT_BRANCHES; ++b) {
			PTHASH_BRANCH branch = &Table->Branch[b];
			KIRQL OldIrql;
			if (Lock)
				thashLockBranch(branch, Exclusive, &OldIrql);
			scanCode = thashScanBranch(
						Table, 
						branch, 
						Callback, 
						Context
					);
			if (Lock)
				thashUnlockBranch(branch, Exclusive, OldIrql);
			if (scanCode & (tHashBreak | tHashRestart))
				break;
		}
	} while (scanCode & tHashRestart);
}

FORCEINLINE
VOID THashScanByHash(
			IN PTHASH Table,
			IN ULONG Hash,
			IN PTHASH_SCAN_FN Callback,
			IN PVOID Context,
			IN BOOLEAN Lock,
			IN BOOLEAN Exclusive
		)
{
	UCHAR scanCode = 0;
	do {
		PTHASH_BRANCH branch = thashGetBranch(Table, Hash);
		KIRQL OldIrql;
		if (Lock)
			thashLockBranch(branch, Exclusive, &OldIrql);
		scanCode = thashScanBranch(
					Table, 
					branch, 
					Callback, 
					Context
				);
		if (Lock)
			thashUnlockBranch(branch, Exclusive, OldIrql);
		if (scanCode & (tHashBreak | tHashRestart))
			break;
	} while (scanCode & tHashRestart);
}

typedef struct _THashMoveToSList_Context {
	PTHASH_SCAN_FN	Callback;
	PVOID			Context;
	PTHASH_ENTRY*	ListHead;
} THashMoveToSList_Context, *PTHashMoveToSList_Context; 

static
UCHAR NTAPI THashMoveToSList_Callback(PTHASH_ENTRY Entry, PVOID Context)
{
	PTHashMoveToSList_Context ctx = (PTHashMoveToSList_Context)Context;
	if (!ctx->Callback || ctx->Callback(Entry, ctx->Context)) {
		Entry->Next = *ctx->ListHead;
		*ctx->ListHead = Entry;
		return tHashRemove;
	} else
		return tHashContinue;
}

// Move entry to list in case Callback returns non-0
// Move all items in case Callback is NULL.
FORCEINLINE
VOID THashMoveToSList(
			IN PTHASH Table,
			IN PTHASH_SCAN_FN Callback,
			IN PVOID Context,
			IN OUT PTHASH_ENTRY* ListHead
		)
{
	THashMoveToSList_Context context = {
			Callback,
			Context,
			ListHead
		};
	THashScan(Table, THashMoveToSList_Callback, &context, TRUE, TRUE);
}

typedef struct _THashMoveToSListByPtr_Context {
	ULONG_PTR		Key;
	LONG			KeyOffset;
	PTHASH_ENTRY*	ListHead;
} THashMoveToSListByPtr_Context, *PTHashMoveToSListByPtr_Context; 

static
UCHAR NTAPI THashMoveToSListByPtr_Callback(PTHASH_ENTRY Entry, PVOID Context)
{
	PTHashMoveToSListByPtr_Context ctx = (PTHashMoveToSListByPtr_Context)Context;
	if (*(PULONG_PTR)((char*)Entry + ctx->KeyOffset) == ctx->Key) {
		Entry->Next = *ctx->ListHead;
		*ctx->ListHead = Entry;
		return tHashRemove;
	} else
		return tHashContinue;
}

// Move entries to list comparing pointer located at specified offset with key
FORCEINLINE
VOID THashMoveToSListByPtr(
			IN PTHASH Table,
			IN ULONG_PTR Key,
			IN LONG KeyOffset,
			IN OUT PTHASH_ENTRY* ListHead
		)
{
	THashMoveToSListByPtr_Context context = {
			Key,
			KeyOffset,
			ListHead
		};
	THashScan(Table, THashMoveToSListByPtr_Callback, &context, TRUE, TRUE);
}

//----------------------------------------------------------------------------------------
// Yet another simple hash function

#define THASH_FNV_32_PRIME 0x01000193

FORCEINLINE
ULONG THashPtrHash(ULONG_PTR val)
{
	PULONG p = (PULONG)&val;
	ULONG h = (p[0] >> PAGE_SHIFT) | (p[0] << (32 - PAGE_SHIFT));
	h *= THASH_FNV_32_PRIME;
	h = (h << PAGE_SHIFT) | (h >> (32 - PAGE_SHIFT));
	if (sizeof(val) > sizeof(*p)) {
		h ^= p[1];
		h *= THASH_FNV_32_PRIME;
	}
	return h;
}
