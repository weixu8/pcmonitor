
#pragma once

//#define _SPIN_DBG_ //asmetanin@:tmp to catch reason of https://jira.sw.ru/browse/PCWIN-16019

//////////////////////////////////////////////////////////////////////////

#ifndef _SPIN_DBG_
	typedef LONG KSHARED_SPIN_LOCK, *PKSHARED_SPIN_LOCK;
#else
	typedef struct _KSHARED_SPIN_LOCK
	{
		LONG Lock;
		PETHREAD Thread;
	}KSHARED_SPIN_LOCK, *PKSHARED_SPIN_LOCK;
#endif
#define EXP_SPIN_LOCK_EXCLUSIVE 0x80000000

//////////////////////////////////////////////////////////////////////////

#define ALIGNED_SHARED_SPIN_LOCK DECLSPEC_CACHEALIGN KSHARED_SPIN_LOCK

//
// Define shared spin lock array structure.
//

typedef struct _ALIGNED_SHARED_SPIN_LOCK_STRUCT {
    ALIGNED_SHARED_SPIN_LOCK Lock;
} ALIGNED_SHARED_SPIN_LOCK_STRUCT, *PALIGNED_SHARED_SPIN_LOCK_STRUCT;

//////////////////////////////////////////////////////////////////////////
FORCEINLINE
VOID
KeInitializeSharedSpinLock(
	IN PKSHARED_SPIN_LOCK SpinLock
	)
{
#ifndef _SPIN_DBG_
	*SpinLock = 0;
#else
	SpinLock->Lock = 0;
	SpinLock->Thread = NULL;
#endif
}
//////////////////////////////////////////////////////////////////////////
FORCEINLINE
VOID
NTAPI
KeAcquireSpinLockSharedAtDpcLevel(
    IN PKSHARED_SPIN_LOCK SpinLock
    )
{
#ifndef _SPIN_DBG_
    KSHARED_SPIN_LOCK LockContents;
    KSHARED_SPIN_LOCK NewLockContents;

	ASSERT (KeGetCurrentIrql () >= DISPATCH_LEVEL);

    do {

        LockContents = *(volatile KSHARED_SPIN_LOCK *)SpinLock;
        if ((LockContents & EXP_SPIN_LOCK_EXCLUSIVE) == 0) {
            NewLockContents = LockContents + 1;
            if (InterlockedCompareExchangeAcquire (SpinLock,NewLockContents,LockContents) == LockContents) {
                return;
            }
        }
        YieldProcessor();
    } while (TRUE);
#else
	LONG LockContents;
	LONG NewLockContents;

	ASSERT (KeGetCurrentIrql () >= DISPATCH_LEVEL);

	do {

		LockContents = SpinLock->Lock;
		if ((LockContents & EXP_SPIN_LOCK_EXCLUSIVE) == 0) {
			NewLockContents = LockContents + 1;
			if (InterlockedCompareExchangeAcquire (&SpinLock->Lock,NewLockContents,LockContents) == LockContents) {
				return;
			}
		}
		YieldProcessor();
	} while (TRUE);
#endif
}
//////////////////////////////////////////////////////////////////////////
FORCEINLINE
VOID
NTAPI
KeAcquireSpinLockShared(
    IN PKSHARED_SPIN_LOCK SpinLock,
	IN PKIRQL OldIrql
    )
{
	KeRaiseIrql (DISPATCH_LEVEL, OldIrql);
	KeAcquireSpinLockSharedAtDpcLevel (SpinLock);
}
//////////////////////////////////////////////////////////////////////////
FORCEINLINE
VOID
NTAPI
KeReleaseSpinLockSharedFromDpcLevel(
    IN PKSHARED_SPIN_LOCK SpinLock
    )
{
    ASSERT (KeGetCurrentIrql () >= DISPATCH_LEVEL);
#ifndef _SPIN_DBG_
    ASSERT (*SpinLock != 0);
    InterlockedDecrementRelease (SpinLock);
#else
	ASSERT(SpinLock->Thread!=PsGetCurrentThread());
	InterlockedDecrementRelease (&SpinLock->Lock);
#endif
}
//////////////////////////////////////////////////////////////////////////
FORCEINLINE
VOID
NTAPI
KeReleaseSpinLockShared(
    IN PKSHARED_SPIN_LOCK SpinLock,
    IN KIRQL OldIrql
    )
{
    ASSERT (OldIrql <= DISPATCH_LEVEL);

	KeReleaseSpinLockSharedFromDpcLevel (SpinLock);
	KeLowerIrql (OldIrql);
}
//////////////////////////////////////////////////////////////////////////
FORCEINLINE
BOOLEAN
NTAPI
KeTryAcquireSpinLockExclusive(
    IN PKSHARED_SPIN_LOCK SpinLock
    )
{
#ifndef _SPIN_DBG_
    KSHARED_SPIN_LOCK LockContents;
    KSHARED_SPIN_LOCK NewLockContents;

    ASSERT (KeGetCurrentIrql () >= DISPATCH_LEVEL);

    do {
        LockContents = *(volatile KSHARED_SPIN_LOCK *)SpinLock;
        ASSERT (LockContents != 0);
        if (LockContents & EXP_SPIN_LOCK_EXCLUSIVE) {
            return FALSE;
        }
        NewLockContents = (LockContents | EXP_SPIN_LOCK_EXCLUSIVE);
        if (InterlockedCompareExchangeAcquire (SpinLock,NewLockContents,LockContents) == LockContents) {
            while (*(volatile KSHARED_SPIN_LOCK *)SpinLock != (EXP_SPIN_LOCK_EXCLUSIVE | 0x1)) {
                YieldProcessor();
            }
            return TRUE;
        }
    } while (TRUE);
#else
	LONG LockContents;
	LONG NewLockContents;

	ASSERT (KeGetCurrentIrql () >= DISPATCH_LEVEL);

	do {
		LockContents = SpinLock->Lock;
		ASSERT (LockContents != 0);
		if (LockContents & EXP_SPIN_LOCK_EXCLUSIVE) {
			return FALSE;
		}
		NewLockContents = (LockContents | EXP_SPIN_LOCK_EXCLUSIVE);
		if (InterlockedCompareExchangeAcquire (&SpinLock->Lock,NewLockContents,LockContents) == LockContents) {
			while ( SpinLock->Lock != (EXP_SPIN_LOCK_EXCLUSIVE | 0x1)) {
				YieldProcessor();
			}			
			return TRUE;
		}
	} while (TRUE);
#endif
}
//////////////////////////////////////////////////////////////////////////
FORCEINLINE
VOID
NTAPI
KeAcquireSpinLockExclusive(
    IN PKSHARED_SPIN_LOCK SpinLock,
	IN PKIRQL pOldIrql
    )
{
	KIRQL OldIrql;
	do {
		KeAcquireSpinLockShared (SpinLock,&OldIrql);
		if (KeTryAcquireSpinLockExclusive (SpinLock) == TRUE) {
#ifdef _SPIN_DBG_
			SpinLock->Thread = PsGetCurrentThread();
#endif
			*pOldIrql = OldIrql;
			return;
		}
		KeReleaseSpinLockShared (SpinLock, OldIrql);
		YieldProcessor();
	} while (TRUE);
}
//////////////////////////////////////////////////////////////////////////
FORCEINLINE
VOID
NTAPI
KeConvertSharedSpinLockToExclusive(
    IN PKSHARED_SPIN_LOCK SpinLock
    )
{
	KIRQL OldIrql;
	do {
		if (KeTryAcquireSpinLockExclusive (SpinLock) == TRUE) {
#ifdef _SPIN_DBG_
			SpinLock->Thread = PsGetCurrentThread();
#endif
			return;
		}
		YieldProcessor();
	} while (TRUE);
}
//////////////////////////////////////////////////////////////////////////
FORCEINLINE
VOID
NTAPI
KeAcquireSpinLockExclusiveAtDpcLevel(
    IN PKSHARED_SPIN_LOCK SpinLock
    )
{
	do {
		KeAcquireSpinLockSharedAtDpcLevel (SpinLock);
		if (KeTryAcquireSpinLockExclusive (SpinLock) == TRUE) {
#ifdef _SPIN_DBG_
			SpinLock->Thread = PsGetCurrentThread();
#endif
			return;
		}
		KeReleaseSpinLockSharedFromDpcLevel (SpinLock);
		YieldProcessor();
	} while (TRUE);
}
//////////////////////////////////////////////////////////////////////////
FORCEINLINE
VOID
NTAPI
KeReleaseSpinLockExclusiveFromDpcLevel(
    IN PKSHARED_SPIN_LOCK SpinLock
    )
{
	ASSERT (KeGetCurrentIrql () >= DISPATCH_LEVEL);
#ifndef _SPIN_DBG_
    ASSERT (*SpinLock == (EXP_SPIN_LOCK_EXCLUSIVE | 0x1));

    KeMemoryBarrierWithoutFence();
    *((KSHARED_SPIN_LOCK volatile *)SpinLock) = 0;
#else
	KeMemoryBarrierWithoutFence();
	SpinLock->Lock = 0;
	SpinLock->Thread = NULL;
#endif
}
//////////////////////////////////////////////////////////////////////////
FORCEINLINE
VOID
NTAPI
KeReleaseSpinLockExclusive(
    IN PKSHARED_SPIN_LOCK SpinLock,
    IN KIRQL OldIrql
    )
{
	ASSERT (OldIrql <= DISPATCH_LEVEL);

	KeReleaseSpinLockExclusiveFromDpcLevel (SpinLock);
	KeLowerIrql (OldIrql);
}
//////////////////////////////////////////////////////////////////////////
