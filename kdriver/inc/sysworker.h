#pragma once
#include <inc/drvmain.h>
#include <inc/systhread.h>

typedef
NTSTATUS(NTAPI *PSYS_WRK_ROUTINE)(PVOID Context);

typedef struct _SYS_WRK_ITEM {
	LIST_ENTRY				ListEntry;
	PSYS_WRK_ROUTINE		Routine;
	PVOID					Context;
	KEVENT					CompletionEvent;
	volatile LONG			RefCount;
	NTSTATUS				Status;
} SYS_WRK_ITEM, *PSYS_WRK_ITEM;

typedef struct _SYSWORKER {
	SYSTHREAD       Thread;
	KSPIN_LOCK      Lock;
	LIST_ENTRY      WrkItemList;
	volatile LONG	Stopping;
} SYSWORKER, *PSYSWORKER;

VOID
	SysWorkerInit(PSYSWORKER Worker);

NTSTATUS	
	SysWorkerStart(PSYSWORKER Worker);

VOID
	SysWorkerAddWork(PSYSWORKER Worker, PSYS_WRK_ROUTINE Routine, PVOID Context);

VOID
	SysWrkItemDeref(PSYS_WRK_ITEM WrkItem);

VOID
	SysWorkerStop(PSYSWORKER Worker);

PSYS_WRK_ITEM
	SysWorkerAddWorkRef(PSYSWORKER Worker, PSYS_WRK_ROUTINE Routine, PVOID Context);