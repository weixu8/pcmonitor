#pragma once
#include <inc/drvmain.h>
#include <inc/systhread.h>

typedef struct _SYSWORKER {
	SYSTHREAD       Thread;
	KSPIN_LOCK      Lock;
	LIST_ENTRY      WrkItemList;
	volatile LONG	Stopping;
} SYSWORKER, *PSYSWORKER;

typedef
VOID(NTAPI *PSYS_WRK_ROUTINE)(PVOID Context);

VOID
	SysWorkerInit(PSYSWORKER Worker);

NTSTATUS	
	SysWorkerStart(PSYSWORKER Worker);

VOID
	SysWorkerAddWork(PSYSWORKER Worker, PSYS_WRK_ROUTINE Routine, PVOID Context);

VOID
	SysWorkerStop(PSYSWORKER Worker);
