#pragma once

#include <inc/drvmain.h>

typedef
BOOLEAN (NTAPI *PSYSTHREAD_ROUTINE)(PVOID Context);

typedef struct _SYSTHREAD {
	HANDLE				ThreadHandle;
	PVOID				Thread;
	BOOLEAN         	ThreadStop;
	PSYSTHREAD_ROUTINE  Routine;
	PVOID				Context;
	KEVENT				Event;
} SYSTHREAD, *PSYSTHREAD;

VOID
	SysThreadInit(PSYSTHREAD ThreadCtx);

VOID
	SysThreadSignal(PSYSTHREAD ThreadCtx);
	

NTSTATUS
	SysThreadStart(PSYSTHREAD ThreadCtx, PSYSTHREAD_ROUTINE  Routine, PVOID Context);

VOID
	SysThreadStop(PSYSTHREAD ThreadCtx);

