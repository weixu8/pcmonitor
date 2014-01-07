#ifndef __SYS_THREAD_H__
#define __SYS_THREAD_H__


#include <inc/drvmain.h>

typedef
VOID (NTAPI *PSYSTHREAD_ROUTINE)(PVOID Context);

typedef struct _SYSTHREAD {
	HANDLE				ThreadHandle;
	PVOID				Thread;
	BOOLEAN         	ThreadStop;
	PSYSTHREAD_ROUTINE  Routine;
	PVOID				Context;
	KEVENT				Event;
} SYSTHREAD, *PSYSTHREAD;

VOID
	SysThreadSignal(PSYSTHREAD ThreadCtx);
	

NTSTATUS
	SysThreadStart(PSYSTHREAD ThreadCtx, PSYSTHREAD_ROUTINE  Routine, PVOID Context);

VOID
	SysThreadStop(PSYSTHREAD ThreadCtx);

#endif
