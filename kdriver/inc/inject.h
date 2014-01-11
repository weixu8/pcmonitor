
#pragma once

#include <inc/drvmain.h>

typedef struct _INJECT_INFO {
	PVOID		pStubData;
	BOOLEAN		StubSetup;
	ULONG		ThreadApcQueuedCount;
	BOOLEAN		StubCalled;
	NTSTATUS	InjectStatus;
} INJECT_INFO, *PINJECT_INFO;

typedef struct _INJECT_BLOCK {
	SYSWORKER	Worker;
	KTIMER		Timer;
	KDPC		TimerDpc;
	volatile LONG Started;
} INJECT_BLOCK, *PINJECT_BLOCK;

VOID
InjectInit(PINJECT_BLOCK Inject);

NTSTATUS
InjectStart(PINJECT_BLOCK Inject);

VOID
InjectStop(PINJECT_BLOCK Inject);

