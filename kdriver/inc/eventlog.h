#pragma once

#include <inc/drvmain.h>
#include <inc/sysworker.h>
#include <inc/srequest.h>

typedef struct _EVENT_LOG {
	LIST_ENTRY		EventListHead;
	KSPIN_LOCK		EventListLock;
	SYSWORKER		Worker;
	KTIMER			Timer;
	KDPC			TimerDpc;
	volatile LONG	Stopping;
} EVENT_LOG, *PEVENT_LOG;

NTSTATUS
EventLogStart(PEVENT_LOG EventLog);

VOID
EventLogStop(PEVENT_LOG EventLog);

NTSTATUS
EventLogAdd(PEVENT_LOG EventLog, PSREQUEST request);
