#pragma once

#include <inc/drvmain.h>
#include <inc/sysworker.h>

typedef struct _EVENT_ENTRY {
	LIST_ENTRY	ListEntry;
	int			type;
	char		*data;
	size_t		dataSz;
} EVENT_ENTRY, *PEVENT_ENTRY;

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