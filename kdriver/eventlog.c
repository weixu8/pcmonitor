#include <inc/eventlog.h>

VOID
	EventLogFlush(PEVENT_LOG EventLog)
{

}

NTSTATUS
	EventLogWorkerRoutine(PEVENT_LOG EventLog)
{
	return STATUS_SUCCESS;
}

VOID NTAPI
	EventLogTimerDpcRoutine(
	_In_      struct _KDPC *Dpc,
	_In_opt_  PVOID DeferredContext,
	_In_opt_  PVOID SystemArgument1,
	_In_opt_  PVOID SystemArgument2
	)
{
	PEVENT_LOG EventLog = (PEVENT_LOG)DeferredContext;

	SysWorkerAddWork(&EventLog->Worker, EventLogWorkerRoutine, EventLog);
}

NTSTATUS
	EventLogStart(PEVENT_LOG EventLog)
{
	LARGE_INTEGER TimerDueTime;
	NTSTATUS Status;

	RtlZeroMemory(EventLog, sizeof(EVENT_LOG));
	InitializeListHead(&EventLog->EventListHead);
	KeInitializeSpinLock(&EventLog->EventListLock);
	KeInitializeTimer(&EventLog->Timer);
	KeInitializeDpc(&EventLog->TimerDpc, EventLogTimerDpcRoutine, EventLog);
	SysWorkerInit(&EventLog->Worker);

	Status = SysWorkerStart(&EventLog->Worker);
	if (!NT_SUCCESS(Status)) {
		goto start_failed;
	}

	TimerDueTime.QuadPart = 0;
	KeSetTimerEx(&EventLog->Timer, TimerDueTime, 500, &EventLog->TimerDpc);

start_failed:
	KeCancelTimer(&EventLog->Timer);
	KeFlushQueuedDpcs();
	SysWorkerStop(&EventLog->Worker);
	EventLogFlush(EventLog);

	return Status;
}

VOID
	EventLogStop(PEVENT_LOG EventLog)
{
	PSYS_WRK_ITEM WrkItem = NULL;

	KeCancelTimer(&EventLog->Timer);
	KeFlushQueuedDpcs();
	SysWorkerStop(&EventLog->Worker);
	EventLogFlush(EventLog);
}