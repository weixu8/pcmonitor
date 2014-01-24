#include <inc/eventlog.h>
#include <inc/srequest.h>
#include <inc/monitor.h>


#define __SUBCOMPONENT__ "eventlog"

VOID
	EventLogFlush(PEVENT_LOG EventLog)
{
	KIRQL Irql;
	PLIST_ENTRY ListEntry = NULL;
	PSREQUEST request = NULL;
	LIST_ENTRY FreeListHead;

	InitializeListHead(&FreeListHead);

	KeAcquireSpinLock(&EventLog->EventListLock, &Irql);
	while (!IsListEmpty(&EventLog->EventListHead)) {
		ListEntry = RemoveHeadList(&EventLog->EventListHead);
		request = CONTAINING_RECORD(ListEntry, SREQUEST, ListEntry);
		InsertHeadList(&FreeListHead, &request->ListEntry);
	}
	KeReleaseSpinLock(&EventLog->EventListLock, Irql);

	while (!IsListEmpty(&FreeListHead)) {
		ListEntry = RemoveHeadList(&FreeListHead);
		request = CONTAINING_RECORD(ListEntry, SREQUEST, ListEntry);
		SRequestDelete(request);
	}
}

NTSTATUS
	EventLogWorkerRoutine(PEVENT_LOG EventLog)
{
	KIRQL Irql;
	PLIST_ENTRY ListEntry = NULL;
	PSREQUEST request = NULL;
	
	if (EventLog->Stopping)
		return STATUS_TOO_LATE;

	KeAcquireSpinLock(&EventLog->EventListLock, &Irql);
	if (!IsListEmpty(&EventLog->EventListHead)) {
		ListEntry = RemoveHeadList(&EventLog->EventListHead);
		request = CONTAINING_RECORD(ListEntry, SREQUEST, ListEntry);
	}
	KeReleaseSpinLock(&EventLog->EventListLock, Irql);

	if (request != NULL) {
		PSREQUEST response = NULL;
		response = MonitorCallServer(request);
		if (response->status != SREQ_SUCCESS)
			KLog(LError, "request %d failed with err=%d", request->type, response->status);

		if (response != NULL)
			SRequestDelete(response);

		SRequestDelete(request);
	}

	return STATUS_SUCCESS;
}

NTSTATUS 
	EventLogAdd(PEVENT_LOG EventLog, PSREQUEST request)
{
	KIRQL Irql;
	NTSTATUS Status;

	if (EventLog->Stopping)
		return STATUS_TOO_LATE;

	KeAcquireSpinLock(&EventLog->EventListLock, &Irql);
	if (EventLog->Stopping) {
		Status = STATUS_TOO_LATE;
		goto unlock;
	}

	InsertTailList(&EventLog->EventListHead, &request->ListEntry);
	Status = STATUS_SUCCESS;
unlock:
	KeReleaseSpinLock(&EventLog->EventListLock, Irql);
	return Status;
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
	KIRQL Irql;
	BOOLEAN isEmpty = TRUE;

	if (EventLog->Stopping)
		return;
	
	KeAcquireSpinLock(&EventLog->EventListLock, &Irql);
	isEmpty = IsListEmpty(&EventLog->EventListHead);
	KeReleaseSpinLock(&EventLog->EventListLock, Irql);
	
	if (!isEmpty)
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
	return STATUS_SUCCESS;

start_failed:
	EventLog->Stopping = 1;
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

	EventLog->Stopping = 1;
	KeCancelTimer(&EventLog->Timer);
	KeFlushQueuedDpcs();
	SysWorkerStop(&EventLog->Worker);
	EventLogFlush(EventLog);
}