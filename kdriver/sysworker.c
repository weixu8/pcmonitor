#include <inc/sysworker.h>
#include <inc/klogger.h>

#define __SUBCOMPONENT__ "sysworker"


#define SYS_WRK_ITEM_TAG 'mont'

VOID
	SysWrkItemRef_(PSYS_WRK_ITEM WrkItem)
{
	InterlockedIncrement(&WrkItem->RefCount);
}

VOID
	SysWrkItemDeref_(PSYS_WRK_ITEM WrkItem)
{
	LONG RefCount = -1;
	RefCount = InterlockedDecrement(&WrkItem->RefCount);
	if (RefCount < 0)
		__debugbreak();

	if (0 == RefCount) {
		ExFreePoolWithTag(WrkItem, SYS_WRK_ITEM_TAG);
	}
}

PSYS_WRK_ITEM
	SysWorkerAddWorkRef(PSYSWORKER Worker, PSYS_WRK_ROUTINE Routine, PVOID Context)
{
	PSYS_WRK_ITEM WrkItem = NULL;
	KIRQL Irql;

	if (Worker->Stopping)
		return NULL;

	WrkItem = (PSYS_WRK_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(SYS_WRK_ITEM), SYS_WRK_ITEM_TAG);
	if (WrkItem == NULL) {
		__debugbreak();
		return NULL;
	}

	RtlZeroMemory(WrkItem, sizeof(SYS_WRK_ITEM));
	SYS_WRK_ITEM_REF(WrkItem)
	WrkItem->Routine = Routine;
	WrkItem->Context = Context;

	KeInitializeEvent(&WrkItem->CompletionEvent, NotificationEvent, FALSE);
	
	KeAcquireSpinLock(&Worker->Lock, &Irql);
	SYS_WRK_ITEM_REF(WrkItem)
	InsertTailList(&Worker->WrkItemList, &WrkItem->ListEntry);
	KeReleaseSpinLock(&Worker->Lock, Irql);

	SysThreadSignal(&Worker->Thread);

	return WrkItem;
}

VOID
	SysWorkerAddWork(PSYSWORKER Worker, PSYS_WRK_ROUTINE Routine, PVOID Context)
{
	PSYS_WRK_ITEM WrkItem = SysWorkerAddWorkRef(Worker, Routine, Context);
	if (WrkItem != NULL) {
		SYS_WRK_ITEM_DEREF(WrkItem)
	}
}

PSYS_WRK_ITEM
	SysWorkerGetWkItemToProcess(PSYSWORKER Worker)
{
	PSYS_WRK_ITEM WrkItem = NULL;
	KIRQL Irql;

	KeAcquireSpinLock(&Worker->Lock, &Irql);
	if (!IsListEmpty(&Worker->WrkItemList)) {
		PLIST_ENTRY ListEntry;
		ListEntry = RemoveHeadList(&Worker->WrkItemList);
		WrkItem = CONTAINING_RECORD(ListEntry, SYS_WRK_ITEM, ListEntry);
	}
	KeReleaseSpinLock(&Worker->Lock, Irql);
	return WrkItem;
}

BOOLEAN
	SysWorkerThreadRoutine(PVOID Context)
{
	PSYSWORKER Worker = (PSYSWORKER)Context;
	PSYS_WRK_ITEM WrkItem;
	BOOLEAN bCallMeAgain = FALSE;
	KIRQL Irql;

	while ((!Worker->Stopping) && ((WrkItem = SysWorkerGetWkItemToProcess(Worker)) != NULL)) {
		WrkItem->Status = WrkItem->Routine(WrkItem->Context);
		KeSetEvent(&WrkItem->CompletionEvent, 0, FALSE);
		SYS_WRK_ITEM_DEREF(WrkItem)
	}
	
	KeAcquireSpinLock(&Worker->Lock, &Irql);
	if (!IsListEmpty(&Worker->WrkItemList))
		bCallMeAgain = TRUE;
	KeReleaseSpinLock(&Worker->Lock, Irql);
	
	return bCallMeAgain;
}

VOID
	SysWorkerInit(PSYSWORKER Worker)
{
	Worker->Stopping = 0;
	SysThreadInit(&Worker->Thread);
	InitializeListHead(&Worker->WrkItemList);
	KeInitializeSpinLock(&Worker->Lock);
}

NTSTATUS
	SysWorkerInitStart(PSYSWORKER Worker)
{
	SysWorkerInit(Worker);
	return SysWorkerStart(Worker);
}

NTSTATUS
	SysWorkerStart(PSYSWORKER Worker)
{
	NTSTATUS Status;

	Status = SysThreadStart(&Worker->Thread, SysWorkerThreadRoutine, Worker);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Worker->Stopping = 0;

	return STATUS_SUCCESS;
}

VOID
	SysWorkerStop(PSYSWORKER Worker)
{
	PSYS_WRK_ITEM WrkItem = NULL;
	Worker->Stopping = 1;
	SysThreadStop(&Worker->Thread);

	while ((WrkItem = SysWorkerGetWkItemToProcess(Worker)) != NULL) {
		SYS_WRK_ITEM_DEREF(WrkItem)
	}
}