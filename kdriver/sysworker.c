#include <inc/sysworker.h>
#include <inc/klogger.h>

#define __SUBCOMPONENT__ "sysworker"


#define SYS_WRK_ITEM_TAG 'mont'

typedef struct _SYS_WRK_ITEM {
	LIST_ENTRY				ListEntry;
	PSYS_WRK_ROUTINE		Routine;
	PVOID					Context;
} SYS_WRK_ITEM, *PSYS_WRK_ITEM;

VOID
	SysWorkerAddWork(PSYSWORKER Worker, PSYS_WRK_ROUTINE Routine, PVOID Context)
{
	PSYS_WRK_ITEM WrkItem;
	KIRQL Irql;

	if (Worker->Stopping)
		return;

	WrkItem = (PSYS_WRK_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(SYS_WRK_ITEM), SYS_WRK_ITEM_TAG);
	if (WrkItem == NULL) {
		__debugbreak();
		return;
	}

	WrkItem->Routine = Routine;
	WrkItem->Context = Context;

	KeAcquireSpinLock(&Worker->Lock, &Irql);
	InsertTailList(&Worker->WrkItemList, &WrkItem->ListEntry);
	KeReleaseSpinLock(&Worker->Lock, Irql);

	SysThreadSignal(&Worker->Thread);
}

PSYS_WRK_ITEM
	SysWorkerGetWkItemToProcess(PSYSWORKER Worker)
{
	PSYS_WRK_ITEM WrkItem = NULL;
	KIRQL Irql;

	KeAcquireSpinLock(&Worker->Lock, &Irql);
	while (!IsListEmpty(&Worker->WrkItemList)) {
		PLIST_ENTRY ListEntry;
		ListEntry = RemoveHeadList(&Worker->WrkItemList);
		WrkItem = CONTAINING_RECORD(ListEntry, SYS_WRK_ITEM, ListEntry);
	}
	KeReleaseSpinLock(&Worker->Lock, Irql);
	return WrkItem;
}

VOID
	SysWorkerThreadRoutine(PVOID Context)
{
	PSYSWORKER Worker = (PSYSWORKER)Context;
	PSYS_WRK_ITEM WrkItem;
	BOOLEAN bSignalThread = FALSE;
	KIRQL Irql;

	while ((!Worker->Stopping) && ((WrkItem = SysWorkerGetWkItemToProcess(Worker)) != NULL)) {
		WrkItem->Routine(WrkItem->Context);
		ExFreePoolWithTag(WrkItem, SYS_WRK_ITEM_TAG);
	}
	
	KeAcquireSpinLock(&Worker->Lock, &Irql);
	if (!IsListEmpty(&Worker->WrkItemList))
		bSignalThread = TRUE;
	KeReleaseSpinLock(&Worker->Lock, Irql);
	
	if (bSignalThread)
		SysThreadSignal(&Worker->Thread);
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
	SysWorkerStart(PSYSWORKER Worker)
{
	NTSTATUS Status;

	Status = SysThreadStart(&Worker->Thread, SysWorkerThreadRoutine, Worker);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	return STATUS_SUCCESS;
}

VOID
	SysWorkerStop(PSYSWORKER Worker)
{
	PSYS_WRK_ITEM WrkItem = NULL;
	Worker->Stopping = 1;
	SysThreadStop(&Worker->Thread);

	while ((WrkItem = SysWorkerGetWkItemToProcess(Worker)) != NULL) {
		ExFreePoolWithTag(WrkItem, SYS_WRK_ITEM_TAG);
	}
}