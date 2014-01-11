#include <inc\processtable.h>
#include <inc\monitor.h>
#include <inc\klogger.h>

#define __SUBCOMPONENT__ "processtable"

#define MODULE_TAG 'prtb'

ULONG
	NTAPI
	ProcessEntryHash(PPROCESS_ENTRY Entry)
{
	return THashPtrHash((ULONG_PTR)Entry->Process);
}

VOID
	ProcessEntryRelease(PPROCESS_ENTRY Entry)
{
	KLog(LInfo, "ProcEntry=%p , proc=%p released", Entry, Entry->Process);

	if (Entry->Process != NULL)
		ObDereferenceObject(Entry->Process);

	ExFreePoolWithTag(Entry, MODULE_TAG);
}

VOID
	ProcessEntryRef(PPROCESS_ENTRY Entry) 
{
	InterlockedIncrement(&Entry->RefCount);
}

VOID
	ProcessEntryDeref(PPROCESS_ENTRY Entry) 
{
	LONG RefCount = -1;
	RefCount = InterlockedDecrement(&Entry->RefCount);
	if (RefCount < 0)
		__debugbreak();

	if (0 == RefCount) {
		ProcessEntryRelease(Entry);
	}
}

PPROCESS_ENTRY
	ProcessEntryCreate(PPROCESS_TABLE Table, PEPROCESS Process)
{
	PPROCESS_ENTRY Entry = NULL;
	BOOLEAN Inserted = FALSE;

	Entry = (PPROCESS_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_ENTRY), MODULE_TAG);
	if (Entry == NULL) {
		KLog(LError, "Cant alllocate entry for proc=%p\n", Process);
		return NULL;
	}
	KLog(LInfo, "ProcEntry=%p created , proc=%p", Entry, Process);

	RtlZeroMemory(Entry, sizeof(PROCESS_ENTRY));
	ObReferenceObject(Process);
	Entry->Process = Process;
	Entry->RefCount = 2;

	THashInsertUniqueByPtrClb(&Table->HashTable, (PTHASH_ENTRY)Entry, FIELD_OFFSET(PROCESS_ENTRY, Process), ProcessEntryHash(Entry), FALSE, NULL, NULL, &Inserted);
	if (!Inserted) {
		KLog(LInfo, "duplicate entry already exists for proc=%p\n", Process);
		ProcessEntryDeref(Entry);
		ProcessEntryDeref(Entry);
		return NULL;
	} 

	return Entry;
}

UCHAR NTAPI ProcessEntryLookupClb(PPROCESS_ENTRY Entry, PVOID Context)
{
	ProcessEntryRef(Entry);
	return tHashBreak;
}

PPROCESS_ENTRY
	ProcessEntryLookup(PPROCESS_TABLE Table, PEPROCESS Process)
{
	PPROCESS_ENTRY Entry = NULL;
	Entry = (PPROCESS_ENTRY)THashLookupByPtrClb(&Table->HashTable, (ULONG_PTR)Process, FIELD_OFFSET(PROCESS_ENTRY, Process), THashPtrHash((ULONG_PTR)Process), FALSE, (PTHASH_SCAN_FN)ProcessEntryLookupClb, NULL);
	
	return Entry;
}

UCHAR NTAPI ProcessEntryRemoveClb(PPROCESS_ENTRY Entry, PVOID Context) 
{
	return tHashRemove;
}

PPROCESS_ENTRY
	ProcessEntryRemove(PPROCESS_TABLE Table, PEPROCESS Process)
{
	PPROCESS_ENTRY Entry = NULL;
	Entry = (PPROCESS_ENTRY)THashLookupByPtrClb(&Table->HashTable, (ULONG_PTR)Process, FIELD_OFFSET(PROCESS_ENTRY, Process), THashPtrHash((ULONG_PTR)Process), FALSE, (PTHASH_SCAN_FN)ProcessEntryRemoveClb, NULL);

	return Entry;
}

UCHAR
NTAPI
	ProcessEntryScanClb(PPROCESS_ENTRY Entry, PLIST_ENTRY ListHead)
{
	ProcessEntryRef(Entry);
	InsertHeadList(ListHead, &Entry->ListEntry);

	return tHashContinue;
}

NTSTATUS
	ProcessTableWaitWorker(PPROCESS_TABLE Table)
{
	LIST_ENTRY EntryList;
	PLIST_ENTRY ListEntry = NULL;
	PPROCESS_ENTRY Entry = NULL;

	InitializeListHead(&EntryList);

	THashScan(&Table->HashTable, (PTHASH_SCAN_FN)ProcessEntryScanClb, &EntryList, TRUE, FALSE);

	while (!IsListEmpty(&EntryList)) {
		ListEntry = RemoveHeadList(&EntryList);
		Entry = CONTAINING_RECORD(ListEntry, PROCESS_ENTRY, ListEntry);
		if (0 != KeReadStateEvent((PRKEVENT)Entry->Process)) {
			Entry->Waited = 1;
		}

		if (Entry->Waited) {
			PPROCESS_ENTRY RemovedEntry = NULL;
			RemovedEntry = ProcessEntryRemove(Table, Entry->Process);
			if (RemovedEntry != NULL)
				ProcessEntryDeref(RemovedEntry);
		}

		ProcessEntryDeref(Entry);
	}

	return STATUS_SUCCESS;
}


UCHAR
NTAPI
	ProcessEntryScanRemoveClb(PPROCESS_ENTRY Entry, PLIST_ENTRY ListHead)
{
	InsertHeadList(ListHead, &Entry->ListEntry);

	return tHashRemove;
}

NTSTATUS 
	ProcessTableRemoveAllWorker(PPROCESS_TABLE Table)
{
	LIST_ENTRY EntryList;
	PLIST_ENTRY ListEntry = NULL;
	PPROCESS_ENTRY Entry = NULL;

	InitializeListHead(&EntryList);

	THashScan(&Table->HashTable, (PTHASH_SCAN_FN)ProcessEntryScanRemoveClb, &EntryList, TRUE, TRUE);
	while (!IsListEmpty(&EntryList)) {
		ListEntry = RemoveHeadList(&EntryList);
		Entry = CONTAINING_RECORD(ListEntry, PROCESS_ENTRY, ListEntry);
		ProcessEntryDeref(Entry);
	}

	return STATUS_SUCCESS;
}

VOID NTAPI
	ProcTableTimerDpcRoutine(
		_In_      struct _KDPC *Dpc,
		_In_opt_  PVOID DeferredContext,
		_In_opt_  PVOID SystemArgument1,
		_In_opt_  PVOID SystemArgument2
)
{
	PPROCESS_TABLE Table = (PPROCESS_TABLE)DeferredContext;

	SysWorkerAddWork(&Table->Worker, ProcessTableWaitWorker, Table);
}

VOID
	ProcessTableInit(PPROCESS_TABLE Table)
{
	RtlZeroMemory(Table, sizeof(PROCESS_TABLE));
	KeInitializeTimer(&Table->Timer);
	KeInitializeDpc(&Table->TimerDpc, ProcTableTimerDpcRoutine, Table);
	SysWorkerInit(&Table->Worker);
}

NTSTATUS
	ProcessTableStart(PPROCESS_TABLE Table)
{
	NTSTATUS Status;
	LARGE_INTEGER TimerDueTime;

	THashInitialize(&Table->HashTable, (PTHASH_HASH_FN)ProcessEntryHash, NULL, NULL, NULL);

	Status = SysWorkerStart(&Table->Worker);
	if (!NT_SUCCESS(Status)) {
		goto start_failed;
	}

	TimerDueTime.QuadPart = 0;
	KeSetTimerEx(&Table->Timer, TimerDueTime, 500, &Table->TimerDpc);
	return STATUS_SUCCESS;

start_failed:
	KeCancelTimer(&Table->Timer);
	KeFlushQueuedDpcs();
	SysWorkerStop(&Table->Worker);
	THashRelease(&Table->HashTable);

	return Status;
}

VOID
	ProcessTableStop(PPROCESS_TABLE Table)
{
	PSYS_WRK_ITEM WrkItem = NULL;

	KeCancelTimer(&Table->Timer);
	KeFlushQueuedDpcs();

	WrkItem = SysWorkerAddWorkRef(&Table->Worker, ProcessTableRemoveAllWorker, Table);
	if (WrkItem != NULL) {
		KeWaitForSingleObject(&WrkItem->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		SysWrkItemDeref(WrkItem);
	}

	SysWorkerStop(&Table->Worker);
	THashRelease(&Table->HashTable);
}
