#include <inc\processtable.h>
#include <inc\monitor.h>
#include <inc\klogger.h>

#define __SUBCOMPONENT__ "processtable"

#define MODULE_TAG 'prtb'

ULONG
	ProcEntryHash(PPROCESS_ENTRY Entry)
{
	return THashPtrHash((ULONG_PTR)Entry->Process);
}

VOID
	ProcEntryRelease(PPROCESS_ENTRY Entry)
{
	if (Entry->Process != NULL)
		ObDereferenceObject(Entry->Process);

	ExFreePoolWithTag(Entry, MODULE_TAG);
}

VOID
ProcEntryRef(PPROCESS_ENTRY Entry) {
	InterlockedIncrement(&Entry->RefCount);
}

VOID
ProcEntryDeref(PPROCESS_ENTRY Entry) {
	LONG RefCount = -1;
	RefCount = InterlockedDecrement(&Entry->RefCount);
	if (RefCount < 0)
		__debugbreak();

	if (0 == RefCount) {
		ProcEntryRelease(Entry);
	}
}


VOID
	ProcessTableInit(THASH *ProcTable)
{
	THashInitialize(ProcTable, (PTHASH_HASH_FN)ProcEntryHash, NULL, NULL, NULL);
}

UCHAR NTAPI ProcEntryScanRemoveClb(PPROCESS_ENTRY Entry, PLIST_ENTRY ListHead)
{
	InsertHeadList(ListHead, &Entry->ListEntry);

	return tHashRemove;
}

VOID
	ProcessTableRelease(THASH *ProcTable)
{
	LIST_ENTRY EntryList;
	PLIST_ENTRY ListEntry;
	PPROCESS_ENTRY Entry;
	
	InitializeListHead(&EntryList);

	THashScan(ProcTable, (PTHASH_SCAN_FN)ProcEntryScanRemoveClb, &EntryList, TRUE, TRUE);

	while (!IsListEmpty(&EntryList)) {
		ListEntry = RemoveHeadList(&EntryList);
		Entry = CONTAINING_RECORD(ListEntry, PROCESS_ENTRY, ListEntry);
		ProcEntryDeref(Entry);
	}

	THashRelease(ProcTable);
}


BOOLEAN
	ProcEntryCreate(THASH *ProcTable, PEPROCESS Process)
{
	PPROCESS_ENTRY Entry = NULL;
	BOOLEAN Inserted = FALSE;

	Entry = (PPROCESS_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_ENTRY), MODULE_TAG);
	if (Entry == NULL) {
		KLog(LError, "Cant alllocate entry for proc=%p\n", Process);
		return FALSE;
	}

	RtlZeroMemory(Entry, sizeof(PROCESS_ENTRY));
	ObReferenceObject(Process);
	Entry->Process = Process;
	Entry->RefCount = 1;

	THashInsertUniqueByPtrClb(ProcTable, (PTHASH_ENTRY)Entry, FIELD_OFFSET(PROCESS_ENTRY, Process), ProcEntryHash(Entry), FALSE, NULL, NULL, &Inserted);
	if (!Inserted) {
		ProcEntryDeref(Entry);
	} 

	return TRUE;
}

UCHAR ProcEntryLookupClb(PPROCESS_ENTRY Entry, PVOID Context)
{
	ProcEntryRef(Entry);
	return tHashBreak;
}

PPROCESS_ENTRY
	ProcEntryLookup(THASH *ProcTable, PEPROCESS Process)
{
	PPROCESS_ENTRY ProcEntry = NULL;
	ProcEntry = (PPROCESS_ENTRY)THashLookupByPtrClb(ProcTable, (ULONG_PTR)Process, FIELD_OFFSET(PROCESS_ENTRY, Process), THashPtrHash((ULONG_PTR)Process), FALSE, (PTHASH_SCAN_FN)ProcEntryLookupClb, NULL);
	
	return ProcEntry;
}

UCHAR 
	ProcEntryRemoveClb(PPROCESS_ENTRY Entry, PVOID Context) {
	return tHashBreak;
}

PPROCESS_ENTRY
	ProcEntryRemove(THASH *ProcTable, PEPROCESS Process)
{
	PPROCESS_ENTRY ProcEntry = NULL;
	ProcEntry = (PPROCESS_ENTRY)THashLookupByPtrClb(ProcTable, (ULONG_PTR)Process, FIELD_OFFSET(PROCESS_ENTRY, Process), THashPtrHash((ULONG_PTR)Process), FALSE, (PTHASH_SCAN_FN)ProcEntryRemoveClb, NULL);

	return ProcEntry;
}
