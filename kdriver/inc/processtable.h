#pragma once
#include <inc\drvmain.h>
#include <inc\thash.h>
#include <inc\sysworker.h>
#include <inc\inject.h>

typedef struct _PROCESS_ENTRY {
	THASH_ENTRY			HashEntry;
	LIST_ENTRY			ListEntry;
	PEPROCESS			Process;
	LONG				RefCount;
	LONG				Waited;
	INJECT_INFO			InjectInfo;
} PROCESS_ENTRY, *PPROCESS_ENTRY;


typedef struct _PROCESS_TABLE {
	THASH				HashTable;
	SYSWORKER			Worker;
	KTIMER				Timer;
	KDPC				TimerDpc;
} PROCESS_TABLE, *PPROCESS_TABLE; 

VOID
	ProcessTableInit(PPROCESS_TABLE Table);

NTSTATUS
	ProcessTableStart(PPROCESS_TABLE Table);

VOID
	ProcessTableStop(PPROCESS_TABLE Table);

PPROCESS_ENTRY
	ProcessEntryCreate(PPROCESS_TABLE Table, PEPROCESS Process);

PPROCESS_ENTRY
	ProcessEntryLookup(PPROCESS_TABLE Table, PEPROCESS Process);


VOID
ProcessEntryRef(PPROCESS_ENTRY Entry);

VOID
ProcessEntryDeref(PPROCESS_ENTRY Entry);

