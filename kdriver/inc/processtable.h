#pragma once
#include <inc\drvmain.h>
#include <inc\thash.h>

typedef struct _PROCESS_ENTRY {
	THASH_ENTRY HashEntry;
	LIST_ENTRY  ListEntry;
	PEPROCESS	Process;
	LONG		RefCount;
} PROCESS_ENTRY, *PPROCESS_ENTRY;


VOID
	ProcessTableInit(THASH *ProcTable);

VOID
	ProcessTableRelease(THASH *ProcTable);
