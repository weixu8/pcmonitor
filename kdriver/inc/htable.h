#pragma once

#include <inc\drvmain.h>


typedef struct _HTABLE {
	PVOID		   *Objects;
	ULONG		   MaxHandles;
	KGUARDED_MUTEX Lock;
} HTABLE, *PHTABLE;

NTSTATUS HTableInit(PHTABLE HTable, ULONG MaxHandles);

VOID HTableRelease(PHTABLE HTable);

int HTableCreateHandle(PHTABLE HTable, PVOID Object);

PVOID HTableRefByHandle(PHTABLE HTable, int handle);

void HTableCloseHandle(PHTABLE HTable, int handle);
