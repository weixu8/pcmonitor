#include <inc\htable.h>

#define __SUBCOMPONENT__ "htable"
#define MODULE_TAG 'htbl'

NTSTATUS HTableInit(PHTABLE HTable, ULONG MaxHandles)
{
	RtlZeroMemory(HTable, sizeof(HTABLE));
	HTable->Objects = (PVOID *)ExAllocatePoolWithTag(NonPagedPool, MaxHandles*sizeof(PVOID), MODULE_TAG);
	if (HTable->Objects == NULL) {
		return STATUS_NO_MEMORY;
	}

	RtlZeroMemory(HTable->Objects, MaxHandles*sizeof(PVOID));
	KeInitializeGuardedMutex(&HTable->Lock);
	HTable->MaxHandles = MaxHandles;

	return STATUS_SUCCESS;
}

VOID HTableRelease(PHTABLE HTable)
{
	if (HTable->Objects != NULL)
		ExFreePoolWithTag(HTable->Objects, MODULE_TAG);
	RtlZeroMemory(HTable, sizeof(HTABLE));
}

int HTableCreateHandle(PHTABLE HTable, PVOID Object)
{
	ULONG Index;
	int Handle = -1;

	KeAcquireGuardedMutex(&HTable->Lock);
	for (Index = 0; Index < HTable->MaxHandles; Index++) {
		if (HTable->Objects[Index] == NULL) {
			HTable->Objects[Index] = Object;
			Handle = (int)Index;
		}
	}
	KeReleaseGuardedMutex(&HTable->Lock);
	return Handle;
}

void HTableCloseHandle(PHTABLE HTable, int handle)
{
	ULONG Index = (ULONG)handle;

	if (handle < 0 || Index >= HTable->MaxHandles)
		return;

	KeAcquireGuardedMutex(&HTable->Lock);
	if (Index < HTable->MaxHandles)
		HTable->Objects[Index] = NULL;
	KeReleaseGuardedMutex(&HTable->Lock);
}


PVOID HTableRefByHandle(PHTABLE HTable, int handle)
{
	ULONG Index = (ULONG)handle;
	PVOID Object = NULL;

	if (handle < 0 || Index >= HTable->MaxHandles)
		return NULL;

	KeAcquireGuardedMutex(&HTable->Lock);
	if (Index < HTable->MaxHandles)
		Object = HTable->Objects[Index];
	KeReleaseGuardedMutex(&HTable->Lock);
	
	return Object;
}