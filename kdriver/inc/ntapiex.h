#ifndef __MNTAPIEX_H__
#define __MNTAPIEX_H__

#include <inc/drvmain.h>

NTSYSAPI
PEPROCESS PsGetNextProcess(PEPROCESS Process);

NTSYSAPI
NTSTATUS
PsAcquireProcessExitSynchronization(PEPROCESS Process);

NTSYSAPI
VOID
PsReleaseProcessExitSynchronization(PEPROCESS Process);



NTSYSAPI
NTSTATUS
ZwQuerySystemInformation(ULONG InfoClass, PVOID pInfo, ULONG InfoSize, PULONG pReqSize);

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	BYTE Reserved1[52];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;



#endif
