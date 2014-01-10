#pragma once

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
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

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

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;


typedef
VOID
(*PKNORMAL_ROUTINE) (
IN PVOID NormalContext,
IN PVOID SystemArgument1,
IN PVOID SystemArgument2
);


typedef
VOID
(*PKNORMAL_ROUTINE) (
IN PVOID NormalContext,
IN PVOID SystemArgument1,
IN PVOID SystemArgument2
);

typedef
VOID
(*PKKERNEL_ROUTINE) (
IN struct _KAPC *Apc,
IN OUT PKNORMAL_ROUTINE *NormalRoutine,
IN OUT PVOID *NormalContext,
IN OUT PVOID *SystemArgument1,
IN OUT PVOID *SystemArgument2
);

typedef
VOID
(*PKRUNDOWN_ROUTINE) (
IN struct _KAPC *Apc
);

NTSYSAPI
VOID
KeInitializeApc(
__out PRKAPC Apc,
__in PRKTHREAD Thread,
__in KAPC_ENVIRONMENT Environment,
__in PKKERNEL_ROUTINE KernelRoutine,
__in_opt PKRUNDOWN_ROUTINE RundownRoutine,
__in_opt PKNORMAL_ROUTINE NormalRoutine,
__in_opt KPROCESSOR_MODE ProcessorMode,
__in_opt PVOID NormalContext
);


NTSYSAPI
BOOLEAN
KeInsertQueueApc(
__inout PRKAPC Apc,
__in_opt PVOID SystemArgument1,
__in_opt PVOID SystemArgument2,
__in KPRIORITY Increment
);

NTSYSAPI
PVOID
PsGetThreadWin32Thread(PETHREAD Thread);

NTSYSAPI
PVOID
PsGetProcessSectionBaseAddress(PEPROCESS Process);

NTSYSAPI
PCHAR
PsGetProcessImageFileName(PEPROCESS Process);

NTSYSAPI
PIMAGE_NT_HEADERS
RtlImageNtHeader(PVOID ImageBase);


NTSYSAPI
POBJECT_TYPE *ExWindowStationObjectType;

NTSYSAPI
POBJECT_TYPE *ExDesktopObjectType;

NTSYSAPI
NTSTATUS
ObOpenObjectByName(
__in POBJECT_ATTRIBUTES ObjectAttributes,
__in_opt POBJECT_TYPE ObjectType,
__in KPROCESSOR_MODE AccessMode,
__inout_opt PACCESS_STATE AccessState,
__in_opt ACCESS_MASK DesiredAccess,
__inout_opt PVOID ParseContext,
__out PHANDLE Handle
);

NTSYSAPI
ULONG
PsGetProcessSessionId(
__in PEPROCESS Process
);

