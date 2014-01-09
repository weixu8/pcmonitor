#include <inc/keybrd.h>
#include <inc/klogger.h>
#include <inc/ecore.h>
#include <inc/ntapiex.h>
#include <injectstub/h/stub.h>
#include <ntimage.h>

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

		RtlZeroMemory(&Timeout, sizeof(Timeout));
		Timeout.LowPart = -500;//50ms

		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
	}

	return (ApcQueued) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


PVOID
	PeGetPtrFromRVA(
		IN ULONG_PTR			rva,
		IN PIMAGE_NT_HEADERS	pNTHeader,
		IN PUCHAR				imageBase
)
{
	return (PVOID)(imageBase + rva);
}

PVOID
	PeGetImportTableEntry(
		IN PCHAR             pszCalleeModName, // Import module name
		IN PCHAR             strFunctionName,	// Entry name
		IN PVOID             pModuleBase,	    // Pointer to the beginning of the image 
		IN PIMAGE_NT_HEADERS pNTHeader         // Pointer to the image NT header	
)
{
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
	ULONG                    importsStartRVA;
	PSTR                     pszModName;

	ULONG                    rvaINT;
	ULONG                    rvaIAT;

	PIMAGE_THUNK_DATA        pINT;
	PIMAGE_THUNK_DATA        pIAT;

	PIMAGE_IMPORT_BY_NAME    pOrdinalName;
	PVOID                     ppfn = NULL;

	// Look up where the imports section is (normally in the .idata section)
	// but not necessarily so.  Therefore, grab the RVA from the data dir.
	importsStartRVA =
		pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (!importsStartRVA)
		return NULL;

	pImportDesc =
		(PIMAGE_IMPORT_DESCRIPTOR)PeGetPtrFromRVA(
		importsStartRVA, pNTHeader, pModuleBase);

	if (!pImportDesc)
		return NULL;

	// Find the import descriptor containing references to callee's functions
	for (; pImportDesc->Name; pImportDesc++) {
		pszModName = (PCHAR)PeGetPtrFromRVA(
			pImportDesc->Name, pNTHeader, pModuleBase);
		if (pszModName)
		if (_stricmp(pszModName, pszCalleeModName) == 0)
			break;   // Found
	}

	if (pImportDesc->Name == 0)
		goto __end;  // This module doesn't import any functions from this callee

	rvaINT = pImportDesc->OriginalFirstThunk;
	rvaIAT = pImportDesc->FirstThunk;

	if (rvaINT == 0)   // No Characteristics field?
	{
		// Yes! Gotta have a non-zero FirstThunk field then.
		rvaINT = rvaIAT;

		if (rvaINT == 0)   // No FirstThunk field?  Ooops!!!
			goto __end;
	}

	// Adjust the pointer to point where the tables are in the
	// mem mapped file.
	pINT = (PIMAGE_THUNK_DATA)PeGetPtrFromRVA(rvaINT, pNTHeader, pModuleBase);
	if (!pINT)
		goto __end;

	pIAT = (PIMAGE_THUNK_DATA)PeGetPtrFromRVA(rvaIAT, pNTHeader, pModuleBase);


	while (1) // Loop forever (or until we break out)
	{
		if (pINT->u1.AddressOfData == 0)
			break;

		if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal) == FALSE)
		{
			pOrdinalName =
				(PIMAGE_IMPORT_BY_NAME)
				PeGetPtrFromRVA(
				(ULONG_PTR)pINT->u1.AddressOfData,
				pNTHeader,
				pModuleBase
				);
			if (_stricmp(pOrdinalName->Name, strFunctionName) == 0) {
				ppfn = (PVOID)&pIAT->u1.Function;
				break;  // We did it, get out
			}
		}
		else if (pINT->u1.Ordinal >= (ULONG_PTR)pModuleBase &&
			pINT->u1.Ordinal < ((ULONG_PTR)pModuleBase + pNTHeader->OptionalHeader.SizeOfImage))
		{
			pOrdinalName = (PIMAGE_IMPORT_BY_NAME)pINT->u1.AddressOfData;
			if (pOrdinalName) {
				if (_stricmp(pOrdinalName->Name, strFunctionName) == 0) {
					ppfn = (PVOID)&pIAT->u1.Function;
					break;  // We did it, get out
				}
			}
		}

		pINT++;         // Advance to next thunk
		pIAT++;         // advance to next thunk
	}

__end:

	return ppfn;
}

PIMAGE_NT_HEADERS
PeDosHeaderToNtHeader(
IN PIMAGE_DOS_HEADER pDosHeader,
IN ULONG ImageSize
)
{
	PIMAGE_NT_HEADERS pNtHeader;
	if (!pDosHeader){
		return NULL;
	}
	//paranoia: e_lfanew < 4Kb
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
		pDosHeader->e_lfanew > 0x1000 ||
		(ImageSize != 0 && pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) >= ImageSize) ||
		pDosHeader->e_lfanew <= 0)
	{
		return NULL;
	}

	pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}
	return pNtHeader;
}

VOID
	PeGetModuleBaseAddress(
		IN  PVOID              pAddress,
		OUT PIMAGE_DOS_HEADER *ppDOSHeader,
		OUT PIMAGE_NT_HEADERS *ppPEHeader
)
{
	// All modules are page aligned in memory

	*ppDOSHeader = (PIMAGE_DOS_HEADER)(PAGE_ALIGN(pAddress));

	// Go up in memory looking for image header

	while (TRUE)
	{
		*ppPEHeader = PeDosHeaderToNtHeader(*ppDOSHeader, 0);
		if (*ppPEHeader)
		{
			// Criteria for image header passed
			return;
		}
		*ppDOSHeader = (PIMAGE_DOS_HEADER)((PUCHAR)*ppDOSHeader - PAGE_SIZE);
	}
}

PVOID
	PeGetExportEntry(
		IN const char * strFunctionName,
		IN PVOID   pModuleBase,
		IN ULONG   NumberOfNames,
		IN PULONG  ppFunctions,
		IN PULONG  ppNames,
		IN PUSHORT pOrdinals
)
{
	ULONG i, dwOldPointer = 0;

	// Walk the export table entries
	for (i = 0; i < NumberOfNames; ++i)
	{
		// Check if function name matches current entry
		if (!strcmp((char*)pModuleBase + *ppNames, (char*)strFunctionName))
		{
			dwOldPointer = ppFunctions[*pOrdinals];
			return (PUCHAR)pModuleBase + dwOldPointer; // absolute address
		}
		ppNames++;
		pOrdinals++;
	}
	return NULL;
}

PVOID
	PeGetExportEntryByName(
		IN PIMAGE_DOS_HEADER  pDOSHeader,
		IN PIMAGE_NT_HEADERS  pPEHeader,
		IN const char         *strFunctionName
)
{
	PIMAGE_EXPORT_DIRECTORY pExpDir = NULL;
	PULONG   ppFunctions = NULL;
	PULONG   ppNames = NULL;
	PUSHORT  pOrdinals = NULL;

	NTSTATUS ntStatus = STATUS_SUCCESS;
	KIRQL    kIrqlOld;
	ULONG    ulOldValue;

	if (pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0){
		return NULL;
	}
	// Get export directory
	pExpDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDOSHeader +
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (pExpDir->AddressOfFunctions == 0 ||
		pExpDir->AddressOfNames == 0)
	{
		return NULL;
	}

	// Get names, functions and ordinals arrays pointers
	ppFunctions = (PULONG)((PUCHAR)pDOSHeader + (ULONG)pExpDir->AddressOfFunctions);
	ppNames = (PULONG)((PUCHAR)pDOSHeader + (ULONG)pExpDir->AddressOfNames);
	pOrdinals = (PUSHORT)((PUCHAR)pDOSHeader + (ULONG)pExpDir->AddressOfNameOrdinals);

	return
		PeGetExportEntry(strFunctionName,
		(PUCHAR)pDOSHeader,
		pExpDir->NumberOfNames,
		ppFunctions,
		ppNames,
		pOrdinals
		);
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
InjectDllProcess(HANDLE ProcessHandle, PEPROCESS Process, PSYSTEM_PROCESS_INFORMATION ProcInfo, ULONG_PTR ProcInfoBarrier, PUNICODE_STRING DllPath, PUNICODE_STRING DllName)
{

	NTSTATUS Status;
	SIZE_T pStubSize = 0;
	KAPC_STATE ApcState;
	ULONG Index = 0;
	PETHREAD Thread = NULL;
	ULONG InjectedCount = 0;
	PSTUB_DATA pStubData = NULL;

	KLog(LInfo, "ProcH=%p, proc=%p, DllPath=%wZ, DllName=%wZ", ProcessHandle, Process, DllPath, DllName);

	Status = InjectProcessAllocateCode(ProcessHandle, &pStubData, &pStubSize);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	KLog(LInfo, "pStubCode=%p, pStubSize=%x", pStubData, pStubSize);

	KeStackAttachProcess(Process, &ApcState);
	RtlCopyMemory(pStubData, (PVOID)&stubStart, (ULONG)stubSize);
	Status = InjectDllProcessSetStubData(ProcessHandle, Process, pStubData, DllPath, DllName);
	KeUnstackDetachProcess(&ApcState);
	if (!NT_SUCCESS(Status)) {
		goto free_mem;
	}

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

	KLog(LInfo, "InjectedCount=%x", InjectedCount);
	if (InjectedCount > 0) {
		LARGE_INTEGER Timeout;

		RtlZeroMemory(&Timeout, sizeof(Timeout));
		Timeout.LowPart = -5000;//500ms

		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

		KeStackAttachProcess(Process, &ApcState);
		Status = (pStubData->Inited) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		KeUnstackDetachProcess(&ApcState);
		if (NT_SUCCESS(Status))
			KLog(LInfo, "Injection SUCCESS for proc=%p", Process);

		return Status;
	} else {
free_mem:
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
InjectCheckProcessAndInjectDll(PEPROCESS Process, PSYSTEM_PROCESS_INFORMATION ProcInfo, ULONG_PTR ProcInfoBarrier, PUNICODE_STRING ProcessPrefix, PUNICODE_STRING DllPath, PUNICODE_STRING DllName)
{
	NTSTATUS Status;
	PUNICODE_STRING pImageFileName = NULL;
	UNICODE_STRING ImageFileNameSz = { 0, 0, NULL };
	UNICODE_STRING ProcessPrefixSz = { 0, 0, NULL };
	HANDLE ProcessHandle = NULL;
	BOOLEAN bProcAcquired = FALSE;

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
	bProcAcquired = TRUE;

	Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &ProcessHandle);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Cant open handle for process=%p, name=%wZ, error=%x", Process, &ImageFileNameSz, Status);
		goto cleanup;
	}

	Status = InjectDllProcess(ProcessHandle, Process, ProcInfo, ProcInfoBarrier, DllPath, DllName);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Can't inject dll for process=%p, name=%wZ, error=%x", Process, &ImageFileNameSz, Status);
	}

cleanup:
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
			KLog(LError, "lookup for pid=%p failed error=%x", CurrProcInfo->UniqueProcessId, Status);
			goto _next_process;
		}
		KLog(LInfo, "found proc %p by pid=%p", Process, CurrProcInfo->UniqueProcessId);

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
