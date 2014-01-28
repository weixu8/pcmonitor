#include <inc\pe.h>
#include <inc\ntapiex.h>

#define __SUBCOMPONENT__ "pe"
#define MODULE_TAG 'pelb'

char* KstdStrRChr(char* pStr, char ch) {
	if (pStr) {
		do {
			pStr++;
		} while (*pStr);
		pStr--;

		while (*pStr) {
			if (*pStr == ch) return pStr;
			pStr--;
		}
	}
	return NULL;
}

PVOID
PeGetModuleExportByName(PCSZ modName, PCSZ exportName)
{
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PVOID modBase = NULL;
	PVOID exportAddr = NULL;

	modBase = PeGetModuleBaseAddressByName(modName);
	if (modBase == NULL) {
		KLog(LError, "cant resolve modBase by name=%s", modName);
		return NULL;
	}

	pNtHeader = RtlImageNtHeader(modBase);
	if (pNtHeader == NULL) {
		KLog(LError, "cant get nt header for mod:%s, base=%p\n", modName, modBase);
		return NULL;
	}

	exportAddr = PeGetExportEntryByName(modBase, pNtHeader, exportName);
	if (exportAddr == NULL) {
		KLog(LError, "cant resolve address of export %s, mod:%s, base=%p\n", exportName, modName, modBase);
		return NULL;
	}

	return exportAddr;
}

PSYSTEM_MODULE_INFORMATION
PeGetModuleInfo(
	IN PCSZ pModuleName
	)
{
	ULONG		ulReturn;
	ULONG		ulCount;
	ULONG		i;
	PCHAR		pBuffer = NULL;
	NTSTATUS	ntStatus;
	PSYSTEM_MODULE_INFORMATION pModule, pCurrModule;
	CHAR		initBuffer[10];
	BOOLEAN		bFound = FALSE;

	pModule = ExAllocatePoolWithTag(NonPagedPool, sizeof(SYSTEM_MODULE_INFORMATION), MODULE_TAG);
	if (pModule == NULL)
		return NULL;

	ntStatus = ZwQuerySystemInformation(SystemModuleInformation, initBuffer, 10, &ulReturn);

	ulReturn = 2 * ulReturn;

	pBuffer = (PCHAR)ExAllocatePoolWithTag(
		NonPagedPool,
		ulReturn,
		MODULE_TAG
		);
	if (!pBuffer)
		return NULL;

	ntStatus = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulReturn, &ulReturn);
	if (ntStatus == STATUS_SUCCESS)
	{
		ulCount = (ULONG)*((ULONG *)pBuffer);
		pCurrModule = (PSYSTEM_MODULE_INFORMATION)(pBuffer + sizeof(ULONG_PTR));
		for (i = 0; i<ulCount; i++)
		{
			PCHAR pBaseName = KstdStrRChr(pCurrModule->ImageName, '\\');
			if (!pBaseName) pBaseName = pCurrModule->ImageName;
			else pBaseName++;

			if (!_stricmp((const char*)pBaseName, pModuleName))
			{
				RtlCopyMemory(pModule, pCurrModule, sizeof(SYSTEM_MODULE_INFORMATION));
				bFound = TRUE;
				break;
			}
			pCurrModule++;
		}
	}
	ExFreePool(pBuffer);
	if (!bFound)
		ExFreePoolWithTag(pModule, MODULE_TAG);

	return (bFound) ? pModule : NULL;
}

PVOID
PeGetModuleBaseAddressByName(
IN PCSZ pModuleName
)
{
	ULONG		ulReturn;
	ULONG		ulCount;
	ULONG		i;
	PCHAR		pBuffer = NULL;
	NTSTATUS	ntStatus;
	PSYSTEM_MODULE_INFORMATION pModule;
	CHAR		initBuffer[10];
	PVOID		pBaseAddress = NULL;

	ntStatus = ZwQuerySystemInformation(SystemModuleInformation, initBuffer, 10, &ulReturn);

	pBuffer = (PCHAR)ExAllocatePoolWithTag(
		NonPagedPool,
		ulReturn,
		MODULE_TAG
		);
	if (!pBuffer)
		return pBaseAddress;

	ntStatus = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulReturn, &ulReturn);
	if (ntStatus == STATUS_SUCCESS)
	{
		ulCount = (ULONG)*((ULONG *)pBuffer);
		pModule = (PSYSTEM_MODULE_INFORMATION)(pBuffer + sizeof(ULONG_PTR));
		for (i = 0; i<ulCount; i++)
		{
			PCHAR pBaseName = KstdStrRChr(pModule->ImageName, '\\');
			if (!pBaseName) pBaseName = pModule->ImageName;
			else pBaseName++;

			if (!_stricmp((const char*)pBaseName, pModuleName))
			{
				pBaseAddress = pModule->Base;
				break;
			}
			pModule++;
		}
	}
	ExFreePool(pBuffer);
	return pBaseAddress;
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
IN PCSZ             pszCalleeModName, // Import module name
IN PCSZ             strFunctionName,	// Entry name
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
IN PCSZ strFunctionName,
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
IN PCSZ strFunctionName
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
