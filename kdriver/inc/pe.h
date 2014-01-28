#pragma once

#include <inc\drvmain.h>
#include <inc\klogger.h>
#include <inc\ntapiex.h>

#include <ntimage.h>

PVOID
PeGetModuleBaseAddressByName(
IN PCSZ pModuleName
);

PVOID
PeGetModuleBaseAddressByName(
IN PCSZ pModuleName
);

PVOID
PeGetModuleExportByName(PCSZ modName, PCSZ exportName);

PVOID
PeGetPtrFromRVA(
IN ULONG_PTR			rva,
IN PIMAGE_NT_HEADERS	pNTHeader,
IN PUCHAR				imageBase
);


PVOID
PeGetImportTableEntry(
IN PCSZ             pszCalleeModName, // Import module name
IN PCSZ             strFunctionName,	// Entry name
IN PVOID             pModuleBase,	    // Pointer to the beginning of the image 
IN PIMAGE_NT_HEADERS pNTHeader         // Pointer to the image NT header	
);

PIMAGE_NT_HEADERS
PeDosHeaderToNtHeader(
IN PIMAGE_DOS_HEADER pDosHeader,
IN ULONG ImageSize
);

VOID
PeGetModuleBaseAddress(
IN  PVOID              pAddress,
OUT PIMAGE_DOS_HEADER *ppDOSHeader,
OUT PIMAGE_NT_HEADERS *ppPEHeader
);

PVOID
PeGetExportEntry(
IN PCSZ strFunctionName,
IN PVOID   pModuleBase,
IN ULONG   NumberOfNames,
IN PULONG  ppFunctions,
IN PULONG  ppNames,
IN PUSHORT pOrdinals
);

PVOID
PeGetExportEntryByName(
IN PIMAGE_DOS_HEADER  pDOSHeader,
IN PIMAGE_NT_HEADERS  pPEHeader,
IN PCSZ strFunctionName
);


PSYSTEM_MODULE_INFORMATION
PeGetModuleInfo(
IN PCSZ pModuleName
);
