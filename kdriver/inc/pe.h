#pragma once

#include <inc\drvmain.h>
#include <inc\klogger.h>
#include <ntimage.h>

PVOID
PeGetPtrFromRVA(
IN ULONG_PTR			rva,
IN PIMAGE_NT_HEADERS	pNTHeader,
IN PUCHAR				imageBase
);


PVOID
PeGetImportTableEntry(
IN PCHAR             pszCalleeModName, // Import module name
IN PCHAR             strFunctionName,	// Entry name
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
IN const char * strFunctionName,
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
IN const char         *strFunctionName
);