#ifndef __MSTUB_H__
#define __MSTUB_H__

#include <ntifs.h>

extern ULONG_PTR stubStart;
extern ULONG_PTR stubSize;
/*
STUB_DATA				struc
libName					dw		100h dup(? )
Kernel32Name			dw		20h dup(? )
VirtualProtectName		db		20h dup(? )
bLoadLibraryEx			db ?
pLoadLibraryW			dq ?
pGetProcAddress			dq ?
VirtualProtect			dq ?
STUB_DATA			ends
*/

#pragma pack(push, 1)

typedef struct _STUB_DATA {
	ULONG_PTR   Inited;
	WCHAR		LibName[0x100];
	WCHAR		Kernel32Name[0x20];
	CHAR		VirtualProtectName[0x20];
	BOOLEAN		bLoadLibraryEx;
	PVOID		pLoadLibraryW;
	PVOID		pGetProcAddress;
	PVOID		VirtualProtect;
} STUB_DATA, *PSTUB_DATA;

#pragma pack(pop)

#endif
