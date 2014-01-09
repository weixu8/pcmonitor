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
	ULONG_PTR		Inited;
	PVOID			LdrLoadDll;
	UNICODE_STRING	usDllName;
	WCHAR			DllName[0x100];
	WCHAR			DllPath[0x100];
	PVOID			hModule;
	ULONG_PTR		Loaded;
} STUB_DATA, *PSTUB_DATA;

#pragma pack(pop)

#endif
