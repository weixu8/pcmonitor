#pragma once

#include <inc\drvmain.h>
#include <inc\klogger.h>

NTSTATUS
	CRtlUnicodeStringCopyToSZ(IN PUNICODE_STRING Src, OUT PUNICODE_STRING pDst, ULONG Tag);

VOID
	CRtlUnicodeStringFreeAndZero(IN PUNICODE_STRING Src);

char *CRtlCopyStr(const char *str);

char *CRtlCopyStrFromWstrBuffer(PWSTR Buf, ULONG NumChars);