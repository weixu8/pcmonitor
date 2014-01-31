#include "project.h"
#include <stdio.h>

void DebugPrint(WCHAR *Format, ...)
{
	va_list argptr;
	WCHAR Buffer[256];
	INT nChars = 0;
	DWORD pid = GetCurrentProcessId();
	DWORD tid = GetCurrentThreadId();
	DWORD sessionId = -1;

	ProcessIdToSessionId(pid, &sessionId);

	va_start(argptr, Format);
	nChars = _snwprintf_s(Buffer, RTL_NUMBER_OF(Buffer), _TRUNCATE, L"kdll.dll:s%d p%x t%x:", sessionId, pid, tid);
	nChars = _vsnwprintf_s(&Buffer[nChars], RTL_NUMBER_OF(Buffer) - nChars, _TRUNCATE, Format, argptr);

	if (nChars > 0)	{
		OutputDebugStringW(Buffer);
	} else {
		OutputDebugStringW(L"kdll.dll:FORMATING FAILED!!!");
	}

	va_end(argptr);
}