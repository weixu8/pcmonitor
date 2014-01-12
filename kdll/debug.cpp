#include "project.h"
#include <stdio.h>

void DebugPrint(CHAR *Format, ...)
{
	va_list argptr;
	CHAR Buffer[256];
	INT nChars = 0;
	DWORD pid = GetCurrentProcessId();
	DWORD tid = GetCurrentThreadId();
	DWORD sessionId = -1;

	ProcessIdToSessionId(pid, &sessionId);

	va_start(argptr, Format);
	nChars = _snprintf_s(Buffer, RTL_NUMBER_OF(Buffer), _TRUNCATE, "kdll.dll:s%d p%x t%x:", sessionId, pid, tid);
	nChars = _vsnprintf_s(&Buffer[nChars], RTL_NUMBER_OF(Buffer) - nChars, _TRUNCATE, Format, argptr);

	if (nChars > 0)	{
		OutputDebugStringA(Buffer);
	}
	va_end(argptr);
}