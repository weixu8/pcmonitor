#include "project.h"
#include "monitor.h"
#include "debug.h"

#define PAGE_SIZE 4096

static DWORD g_MonitorThreadId = 0;
static volatile LONG g_MonitorStopping = 0;
static HANDLE g_MonitorThreadHandle = NULL;

DWORD 
WINAPI
MonitorMainRoutine(
	_In_  LPVOID lpParameter
)
{
	DebugPrint("Monitor thread starting processId=%x, threadId=%x\n", GetCurrentProcessId(), GetCurrentThreadId());
	while (!g_MonitorStopping) {
		Sleep(100);
	}

	DebugPrint("Monitor thread exiting processId=%x, threadId=%x\n", GetCurrentProcessId(), GetCurrentThreadId());
	return 0;
}

BOOL
	MonitorStart()
{
	g_MonitorStopping = 0;
	g_MonitorThreadHandle = CreateThread(NULL, 256 * PAGE_SIZE, MonitorMainRoutine, NULL, 0, &g_MonitorThreadId);
	if (g_MonitorThreadHandle == NULL)
		return FALSE;

	return TRUE;
}

VOID
	MonitorStop()
{
	g_MonitorStopping = 1;
	if (g_MonitorThreadHandle != NULL) {
		WaitForSingleObject(g_MonitorThreadHandle, INFINITE);
		CloseHandle(g_MonitorThreadHandle);
		g_MonitorThreadHandle = NULL;
	}
}