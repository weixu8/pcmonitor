#include "project.h"
#include "monitor.h"
#include "debug.h"
#include "screenshot.h"

#define PAGE_SIZE 4096

static DWORD g_MonitorThreadId = 0;
static volatile LONG g_MonitorStopping = 0;
static HANDLE g_MonitorThreadHandle = NULL;



typedef
BOOL
(WINAPI *PCLIENT_THREAD_SETUP)(VOID);

BOOL CALLBACK DesktopEnumProcedure(
	_In_  LPTSTR lpszDesktop,
	_In_  LPARAM lParam
	)
{
	DebugPrint("DesktopEnumProcedure:desktop=%ws\n", lpszDesktop);

	HDESK hDesk = OpenDesktop(lpszDesktop, 0, FALSE, GENERIC_READ);
	if (hDesk == NULL) {
		DebugPrint("Failed to open desktop=%ws, error=%d\n", lpszDesktop, GetLastError());
		return TRUE;
	}

	CloseDesktop(hDesk);
	return TRUE;
}

BOOL CALLBACK WinstaEnumProcedure(
	_In_  LPTSTR lpszWindowStation,
	_In_  LPARAM lParam
	)
{
	DebugPrint("EnumWindowStationProc:winstaname=%ws\n", lpszWindowStation);

	HWINSTA hWinsta = OpenWindowStation(lpszWindowStation, FALSE, GENERIC_READ);
	if (hWinsta == NULL) {
		DebugPrint("Failed to open winsta %ws, error=%d\n", lpszWindowStation, GetLastError());
		return TRUE;
	}
	EnumDesktops(hWinsta, DesktopEnumProcedure, NULL);

	CloseWindowStation(hWinsta);
	return TRUE;
}

VOID
PrepareThread()
{
	HMODULE hModule = LoadLibrary(L"user32.dll");
	if (hModule == NULL) {
		DebugPrint("LoadLibrary failed\n");
		return;
	}

	PCLIENT_THREAD_SETUP ClientThreadSetup = NULL;
	ClientThreadSetup = (PCLIENT_THREAD_SETUP)GetProcAddress(hModule, "ClientThreadSetup");
	if (ClientThreadSetup == NULL) {
		DebugPrint("ClientThreadSetup not found in mod=%p\n", hModule);
		goto cleanup;
	}

	BOOL Result = FALSE;
	Result = ClientThreadSetup();
	DebugPrint("ClientThreadSetup=%x\n", Result);


	EnumWindowStations(WinstaEnumProcedure, NULL);

cleanup:	
	FreeLibrary(hModule);
}

DWORD 
WINAPI
MonitorMainRoutine(
	_In_  LPVOID lpParameter
)
{
	DebugPrint("Monitor thread starting processId=%x, threadId=%x\n", GetCurrentProcessId(), GetCurrentThreadId());

	DebugPrint("IsGUIThread=%x\n", IsGUIThread(TRUE));
	PrepareThread();

	while (!g_MonitorStopping) {

		CaptureAnImage();
		Sleep(10000);
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