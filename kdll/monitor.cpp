#include "project.h"
#include "monitor.h"
#include "debug.h"
#include "screenshot.h"
#include "device.h"

#define PAGE_SIZE 4096

static MONITOR g_Monitor;

PMONITOR 
	GetMonitor()
{
	return &g_Monitor;
}

typedef
BOOL
(WINAPI *PCLIENT_THREAD_SETUP)(VOID);

VOID
	PrepareMainThread()
{
	PMONITOR Monitor = GetMonitor();
	HMODULE hModule = NULL;
	HWINSTA hWinsta = NULL;
	HDESK hDesk = NULL;
	PCLIENT_THREAD_SETUP ClientThreadSetup = NULL;

	hModule = LoadLibrary(L"user32.dll");
	if (hModule == NULL) {
		DebugPrint(L"LoadLibrary failed\n");
		return;
	}
	
	DebugPrint(L"IsGUIThread=%x\n", IsGUIThread(TRUE));

	ClientThreadSetup = (PCLIENT_THREAD_SETUP)GetProcAddress(hModule, "ClientThreadSetup");
	if (ClientThreadSetup == NULL) {
		DebugPrint(L"ClientThreadSetup not found in mod=%p\n", hModule);
		goto cleanup;
	}
	
	BOOL Result = ClientThreadSetup();
	DebugPrint(L"ClientThreadSetup=%x\n", Result);
	hWinsta = DeviceOpenWinsta(L"WinSta0");
	if (hWinsta != NULL) {
		hDesk = DeviceOpenDesktop(hWinsta, L"Default");
	}
	
	DebugPrint(L"Opened hwinsta=%p, hdesk=%p\n", hWinsta, hDesk);

	if (hWinsta != NULL) {
		if (!SetProcessWindowStation(hWinsta)) {
			DebugPrint(L"SetProcessWindowStation failed, err=%d, hWinsta=%x\n", GetLastError(), hWinsta);
		}
	}

	if (hDesk != NULL) {
		if (!SetThreadDesktop(hDesk)) {
			DebugPrint(L"SetThreadDesktop failed, error=%d\n", GetLastError());
		}
	}

	if (hDesk != NULL)
		CloseDesktop(hDesk);

	if (hWinsta != NULL)
		CloseWindowStation(hWinsta);
	
cleanup:	
	FreeLibrary(hModule);
}


VOID
	GetKbdLayout()
{
	WCHAR kbdLayout[MAX_PATH];
	memset(kbdLayout, 0, sizeof(kbdLayout));
	if (GetKeyboardLayoutName(kbdLayout))
		DebugPrint(L"kbdLayout=%ws\n", kbdLayout);
	else
		DebugPrint(L"GetKeyboardLayoutName failed with err=%d", GetLastError());
}




VOID
KbdTestGetKeyNameText()
{
	WCHAR text[20];
	HWND hForegroundWnd = NULL;
	DWORD threadId = 0;
	HKL hCurrKL = NULL;
	BYTE btKeyState[256];
	UINT scanCode = 21;
	GUITHREADINFO threadInfo;
	DWORD focusThread = NULL;
	hForegroundWnd = GetForegroundWindow();
	threadId = GetWindowThreadProcessId(hForegroundWnd, NULL);

	DebugPrint(L"hForegroundWnd=%x, threadId=%x\n", hForegroundWnd, threadId);
	memset(&threadInfo, 0, sizeof(threadInfo));
	threadInfo.cbSize = sizeof(threadInfo);

	if (!GetGUIThreadInfo(threadId, &threadInfo)) {
		DebugPrint(L"GetGUIThreadInfo failed with err=%x for threadId=%x", GetLastError(), threadId);
	}

	DebugPrint(L"thread.hwndFocus=%x\n", threadInfo.hwndFocus);
	focusThread = GetWindowThreadProcessId(threadInfo.hwndFocus, NULL);
	DebugPrint(L"focusThread=%x\n", focusThread);

	hCurrKL = GetKeyboardLayout(threadId);
	DebugPrint(L"Thread hKL=%x\n", hCurrKL);

	for (int i = 0; i < 10; i++) {
		hCurrKL = ActivateKeyboardLayout((HKL)HKL_NEXT, 0);
		DebugPrint(L"ActivateKeyboardLayout:prevHKL=%x\n", hCurrKL);
		hCurrKL = GetKeyboardLayout(0);
		DebugPrint(L"Curr thread hKL=%x\n", hCurrKL);

		//GetKeyboardState(btKeyState);
		memset(btKeyState, 0, sizeof(btKeyState));
		memset(text, 0, sizeof(text));
		ToUnicodeEx(MapVirtualKey(scanCode, MAPVK_VSC_TO_VK_EX), scanCode, btKeyState, text, RTL_NUMBER_OF(text), 0, hCurrKL);
		DebugPrint(L"ToUnicodeEx text is=%ws, unicode=%x\n", text, (USHORT)text[0]);
	}
}

VOID
	KbdTest()
{
	WCHAR klId[KL_NAMELENGTH];

	KbdTestGetKeyNameText();

	GetKeyboardLayoutName(klId);
	DebugPrint(L"klId is %ws\n", klId);

	UINT vkCode = MapVirtualKey(31, MAPVK_VSC_TO_VK_EX);
	DebugPrint(L"vkCode(31) is %d\n", vkCode);
	vkCode = MapVirtualKey(30, MAPVK_VSC_TO_VK_EX);
	DebugPrint(L"vkCode(30) is %d\n", vkCode);
	vkCode = MapVirtualKey(21, MAPVK_VSC_TO_VK_EX);
	DebugPrint(L"vkCode(21) is %d\n", vkCode);
}

DWORD 
WINAPI
	MonitorMainThreadRoutine(
	_In_  LPVOID lpParameter
)
{
	PMONITOR Monitor = (PMONITOR)lpParameter;

	DebugPrint(L"Monitor thread starting processId=%x, threadId=%x\n", GetCurrentProcessId(), GetCurrentThreadId());
	
	PrepareMainThread();

	while (!Monitor->Stopping) {
		if (GetDesktopWindow() != NULL)
			KbdTest();
		
		CaptureScreenCallback();
		Sleep(30000);
	}


	DebugPrint(L"Monitor thread exiting processId=%x, threadId=%x\n", GetCurrentProcessId(), GetCurrentThreadId());
	return 0;
}

BOOL
	MonitorStart(PMONITOR Monitor)
{
	memset(Monitor, 0, sizeof(MONITOR));
	Monitor->Stopping = 0;
	Monitor->MainThreadHandle = CreateThread(NULL, 256 * PAGE_SIZE, MonitorMainThreadRoutine, GetMonitor(), 0, &Monitor->MainThreadId);
	if (Monitor->MainThreadHandle == NULL) {
		return FALSE;
	}

	return TRUE;
}

VOID
	MonitorStop(PMONITOR Monitor)
{
	Monitor->Stopping = 1;
	if (Monitor->MainThreadHandle != NULL) {
		WaitForSingleObject(Monitor->MainThreadHandle, INFINITE);
		CloseHandle(Monitor->MainThreadHandle);
		Monitor->MainThreadHandle = NULL;
	}
	Monitor->MainThreadId = 0;
}