#include "device.h"
#include "..\kdriver\h\drvioctl.h"
#include "debug.h"
#include <stdio.h>

HANDLE OpenDevice()
{

	HANDLE hDevice =           // Получаем доступ к драйверу
		CreateFile(KMON_WIN32_DEVICE_NAME_W,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		DebugPrint("ERROR: can not access driver %ws, error %d\n", KMON_WIN32_DEVICE_NAME_W, GetLastError());
		return NULL;
	}

	DebugPrint("OpenDevice=%p", hDevice);

	return hDevice;
}

BOOL
	CloseDevice(IN HANDLE hDevice)
{
	return CloseHandle(hDevice);
}

DWORD NTAPI ControlDevice(HANDLE hDevice, DWORD Ioctl, PVOID Input, DWORD InputSize, PVOID Output, DWORD OutputSize, DWORD *pBytesReturned)
{
	DWORD Error = ERROR_SUCCESS;

	if (!DeviceIoControl(hDevice,
		Ioctl,
		Input, InputSize,	// Input
		Output, OutputSize,	// Output
		pBytesReturned,
		NULL)) {
		Error = GetLastError();
	}

	DebugPrint("ControlDevice:ioctl=%d err=%d\n", Ioctl, Error);

	return Error;
}


HWINSTA	DeviceOpenWinsta(HANDLE hDevice, WCHAR *lpszWindowStation)
{
	OPEN_WINSTA Request, Result;
	DWORD ResultBytes;
	DWORD Error;

	_snwprintf_s((WCHAR *)&Request.WinstaName, sizeof(Request.WinstaName), _TRUNCATE, L"%ws", lpszWindowStation);

	Error = ControlDevice(hDevice, IOCTL_KMON_OPEN_WINSTA, &Request, sizeof(Request), &Result, sizeof(Result), &ResultBytes);
	if (Error != ERROR_SUCCESS) {
		DebugPrint("ControlDevice error=%d\n", Error);
		return NULL;
	}

	if (sizeof(Result) != ResultBytes) {
		DebugPrint("mismatch result size\n");
		return NULL;
	}
	
	if (Result.Error != ERROR_SUCCESS) {
		DebugPrint("Result.error=%d\n", Result.Error);
		return NULL;
	}

	return (HWINSTA)Result.hWinsta;
}

HDESK	DeviceOpenDesktop(HANDLE hDevice, HWINSTA hWinsta, WCHAR *lpszDesktopName)
{
	OPEN_DESKTOP Request, Result;
	DWORD ResultBytes;
	DWORD Error;

	_snwprintf_s((WCHAR *)&Request.DesktopName, sizeof(Request.DesktopName), _TRUNCATE, L"%ws", lpszDesktopName);
	Request.hWinsta = hWinsta;

	Error = ControlDevice(hDevice, IOCTL_KMON_OPEN_DESKTOP, &Request, sizeof(Request), &Result, sizeof(Result), &ResultBytes);
	if (Error != ERROR_SUCCESS) {
		DebugPrint("ControlDevice error=%d\n", Error);
		return NULL;
	}

	if (sizeof(Result) != ResultBytes) {
		DebugPrint("mismatch result size\n");
		return NULL;
	}

	if (Result.Error != ERROR_SUCCESS) {
		DebugPrint("Result.error=%d\n", Result.Error);
		return NULL;
	}

	return (HDESK)Result.hDesktop;
}
