#pragma once
#include "project.h"


HANDLE OpenDevice();
BOOL CloseDevice(IN HANDLE hDevice);

DWORD NTAPI ControlDevice(HANDLE hDevice, DWORD Ioctl, PVOID Input, DWORD InputSize, PVOID Output, DWORD OutputSize, DWORD *pBytesReturned);

HWINSTA	DeviceOpenWinsta(HANDLE hDevice, WCHAR *lpszWindowStation);
HDESK	DeviceOpenDesktop(HANDLE hDevice, HWINSTA hWinsta, WCHAR *lpszDesktopName);