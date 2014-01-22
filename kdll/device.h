#pragma once
#include "project.h"
#include "..\kdriver\h\drvioctl.h"

HWINSTA	DeviceOpenWinsta(WCHAR *lpszWindowStation);
HDESK	DeviceOpenDesktop(HWINSTA hWinsta, WCHAR *lpszDesktopName);

DWORD	DeviceScreenShot(char *data, unsigned long dataSz, unsigned long sessionId, int type);
