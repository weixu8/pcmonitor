#pragma once
#include "project.h"


HWINSTA	DeviceOpenWinsta(WCHAR *lpszWindowStation);
HDESK	DeviceOpenDesktop(HWINSTA hWinsta, WCHAR *lpszDesktopName);