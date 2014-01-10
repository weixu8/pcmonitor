#pragma once

#include "project.h"


typedef struct _MONITOR {
	DWORD	MainThreadId;
	HANDLE	MainThreadHandle;
	DWORD	Stopping;
	HANDLE	hDevice;
} MONITOR, *PMONITOR;


BOOL
MonitorStart(PMONITOR Monitor);

VOID
MonitorStop(PMONITOR Monitor);

PMONITOR
	GetMonitor();
