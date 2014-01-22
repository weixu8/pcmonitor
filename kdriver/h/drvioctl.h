#pragma once

#ifdef _WINDOWS
#include <WinIoCtl.h>
#endif

#define KMOM_NAME_W 				L"kdriver"
#define KMON_DRIVER_NAME_W 			L"kdriver.sys"
#define KMON_NT_DEVICE_NAME_W		L"\\Device\\kdriver"
#define KMON_NT_DEVICE_NAME_A		"\\Device\\kdriver"
#define KMON_DOS_DEVICE_NAME_W		L"\\DosDevices\\kdriver"
#define KMON_DOS_DEVICE_NAME_A	 	"\\DosDevices\\kdriver"
#define KMON_WIN32_DEVICE_NAME_W	L"\\\\.\\kdriver"
#define KMON_WIN32_DEVICE_NAME_A	"\\\\.\\kdriver"

enum {
	KMON_DRV_INIT = 0x801,
	KMON_DRV_RELEASE,
	KMON_DRV_OPEN_WINSTA,
	KMON_DRV_OPEN_DESKTOP,
	KMON_DRV_SCREENSHOT
};

#define KMON_MAX_CHARS 0x100

#define KMON_SCREENSHOT_SCREENSHOT_TYPE 1
#define KMON_SCREENSHOT_USERWINDOW_TYPE 2

typedef struct _KMON_SCREENSHOT {
	unsigned long	sessionId;
	void			*data;
	unsigned long	dataSz;
	int				type;
	void			*Process;
	unsigned long	Error;
} KMON_SCREENSHOT, *PKMON_SCREENSHOT;

typedef struct _KMON_INIT {
	char		clientId[KMON_MAX_CHARS];
	char		authId[KMON_MAX_CHARS];
} KMON_INIT, *PKMON_INIT;

typedef struct _KMON_RELEASE {
	char		clientId[KMON_MAX_CHARS];
	char		authId[KMON_MAX_CHARS];
} KMON_RELEASE, *PKMON_RELEASE;

typedef struct _OPEN_WINSTA {
	unsigned short	WinstaName[KMON_MAX_CHARS];
	void			*hWinsta;
	void			*Process;
	unsigned long	Error;
} OPEN_WINSTA, *POPEN_WINSTA;

typedef struct _OPEN_DESKTOP {
	unsigned short	DesktopName[KMON_MAX_CHARS];
	void			*hWinsta;
	void			*hDesktop;
	void			*Process;
	unsigned long	Error;
} OPEN_DESKTOP, *POPEN_DESKTOP;

#define IOCTL_KMON_INIT CTL_CODE( \
	FILE_DEVICE_UNKNOWN, KMON_DRV_INIT, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_KMON_RELEASE CTL_CODE ( \
	FILE_DEVICE_UNKNOWN, KMON_DRV_RELEASE, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_KMON_OPEN_WINSTA	CTL_CODE ( \
	FILE_DEVICE_UNKNOWN, KMON_DRV_OPEN_WINSTA, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define IOCTL_KMON_OPEN_DESKTOP	CTL_CODE ( \
	FILE_DEVICE_UNKNOWN, KMON_DRV_OPEN_DESKTOP, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define IOCTL_KMON_SCREENSHOT	CTL_CODE ( \
	FILE_DEVICE_UNKNOWN, KMON_DRV_SCREENSHOT, METHOD_BUFFERED, FILE_ANY_ACCESS)
