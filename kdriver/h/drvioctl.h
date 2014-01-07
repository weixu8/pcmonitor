#ifndef __DRVIOCTL_H__
#define __DRVIOCTL_H__
#pragma once

#ifdef _WINDOWS
#include <WinIoCtl.h>
#endif

#define KMOM_NAME_W 				L"kmon"
#define KMON_DRIVER_NAME_W 			L"kmon.sys"
#define KMON_NT_DEVICE_NAME_W		L"\\Device\\kmon"
#define KMON_NT_DEVICE_NAME_A		"\\Device\\kmon"
#define KMON_DOS_DEVICE_NAME_W		L"\\DosDevices\\kmon"
#define KMON_DOS_DEVICE_NAME_A	 	"\\DosDevices\\kmon"
#define KMON_WIN32_DEVICE_NAME_W	L"\\\\.\\kmon"
#define KMON_WIN32_DEVICE_NAME_A	"\\\\.\\kmon"

enum {
	KMON_DRV_INIT = 0x801,
	KMON_DRV_RELEASE,
};

#define IOCTL_KMON_INIT CTL_CODE( \
	FILE_DEVICE_UNKNOWN, KMON_DRV_INIT, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_KMON_RELEASE CTL_CODE ( \
	FILE_DEVICE_UNKNOWN, KMON_DRV_RELEASE, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif
