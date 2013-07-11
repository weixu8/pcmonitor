#ifndef __DRVIOCTL_H__
#define __DRVIOCTL_H__
#pragma once

#ifdef _WINDOWS
#include <WinIoCtl.h>
#endif

#define EYE_NAME_W L"eye"
#define EYE_DRIVER_NAME_W L"eye.sys"
#define NT_EYE_DEVICE_NAME_W		L"\\Device\\eye"
#define NT_EYE_DEVICE_NAME_A		 "\\Device\\eye"
#define DOS_EYE_DEVICE_NAME_W	L"\\DosDevices\\eye"
#define DOS_EYE_DEVICE_NAME_A	 "\\DosDevices\\eye"
#define WIN32_EYE_DEVICE_NAME_W	L"\\\\.\\eye"
#define WIN32_EYE_DEVICE_NAME_A	 "\\\\.\\eye"

enum {
	DRV_INIT = 0x801,
	DRV_RELEASE,
	DRV_QUERY_PROCLIST_COUNT,
	DRV_QUERY_PROCLIST
};

#define IOCTL_EYE_INIT CTL_CODE( \
	FILE_DEVICE_UNKNOWN, DRV_INIT, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_EYE_RELEASE CTL_CODE ( \
	FILE_DEVICE_UNKNOWN, DRV_RELEASE, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_EYE_QUERY_PROCLIST_COUNT CTL_CODE ( \
	FILE_DEVICE_UNKNOWN, DRV_QUERY_PROCLIST_COUNT, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_EYE_QUERY_PROCLIST CTL_CODE ( \
	FILE_DEVICE_UNKNOWN, DRV_QUERY_PROCLIST, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EYE_PROC_ENTRY {
	void * ParentId;
	void * ProcessId;
	bool   bCreate;
} EYE_PROC_ENTRY, *PEYE_PROC_ENTRY;

typedef struct _QUERY_PROC_LIST_COUNT {
	unsigned long Count;
} QUERY_PROC_LIST_COUNT, *PQUERY_PROC_LIST_COUNT;

typedef struct _QUERY_PROC_LIST {
	unsigned long Count;
	unsigned long ResultCount;
	EYE_PROC_ENTRY Array[1];
} QUERY_PROC_LIST, *PQUERY_PROC_LIST;


typedef struct _EYE_PROC_INIT_INFO {
	void * hProcListFlushEvent;
} EYE_PROC_INIT_INFO, *PEYE_PROC_INIT_INFO;


#endif
