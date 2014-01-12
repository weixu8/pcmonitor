#pragma once

#include <inc/drvmain.h>

#define KBD_BUF_SZ      100
#define KBD_BUF_COUNT   100

#define KBD_BUFF_BYTES_COUNT 1024

typedef struct _KBD_KEY {
	USHORT      MakeCode;
	USHORT      Flags;
	PSTRING     Str;
	TIME_FIELDS TimeFields;
} KBD_KEY, *PKBD_KEY;


typedef struct _KBD_BUF {
	LIST_ENTRY	ListEntry;
	KBD_KEY		Keys[KBD_BUF_SZ];
	ULONG		Length;
} KBD_BUF, *PKBD_BUF;

typedef struct _KBD_CONTEXT {
	KSPIN_LOCK      Lock;
	LIST_ENTRY      FreeList;
	LIST_ENTRY      FlushQueue;
	LIST_ENTRY      BuffEntryList;
	PCHAR           FmtPage;
	KGUARDED_MUTEX  BuffEntryLock;
	KEVENT          BuffEntryEvent;
	KEVENT          FlushEvent;
	KBD_BUF         Buffs[KBD_BUF_COUNT];
	PVOID           Thread;
	HANDLE          ThreadHandle;
	BOOLEAN         ThreadStop;
	KEVENT          ShutdownEvent;
	volatile LONG   RefCount;
	volatile LONG   Shutdown;
	PDEVICE_OBJECT  KbdDeviceObject;
	PDEVICE_OBJECT  HookDeviceObject;
	PDRIVER_OBJECT  DriverObject;
} KBD_CONTEXT, *PKBD_CONTEXT;


VOID
KbdInit(PKBD_CONTEXT Kbd);

NTSTATUS
KbdStart(PKBD_CONTEXT Kbd);

VOID
KbdStop(PKBD_CONTEXT Kbd);


NTSTATUS 
    KbdDispatchGeneral(
		IN PKBD_CONTEXT Kbd,
        IN PDEVICE_OBJECT   DeviceObject,
        IN PIRP             Irp,
        IN BOOLEAN          *pbHandled
        );

typedef struct _KBD_BUFF_ENTRY {
    LIST_ENTRY  ListEntry;
    ULONG       BytesCount;
    ULONG       BytesUsed;
    PVOID       Bytes;
} KBD_BUFF_ENTRY, *PKBD_BUFF_ENTRY;

VOID
KbdBuffDelete(PKBD_BUFF_ENTRY Entry);