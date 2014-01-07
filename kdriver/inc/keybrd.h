#ifndef __MKEYBOARD_H__
#define __MKEYBOARD_H__

#include <inc/drvmain.h>

NTSTATUS 
    KbdDriverEntry(
        IN PDRIVER_OBJECT  DriverObject,
        IN PUNICODE_STRING RegistryPath 
    );
VOID
    KbdDriverUnload(
        IN PDRIVER_OBJECT  DriverObject
    );

NTSTATUS 
    KbdDispatchGeneral(
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
    KbdBuffEntryDelete(PKBD_BUFF_ENTRY Entry);
	
PKBD_BUFF_ENTRY
    KbdBuffGet(BOOLEAN bWait);

#endif
