#include <inc/srequest.h>
#include <polarssl2/polarssl/base64.h>

#define MODULE_TAG 'sreq'

int SRequestInit(PSREQUEST request)
{
	if (JsonMapInit(&request->map))
		return -1;

	request->data = NULL;
	request->dataSz = 0;
	request->type = SREQ_TYPE_UNDEFINED;
	request->status = SREQ_ERROR_UNDEFINED;

	return 0;
}

int SRequestSetType(PSREQUEST request, int type)
{
	return JsonMapSetLong(&request->map, "type", type);
}


int SRequestSetStatus(PSREQUEST request, int type)
{
	return JsonMapSetLong(&request->map, "type", type);
}


int SRequestSetData(PSREQUEST request, char *data, size_t dataSize)
{
	char *encoded = NULL;
	size_t encodedSz = -1;
	int res = -1;

	if (base64_encode(encoded, &encodedSz, data, dataSize)) {
		encoded = ExAllocatePoolWithTag(NonPagedPool, encodedSz+1, MODULE_TAG);
		if (encoded == NULL)
			return -1;

		if (base64_encode(encoded, &encodedSz, data, dataSize))
			return -1;
		encoded[encodedSz] = '\0';
	}

	if (!JsonMapSetString(&request->map, "data", encoded)) {
		res = -1;
		goto failed;
	}

failed:
	if (encoded != NULL)
		ExFreePoolWithTag(encoded, MODULE_TAG);

	return res;
}

PSREQUEST SRequestCreate(int type)
{
	PSREQUEST request = NULL;
	request = ExAllocatePoolWithTag(NonPagedPool, sizeof(SREQUEST), MODULE_TAG);
	if (request == NULL)
		return NULL;
	
	SRequestInit(request);
	request->type = type;

	return request;
}


void SRequestRelease(PSREQUEST request)
{
	JsonMapRelease(&request->map);
	if (request->data != NULL) {
		ExFreePoolWithTag(request->data, MODULE_TAG);
		request->data = NULL;
	}

	request->data = NULL;
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
	if (!SRequestSetType(request, request->type))
		return NULL;

	if (!SRequestSetStatus(request, request->status))
		return NULL;

	if (!SRequestSetData(request, request->data, request->dataSz))
		return NULL;

	return JsonMapDumps(&request->map);
}

LONG SRequestGetStatus(PSREQUEST request)
{
	LONG status;

	if (!JsonMapGetLong(&request->map, "status", &status)) {
		status = SREQ_ERROR_JSON_DECODE_FAILED;
	}

	return status;
}

LONG SRequestGetType(PSREQUEST request)
{
	LONG type = SREQ_TYPE_UNDEFINED;

	if (JsonMapGetLong(&request->map, "type", &type)) {
		type = SREQ_TYPE_UNDEFINED;
	}

	return type;
}


char *SRequestGetData(PSREQUEST request, size_t *dataSize)
{
	char *data = NULL;
	size_t dataLen = strlen(data) + 1;
	char *decoded = NULL;
	size_t decodedLen = 0;
	BOOLEAN bDecoded = FALSE;

	*dataSize = 0;
	data = JsonMapGetString(&request->map, "data");
	if (data == NULL) {
		return NULL;
	}

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

	return request;
}