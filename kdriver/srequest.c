#include <inc\srequest.h>
#include <inc\klogger.h>

#define __SUBCOMPONENT__ "srequest"
#define MODULE_TAG 'sreq'

VOID
SRequestHeaderHtoN(PSREQUEST_HEADER header)
{
	header->sign = htonl(header->sign);
	header->size = htonl(header->size);
}

VOID SRequestHtoN(PSREQUEST request)
{
	SRequestHeaderHtoN(&request->header);

	request->type = htonl(request->type);
	request->status = htonl(request->status);
	request->txId = htonll(request->txId);
	request->txNum = htonl(request->txNum);
	request->dataSize = htonl(request->dataSize);
}

VOID
SRequestHeaderNtoH(PSREQUEST_HEADER header)
{
	header->sign = ntohl(header->sign);
	header->size = ntohl(header->size);
}

VOID SRequestNtoH(PSREQUEST request)
{
	SRequestHeaderNtoH(&request->header);

	request->type = ntohl(request->type);
	request->status = ntohl(request->status);
	request->txId = ntohll(request->txId);
	request->txNum = ntohl(request->txNum);
	request->dataSize = ntohl(request->dataSize);
}

PSREQUEST
SRequestRawAlloc(int requestSize)
{
	PSREQUEST request = (PSREQUEST)ExAllocatePoolWithTag(NonPagedPool, requestSize, MODULE_TAG);
	if (request == NULL)
		return NULL;

	RtlZeroMemory(request, requestSize);
	return request;
}

PSREQUEST
SRequestAlloc(int status, int type, int dataSize)
{
	PSREQUEST request = NULL;
	ULONG requestSize = sizeof(SREQUEST)+dataSize;

	request = (PSREQUEST)ExAllocatePoolWithTag(NonPagedPool, requestSize, MODULE_TAG);
	if (request == NULL)
		return NULL;

	RtlZeroMemory(request, requestSize);
	
	request->header.sign = SREQUEST_HEADER_SIGN;
	request->header.size = requestSize - sizeof(SREQUEST_HEADER);
	request->dataSize = dataSize;
	request->status = status;
	request->type = type;

	return request;
}

PSREQUEST
SRequestCreate(int status, int type, int dataSize, void *data)
{
	PSREQUEST request = SRequestAlloc(status, type, dataSize);
	PVOID dataPtr = NULL;

	if (request == NULL)
		return NULL;

	dataPtr = SRequestGetDataPtr(request);
	if (dataPtr != NULL) {
		RtlCopyMemory(dataPtr, data, dataSize);
	}

	return request;
}

PVOID SRequestGetDataPtr(PSREQUEST request)
{
	if (!SRequestValid(request))
		return NULL;

	if (request->dataSize == 0)
		return NULL;

	return (PVOID)(request + 1);
}

BOOLEAN
	SRequestHeaderValid(PSREQUEST_HEADER header)
{
	if (header->sign != SREQUEST_HEADER_SIGN)
		return FALSE;

	if (header->size < 0)
		return FALSE;

	if (header->size < sizeof(SREQUEST)-sizeof(SREQUEST_HEADER))
		return FALSE;

	if (header->size + sizeof(SREQUEST_HEADER) > MAX_SREQUEST_SIZE)
		return FALSE;

	return TRUE;
}

BOOLEAN
	SRequestValid(PSREQUEST request)
{
	if (!SRequestHeaderValid(&request->header))
		return FALSE;

	if (request->dataSize < 0)
		return FALSE;
	
	if ((request->dataSize + sizeof(SREQUEST)) > (request->header.size + sizeof(SREQUEST_HEADER)))
		return FALSE;

	return TRUE;
}

ULONG
	SRequestMemSize(PSREQUEST_HEADER header)
{
	return header->size + sizeof(SREQUEST_HEADER);
}

PSREQUEST
	SRequestClone(PSREQUEST request)
{
	PSREQUEST clone = NULL;
	ULONG reqSize = 0;

	if (!SRequestValid(request))
		return NULL;

	reqSize = SRequestMemSize(&request->header);
	clone = SRequestRawAlloc(reqSize);
	if (clone == NULL)
		return NULL;

	RtlCopyMemory(clone, request, reqSize);
	return clone;
}

VOID
SRequestFree(PSREQUEST request)
{
	if (SRequestValid(request)) {
		ULONG memSize = SRequestMemSize(&request->header);
		RtlZeroMemory(request, memSize);
	}

	ExFreePoolWithTag(request, MODULE_TAG);
}