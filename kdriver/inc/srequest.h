#pragma once
#include <inc/drvmain.h>
#include <inc/srequest_status.h>
#include <inc/srequest_type.h>

#include <inc/endian.h>

#pragma pack(push, 1)
#define SREQUEST_HEADER_SIGN 2134234237

typedef struct _SREQUEST_HEADER {
	int sign;
	int size;
} SREQUEST_HEADER, *PSREQUEST_HEADER;

typedef struct _SREQUEST {
	SREQUEST_HEADER header;
	__int64			txId;
	int				txNum;
	int				type;
	int				status;
	int				dataSize;
} SREQUEST, *PSREQUEST;

#pragma pack(pop)

BOOLEAN
SRequestHeaderValid(PSREQUEST_HEADER header);

VOID
SRequestHeaderHtoN(PSREQUEST_HEADER header);

VOID SRequestHtoN(PSREQUEST request);

VOID
SRequestHeaderNtoH(PSREQUEST_HEADER header);

VOID SRequestNtoH(PSREQUEST request);

PSREQUEST
SRequestAlloc(int status, int type, int dataSize);

PVOID SRequestGetDataPtr(PSREQUEST Request);

PSREQUEST
SRequestCreate(int status, int type, int dataSize, void *data);

PSREQUEST
SRequestRawAlloc(int requestSize);

VOID
SRequestFree(PSREQUEST request);

ULONG
SRequestMemSize(PSREQUEST_HEADER header);

BOOLEAN
SRequestValid(PSREQUEST request);

PSREQUEST
SRequestClone(PSREQUEST request);

#define MAX_SREQUEST_SIZE 10*PAGE_SIZE
