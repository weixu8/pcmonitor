#pragma once
#include <inc/drvmain.h>
#include <inc/endian.h>

#pragma pack(push, 1)

#define SREQUEST_HEADER_SIGN 2134234237

typedef struct _SREQUEST_HEADER {
	int sign;
	int size;
} SREQUEST_HEADER, *PSREQUEST_HEADER;

#pragma pack(pop)

BOOLEAN
SRequestHeaderValid(PSREQUEST_HEADER header);

VOID
SRequestHeaderInit(PSREQUEST_HEADER header, int size);

VOID
SRequestHeaderInitAndHtoN(PSREQUEST_HEADER header, int size);

VOID
SRequestHeaderHtoN(PSREQUEST_HEADER header);

VOID
SRequestHeaderNtoH(PSREQUEST_HEADER header);

#define MAX_SREQUEST_BODY_SIZE 10*PAGE_SIZE
