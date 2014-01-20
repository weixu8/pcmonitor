#pragma once
#include <inc/drvmain.h>
#include <inc/json.h>

typedef struct _SREQUEST {
	JSON_MAP map;
	int type;
	int status;
	char *data;
	size_t dataSz;
} SREQUEST, *PSREQUEST;

PSREQUEST SRequestCreate(int type);
PSREQUEST SRequestParse(char *json);
char *SRequestDumps(PSREQUEST request); 
void SRequestDelete(PSREQUEST request);

#define SREQ_TYPE_BASE					0x900
#define SREQ_TYPE_ECHO					(SREQ_TYPE_BASE + 1)
#define SREQ_TYPE_UNDEFINED				(SREQ_TYPE_BASE + 2)

#define SREQ_SUCCESS					0x0
#define SREQ_ERROR						0xD0000000
#define SREQ_ERROR_JSON_DECODE_FAILED	(SREQ_ERROR+1)
#define SREQ_ERROR_NO_MEM				(SREQ_ERROR+2)
#define SREQ_ERROR_UNDEFINED			(SREQ_ERROR+3)