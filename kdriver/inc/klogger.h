#pragma once

#include <inc/drvmain.h>

#define KLOG_MSG_SZ			256
#define KLOG_BUFFERS_COUNT	256

typedef struct _KLOG_BUFFER {
    LIST_ENTRY	ListEntry;
    CHAR		Msg[KLOG_MSG_SZ];
    ULONG		Length;
} KLOG_BUFFER, *PKLOG_BUFFER;


typedef struct _KLOG_CONTEXT {
    BOOLEAN		ThreadStop;
    HANDLE		ThreadHandle;
    PVOID		Thread;
    HANDLE		FileHandle;
    KLOG_BUFFER	Buffer[KLOG_BUFFERS_COUNT];
    LIST_ENTRY	FlushQueue;
    LIST_ENTRY	FreeList;
    KSPIN_LOCK	Lock;
    KEVENT		FlushEvent;
    KDPC		Dpc;
} KLOG_CONTEXT, *PKLOG_CONTEXT;

PKLOG_CONTEXT KLogCreate(PUNICODE_STRING FileName);
VOID KLogRelease(PKLOG_CONTEXT Log);

typedef enum {
    LInfo_,
    LError_,
    LDebug_,
};

#define DL(x)   x, __SUBCOMPONENT__, __FILE__,__LINE__,__FUNCTION__

#define LInfo   DL(LInfo_)
#define LError  DL(LError_)
#define LDebug  DL(LDebug_)

VOID KLog(int level, PCHAR component, PCHAR file, ULONG line, PCHAR func, const char *fmt, ...);

#if 1
    #define KLOG(...)
#else
    #define KLOG(...)  KLog(__VA_ARGS__);
#endif

extern PKLOG_CONTEXT g_Log;

NTSTATUS KLoggingInit();
VOID KLoggingRelease();

void GetLocalTimeFields(PTIME_FIELDS pTimeFields);
