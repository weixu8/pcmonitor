#include <inc/klogger.h>

#include <stdio.h>
#include <stdarg.h>

#define MODULE_TAG 'klog'

PKLOG_CONTEXT g_Log = NULL;

VOID KLoggerThreadRoutine(PVOID Context);


#define LOG_DPRINT

PKLOG_BUFFER KLogAllocBuffer(PKLOG_CONTEXT Log)
{
	return (PKLOG_BUFFER)HAllocatorAlloc(&Log->LogBufAllocator);
}

VOID KLogFreeBuffer(PKLOG_CONTEXT Log, PKLOG_BUFFER KLogBuffer)
{
	HAllocatorFree(&Log->LogBufAllocator, KLogBuffer);
}

VOID KLogDpc(KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    PKLOG_CONTEXT Log = (PKLOG_CONTEXT)DeferredContext;
    LOG_DPRINT("In dpc\n");
    KeSetEvent(&Log->FlushEvent, 0, FALSE);
}

VOID KLogBuffersInit(PKLOG_CONTEXT Log)
{
    ULONG Index;
    KIRQL Irql;

    InitializeListHead(&Log->FreeList);
    InitializeListHead(&Log->FlushQueue);
    KeInitializeSpinLock(&Log->Lock);

    KeInitializeEvent(&Log->FlushEvent, SynchronizationEvent, FALSE);
    KeInitializeDpc(&Log->Dpc, KLogDpc, Log);

	HAllocatorInit(&Log->LogBufAllocator, sizeof(KLOG_BUFFER), 200, 40*PAGE_SIZE, MODULE_TAG);
}

VOID KLogThreadStop(PKLOG_CONTEXT Log)
{
    KeSetEvent(&Log->FlushEvent, 0, FALSE);

    if (Log->ThreadHandle != NULL) {
        ZwWaitForSingleObject(Log->ThreadHandle, FALSE, NULL);
        ZwClose(Log->ThreadHandle);
        Log->ThreadHandle = NULL;
    }

    if (Log->Thread != NULL) {
        KeWaitForSingleObject(Log->Thread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(Log->Thread);
        Log->Thread = NULL;
    }
}

NTSTATUS KLogThreadStart(PKLOG_CONTEXT Log)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(
        &ObjectAttributes, NULL,
        OBJ_KERNEL_HANDLE,
        NULL,NULL
        );

    Status = PsCreateSystemThread(	&Log->ThreadHandle,
                                    THREAD_ALL_ACCESS,
                                    &ObjectAttributes,
                                    0L,
                                    NULL,
                                    KLoggerThreadRoutine,
                                    Log
                                    );

    if (!NT_SUCCESS(Status)) {
        LOG_DPRINT("PsCreateSystemThread failed with err %x\n", Status);
        return Status;
    }

    Status = ObReferenceObjectByHandle(	Log->ThreadHandle,
                                        THREAD_ALL_ACCESS,
                                        *PsThreadType,
                                        KernelMode,
                                        &Log->Thread,
                                        NULL
                                        );
    if (!NT_SUCCESS(Status)) {
        LOG_DPRINT("ObReferenceObjectByHandle failed with err %x\n", Status);
        KLogThreadStop(Log);
        return Status;
    }

    ZwClose(Log->ThreadHandle);
    Log->ThreadHandle = NULL;

    return STATUS_SUCCESS;
}


NTSTATUS KLogFileOpen(PKLOG_CONTEXT Log, PUNICODE_STRING FileName)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;

    InitializeObjectAttributes(
        &ObjectAttributes, FileName,
        OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
        NULL,NULL
        );

    Status = ZwCreateFile(&Log->FileHandle, FILE_APPEND_DATA|SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(Status)) {
        LOG_DPRINT("ZwCreateFile failed with err %x\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS KLogFileWrite(PKLOG_CONTEXT Log, PVOID Buffer, ULONG Length)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;


    Status =ZwWriteFile(Log->FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, Length, NULL, NULL);
    if (!NT_SUCCESS(Status)) {
        LOG_DPRINT("ZwWriteFile failed with err %x\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

VOID KLogFileClose(PKLOG_CONTEXT Log)
{
    if (Log->FileHandle != NULL)
        ZwClose(Log->FileHandle);
    Log->FileHandle = NULL;
}

VOID KLogRelease(PKLOG_CONTEXT Log)
{
	Log->Stopping = TRUE;
	KeFlushQueuedDpcs();
    KLogThreadStop(Log);
	HAllocatorRelease(&Log->LogBufAllocator);
    KLogFileClose(Log);
    ExFreePool(Log);
}

PKLOG_CONTEXT KLogCreate(PUNICODE_STRING FileName)
{
    NTSTATUS Status;
    PKLOG_CONTEXT Log = NULL;

    Log = (PKLOG_CONTEXT)ExAllocatePool(NonPagedPool, sizeof(KLOG_CONTEXT));
    if (Log == NULL) {
        LOG_DPRINT("ExAllocatePool failure\n");
        return NULL;
    }
    RtlZeroMemory(Log, sizeof(KLOG_CONTEXT));
    KLogBuffersInit(Log);

    Status = KLogFileOpen(Log, FileName);
    if (!NT_SUCCESS(Status)) {
        LOG_DPRINT("KLogFileOpen failed with err %x\n", Status);
        ExFreePool(Log);
        return NULL;
    }

    Status = KLogThreadStart(Log);
    if (!NT_SUCCESS(Status)) {
        LOG_DPRINT("KLogThreadStart failed %x\n", Status);
        KLogFileClose(Log);
        ExFreePool(Log);
        return NULL;
    }

    return Log;
}



void GetLocalTimeFields(PTIME_FIELDS pTimeFields)
{
    LARGE_INTEGER time;
    KeQuerySystemTime (&time);
    ExSystemTimeToLocalTime(&time, &time);
    RtlTimeToTimeFields (&time, pTimeFields);
}

int WriteMsg2(PCHAR *pBuff, int *pLeft, const char *fmt, va_list argptr)
{
    int res;
    if (*pLeft < 0)
        return -1;

    res = _vsnprintf(*pBuff,*pLeft,fmt,argptr);
    if (res>=0) {
        *pBuff+=res;
        *pLeft-=res;
        return 0;
    } else {
        return -2;
    }
}

VOID _cdecl WriteMsg(PCHAR *pBuff, int *pLeft, const char *fmt, ...)
{
    va_list args;
    va_start(args,fmt);
    WriteMsg2(pBuff,pLeft,fmt,args);
    va_end(args);
}

static PCHAR TruncatePath(PCHAR filename)
{
    PCHAR temp,curr=filename;
    while(temp = strchr(curr,'\\'))
        curr = ++temp;
    return curr;
}


VOID KLogCtx2(PKLOG_CONTEXT Log, int level, PCHAR component, PCHAR file, ULONG line, PCHAR func, const char *fmt, va_list args)
{
    PKLOG_BUFFER Buffer;
    KIRQL Irql;
    int nsize;
    PCHAR pos;
    int left;
    int res = 0;
    TIME_FIELDS TimeFields;
	
	if (Log->Stopping)
		return;

    Buffer = KLogAllocBuffer(Log);
    if (Buffer == NULL) {
        __debugbreak();
        return;
    }

    pos = (PCHAR)Buffer->Msg;
    left = KLOG_MSG_SZ;

    if (level == LInfo_) {
        WriteMsg(&pos,&left, "Info ");
    } else if (level == LError_) {
        WriteMsg(&pos,&left, "Error ");
    } else if (level == LDebug_) {
        WriteMsg(&pos,&left, "Debug ");
    } else {
        WriteMsg(&pos,&left, "Unk ");
    }

    WriteMsg(&pos, &left, " %s ", component);
    
    GetLocalTimeFields (&TimeFields);
    WriteMsg(&pos,&left,"%02d:%02d:%02d.%03d ",
        TimeFields.Hour, TimeFields.Minute,
        TimeFields.Second, TimeFields.Milliseconds);

    WriteMsg(&pos,&left,"t%x",PsGetCurrentThreadId());
	WriteMsg(&pos, &left, " i%x", KeGetCurrentIrql());
    WriteMsg(&pos,&left," %s():%s:%d: ",func,TruncatePath(file),line);

    res = WriteMsg2(&pos,&left, fmt, args);
    if (res == -2) {
        WriteMsg(&pos, &left, "LOG INVALID FMT OR OVERFLOW:%s\n", fmt);
    } else {
        WriteMsg(&pos,&left, "\n");
    }

    if (left <= 0) {
        Buffer->Length = KLOG_MSG_SZ;
        Buffer->Msg[KLOG_MSG_SZ - 1] = '\n';// Avoiding Buffer Overruns
    } else
        Buffer->Length = KLOG_MSG_SZ - left;

    DbgPrint(Buffer->Msg);

    KeAcquireSpinLock(&Log->Lock, &Irql);
    InsertTailList(&Log->FlushQueue, &Buffer->ListEntry);
    KeReleaseSpinLock(&Log->Lock, Irql);

    LOG_DPRINT("insert buff %p data %p len %x\n", Buffer, Buffer->Msg, Buffer->Length);

    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        LOG_DPRINT("insert dpc\n");
        KeInsertQueueDpc(&Log->Dpc, NULL, NULL);
    } else {
        LOG_DPRINT("signal event\n");
        KeSetEvent(&Log->FlushEvent, 0, FALSE);
    }
}


VOID KLogCtx(PKLOG_CONTEXT Log, int level, PCHAR component, PCHAR file, ULONG line, PCHAR func, const char *fmt, ...)
{
    va_list args;

    va_start(args,fmt);
    KLogCtx2(Log, level, component, file, line, func, fmt, args);
    va_end(args);
}

VOID KLoggerThreadRoutine(PVOID Context)
{
    PKLOG_CONTEXT Log = (PKLOG_CONTEXT)Context;
    KIRQL Irql;
    LIST_ENTRY FlushQueue;
    PKLOG_BUFFER KLogBuffer;
    PLIST_ENTRY ListEntry;
	LARGE_INTEGER Timeout;

    LOG_DPRINT("Log thread started %p\n", PsGetCurrentThread());

	Timeout.QuadPart = -20 * 1000 * 10;//20ms

	while (!Log->Stopping) {
		KeWaitForSingleObject(&Log->FlushEvent, Executive, KernelMode, FALSE, &Timeout);
        LOG_DPRINT("Log thread %p started processing log\n", PsGetCurrentThread());

        InitializeListHead(&FlushQueue);

        KeAcquireSpinLock(&Log->Lock, &Irql);
        while (!IsListEmpty(&Log->FlushQueue)) {
            ListEntry = RemoveHeadList(&Log->FlushQueue);
            InsertTailList(&FlushQueue, ListEntry);
        }
        KeReleaseSpinLock(&Log->Lock, Irql);

        while (!IsListEmpty(&FlushQueue)) {
            ListEntry = RemoveHeadList(&FlushQueue);
            KLogBuffer = CONTAINING_RECORD(ListEntry, KLOG_BUFFER, ListEntry);
            LOG_DPRINT("write buff %p data %p len %x\n", KLogBuffer, KLogBuffer->Msg, KLogBuffer->Length);
            KLogFileWrite(Log, KLogBuffer->Msg, KLogBuffer->Length);
            KLogFreeBuffer(Log, KLogBuffer);
        }
    }

    LOG_DPRINT("Log thread stopped %p\n", PsGetCurrentThread());
}


NTSTATUS KLoggingInit()
{
    UNICODE_STRING LogFileName = RTL_CONSTANT_STRING(L"\\??\\C:\\klog.txt");
    
    LOG_DPRINT("KLoggingInit\n");
    
    if (g_Log != NULL)
        __debugbreak();

    g_Log = KLogCreate(&LogFileName);
    if (g_Log != NULL)
        return STATUS_SUCCESS;
    else
        return STATUS_UNSUCCESSFUL;
}

VOID KLoggingRelease()
{
    LOG_DPRINT("KLoggingRelease\n");
    if (g_Log != NULL) {
        KLogRelease(g_Log);
        g_Log = NULL;
    }
}

VOID KLog(int level, PCHAR component, PCHAR file, ULONG line, PCHAR func, const char *fmt, ...)
{
    va_list args;

    va_start(args,fmt);
    KLogCtx2(g_Log, level, component, file, line, func, fmt, args);
    va_end(args);    
}