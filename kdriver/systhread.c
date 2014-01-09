#include <inc/systhread.h>
#include <inc/klogger.h>
#define __SUBCOMPONENT__ "systhread"

VOID 
	SysThreadRoutine(PVOID Context)
{
    PSYSTHREAD ThreadCtx = (PSYSTHREAD)Context;
    NTSTATUS Status;
    
    KLog(LInfo, "Sys thread started %p", PsGetCurrentThread());

    while (TRUE) {
        Status = KeWaitForSingleObject(&ThreadCtx->Event, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(Status)) {
            KLog(LError, "KeWaitForSingleObject failed with err %x", Status);
        }

		ThreadCtx->Routine(ThreadCtx->Context);
        if (ThreadCtx->ThreadStop)
            break;
    }

    KLog(LInfo, "Sys thread stopped %p", PsGetCurrentThread());
}

VOID
	SysThreadSignal(PSYSTHREAD ThreadCtx)
{
	KeSetEvent(&ThreadCtx->Event, 2, FALSE);
}

VOID
	SysThreadStop(PSYSTHREAD ThreadCtx)
{
    ThreadCtx->ThreadStop = TRUE;
	SysThreadSignal(ThreadCtx);

    if (ThreadCtx->ThreadHandle != NULL) {
        ZwWaitForSingleObject(ThreadCtx->ThreadHandle, FALSE, NULL);
        ZwClose(ThreadCtx->ThreadHandle);
        ThreadCtx->ThreadHandle = NULL;
    }

    if (ThreadCtx->Thread != NULL) {
        KeWaitForSingleObject(ThreadCtx->Thread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(ThreadCtx->Thread);
        ThreadCtx->Thread = NULL;
    }
}

VOID
	SysThreadInit(PSYSTHREAD ThreadCtx)
{
	RtlZeroMemory(ThreadCtx, sizeof(SYSTHREAD));
	KeInitializeEvent(&ThreadCtx->Event, SynchronizationEvent, FALSE);
}

NTSTATUS
	SysThreadStart(PSYSTHREAD ThreadCtx, PSYSTHREAD_ROUTINE  Routine, PVOID Context)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(
        &ObjectAttributes, NULL,
        OBJ_KERNEL_HANDLE,
        NULL,NULL
        );

	ThreadCtx->Routine = Routine;
	ThreadCtx->Context = Context;

    Status = PsCreateSystemThread(	&ThreadCtx->ThreadHandle,
                                    THREAD_ALL_ACCESS,
                                    &ObjectAttributes,
                                    0L,
                                    NULL,
                                    SysThreadRoutine,
                                    ThreadCtx
                                    );

    if (!NT_SUCCESS(Status)) {
        KLog(LError, "PsCreateSystemThread failed with err %x", Status);
        return Status;
    }

    Status = ObReferenceObjectByHandle(	ThreadCtx->ThreadHandle,
                                        THREAD_ALL_ACCESS,
                                        *PsThreadType,
                                        KernelMode,
                                        &ThreadCtx->Thread,
                                        NULL
                                        );
    if (!NT_SUCCESS(Status)) {
        KLog(LError, "ObReferenceObjectByHandle failed with err %x", Status);
        SysThreadStop(ThreadCtx);
        return Status;
    }

    ZwClose(ThreadCtx->ThreadHandle);
    ThreadCtx->ThreadHandle = NULL;

    return STATUS_SUCCESS;
}