
#pragma warning(push)
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // bit field types other than int

#include <inc/mwsk.h>
#include <inc/klogger.h>

#pragma warning(pop)

#define __SUBCOMPONENT__ "wsk"

#define MSOCKET_TAG 'mwss'
#define MWSK_CONTEXT_TAG 'mwsk'
#define MODULE_TAG 'mwst'

// Client-level callback table
const WSK_CLIENT_DISPATCH MWskClientDispatch = {
    MAKE_WSK_VERSION(1, 0), // This sample uses WSK version 1.0
    0, // Reserved
    NULL // WskClientEvent callback is not required in WSK version 1.0
};

NTSTATUS
    MWskRegister(PMWSK_CONTEXT WskContext)
{
    WSK_CLIENT_NPI wskClientNpi;
    NTSTATUS Status;
    
    wskClientNpi.ClientContext = NULL;
    wskClientNpi.Dispatch = &MWskClientDispatch;
    Status = WskRegister(&wskClientNpi, &WskContext->Registration);
    return Status;
}

NTSTATUS
    MWskCaptureProviderNPI(PMWSK_CONTEXT WskContext)
{
    return WskCaptureProviderNPI(&WskContext->Registration, WSK_INFINITE_WAIT, &WskContext->ProviderNpi); 
}

VOID 
    MWskReleaseProviderNPI(PMWSK_CONTEXT WskContext)
{
    WskReleaseProviderNPI(&WskContext->Registration);
}

VOID
    MWskDeregister(PMWSK_CONTEXT WskContext)
{
    WskDeregister(&WskContext->Registration);
}

PMWSK_CONTEXT
    MWskCreate()
{
    PMWSK_CONTEXT WskContext = NULL;
    NTSTATUS Status;

    WskContext = (PMWSK_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(MWSK_CONTEXT), MWSK_CONTEXT_TAG);
    if (WskContext == NULL) {
        __debugbreak();
        return NULL;
    }

    RtlZeroMemory(WskContext, sizeof(MWSK_CONTEXT));

    InitializeListHead(&WskContext->SocketsList);
    KeInitializeSpinLock(&WskContext->Lock);
    Status = MWskRegister(WskContext);
    if (!NT_SUCCESS(Status)) {
        KLog(LError, "wsk register status %x", Status);
        ExFreePoolWithTag(WskContext, MWSK_CONTEXT_TAG);
        return NULL;
    }
    
    Status = MWskCaptureProviderNPI(WskContext);
    if (!NT_SUCCESS(Status)) {
        KLog(LError, "capture provider npi status %x", Status);
        MWskDeregister(WskContext);
        ExFreePoolWithTag(WskContext, MWSK_CONTEXT_TAG);
        return NULL;
    }
    KLOG(LInfo, "wsk context created %p", WskContext);
    return WskContext;
}

VOID
    MWskRelease(PMWSK_CONTEXT WskContext)
{
    KIRQL Irql;
    LIST_ENTRY SocketsList;
    PMSOCKET Socket;
    PLIST_ENTRY ListEntry;

    InitializeListHead(&SocketsList);
    KeAcquireSpinLock(&WskContext->Lock, &Irql);
    WskContext->Shutdown = TRUE;
    while (!IsListEmpty(&WskContext->SocketsList)) {
        ListEntry = RemoveHeadList(&WskContext->SocketsList);
        Socket = CONTAINING_RECORD(ListEntry, MSOCKET, ListEntry);
        InterlockedCompareExchange(&Socket->Queued, 0, 1);
        InsertHeadList(&SocketsList, &Socket->ListEntry);
    }
    KeReleaseSpinLock(&WskContext->Lock, Irql);
    
    while (!IsListEmpty(&SocketsList)) {
        ListEntry = RemoveHeadList(&SocketsList);
        Socket = CONTAINING_RECORD(ListEntry, MSOCKET, ListEntry);
        MWskSocketRelease(Socket);
    }

    MWskReleaseProviderNPI(WskContext);
    MWskDeregister(WskContext);
    ExFreePoolWithTag(WskContext, MWSK_CONTEXT_TAG);
}

NTSTATUS
    MWskSocketCreate(PMWSK_CONTEXT WskContext, PWSK_SOCKET WskSocket, PMSOCKET *pSocket)
{
    PMSOCKET Socket = NULL;
    KIRQL Irql;
    NTSTATUS Status;
    
    *pSocket = NULL;
    Socket = (PMSOCKET)ExAllocatePoolWithTag(NonPagedPool, sizeof(MSOCKET), MSOCKET_TAG);
    if (Socket == NULL) {
        __debugbreak();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Socket, sizeof(MSOCKET));
    Socket->Socket = WskSocket;
    Socket->Dispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch;
    *pSocket = Socket;

    KeAcquireSpinLock(&WskContext->Lock, &Irql);
    if (!WskContext->Shutdown) {
        InterlockedCompareExchange(&Socket->Queued, 1, 0);
        InsertHeadList(&WskContext->SocketsList, &Socket->ListEntry);
        Socket->WskContext = WskContext;
        Status = STATUS_SUCCESS;
    } else {
        Status = STATUS_SHUTDOWN_IN_PROGRESS;
    }
    KeReleaseSpinLock(&WskContext->Lock, Irql);
    return Status;
}

VOID
    MWskSocketRelease(PMSOCKET Socket)
{
    KIRQL Irql;

    MWskDisconnect(Socket, 0);
    MWskClose(Socket);

    if (1 == InterlockedCompareExchange(&Socket->Queued, 0, 1)) {
        PMWSK_CONTEXT WskContext = Socket->WskContext;
        KeAcquireSpinLock(&WskContext->Lock, &Irql);
        RemoveEntryList(&Socket->ListEntry);
        KeReleaseSpinLock(&WskContext->Lock, Irql);
    }
    ExFreePoolWithTag(Socket, MSOCKET_TAG);
}

NTSTATUS
    MWskSocketConnectIrpCompletionRoutine(
    __in PDEVICE_OBJECT Reserved,
    __in PIRP Irp,
    __in PVOID Context
    )
{    
    PKEVENT CompEvent = (PKEVENT)Context;
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    KLOG(LInfo, "completion");
    KeSetEvent(CompEvent, 2, FALSE);    
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
    MWskSocketConnect(
        PMWSK_CONTEXT WskContext,
        USHORT SocketType, 
        ULONG Protocol, 
        PSOCKADDR LocalAddress, 
        PSOCKADDR RemoteAddress,
        PMSOCKET *pSocket
        )
{
    PIRP Irp = NULL;
    NTSTATUS Status;
    KEVENT CompEvent;
    PAGED_CODE();
    
    if (WskContext->Shutdown)
        return STATUS_SHUTDOWN_IN_PROGRESS;

    KeInitializeEvent(&CompEvent, SynchronizationEvent, FALSE);
    
    Irp = IoAllocateIrp(1, FALSE);
    if (Irp == NULL) {
        KLog(LError, "insufficient resources\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    IoSetCompletionRoutine(Irp, 
            MWskSocketConnectIrpCompletionRoutine,
            &CompEvent, TRUE, TRUE, TRUE);
            
    Status = WskContext->ProviderNpi.Dispatch->WskSocketConnect(WskContext->ProviderNpi.Client, 
                                SocketType, 
                                Protocol, 
                                LocalAddress, 
                                RemoteAddress, 
                                0, 
                                NULL, //SocketContext, 
                                NULL, //Dispatch,
                                NULL,
                                NULL,
                                NULL,
                                Irp);
    KLOG(LInfo, "WskSocketConnect status %x", Status);
    
    KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, NULL);
    
    Status = Irp->IoStatus.Status;
    if (NT_SUCCESS(Status)) {
        PWSK_SOCKET WskSocket = (PWSK_SOCKET)Irp->IoStatus.Information;
        PMSOCKET Socket = NULL;
        Status = MWskSocketCreate(WskContext, WskSocket, &Socket);
        if (Status == STATUS_SHUTDOWN_IN_PROGRESS) {
            MWskSocketRelease(Socket);
            Socket = NULL;
        }
        *pSocket = Socket;
    } else {
        KLog(LError, "Connect irp completed with err %x", Status);
        *pSocket = NULL;
    }
    IoFreeIrp(Irp);
    return Status;
}

NTSTATUS
    MWskNameResolveCompletionRoutine(
    __in PDEVICE_OBJECT Reserved,
    __in PIRP Irp,
    __in PVOID Context
    )
{    
    PKEVENT compEvent = (PKEVENT)Context;
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    KeSetEvent(compEvent, 2, FALSE);    
    return STATUS_MORE_PROCESSING_REQUIRED;
}



NTSTATUS
    MWskSockAddrIp4Make(const char *ip, USHORT port, PSOCKADDR_IN sock_addr)
{
    PCSTR terminator;
    IN_ADDR in_addr;
    NTSTATUS Status;

    Status = RtlIpv4StringToAddressA(ip, TRUE, &terminator, &in_addr);
    if (!NT_SUCCESS(Status)) {
        KLog(LError, "RtlIpv4StringToAddressA failed for %s result %x", ip, Status);
        return Status;
    }
    IN4ADDR_SETSOCKADDR(sock_addr, &in_addr, htons(port));
    return STATUS_SUCCESS;
}


NTSTATUS 
    MWskSockAddrToStr(
        PSOCKADDR_IN        addr,
        PUNICODE_STRING     addr_s     
    )
{
    NTSTATUS Status;
    ULONG Length = INET_ADDRSTRLEN;

    addr_s->Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, (INET_ADDRSTRLEN+1)*sizeof(WCHAR), MODULE_TAG);
    if (addr_s->Buffer == NULL) {
        KLog(LError, "alloc failure");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = RtlIpv4AddressToStringExW(&addr->sin_addr, addr->sin_port,  addr_s->Buffer, &Length);
    if (!NT_SUCCESS(Status)) {
        KLog(LError, "RtlIpv4AddressToStringExW err %x", Status);
        ExFreePoolWithTag(addr_s->Buffer, MODULE_TAG);
        addr_s->Buffer = NULL;
        return Status;
    } else {
        addr_s->Buffer[Length] = L'\0';
    }

    addr_s->Length = (USHORT)(Length*sizeof(WCHAR));
    addr_s->MaximumLength = (INET_ADDRSTRLEN+1)*sizeof(WCHAR);

    return STATUS_SUCCESS;
}

NTSTATUS
    MWskResolveName(
        PMWSK_CONTEXT WskContext,
        __in PUNICODE_STRING NodeName,
        __in_opt PUNICODE_STRING ServiceName,
        __in_opt PADDRINFOEXW Hints,
        PSOCKADDR_IN ResolvedAddress
    )
{
    NTSTATUS Status;
    PIRP Irp;
    KEVENT CompletionEvent;
    PADDRINFOEXW Results = NULL, AddrInfo = NULL;
 
    KeInitializeEvent(&CompletionEvent, SynchronizationEvent, FALSE);
 
    Irp = IoAllocateIrp(1, FALSE);
    if(Irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }        

    IoSetCompletionRoutine(Irp, MWskNameResolveCompletionRoutine, &CompletionEvent, TRUE, TRUE, TRUE);
 
    WskContext->ProviderNpi.Dispatch->WskGetAddressInfo (
        WskContext->ProviderNpi.Client,
        NodeName,
        ServiceName,
        NS_ALL,
        NULL, // Provider
        Hints,
        &Results, 
        NULL, // OwningProcess
        NULL, // OwningThread
        Irp);

    KeWaitForSingleObject(&CompletionEvent, Executive, 
                        KernelMode, FALSE, NULL);

    Status = Irp->IoStatus.Status;

    IoFreeIrp(Irp);

    if(!NT_SUCCESS(Status)) {
        KLog(LError, "resolve status %x", Status);
        return Status;
    }
 
    AddrInfo = Results; // your code here
    if (AddrInfo != NULL) {
        *ResolvedAddress = *((PSOCKADDR_IN)(AddrInfo->ai_addr));
    } else {
        Status = STATUS_UNSUCCESSFUL;
        KLog(LError, "no addresses found");
    }

    WskContext->ProviderNpi.Dispatch->WskFreeAddressInfo(
        WskContext->ProviderNpi.Client,
        Results);

    return Status;
}

NTSTATUS
MWskSendIrpCompletionRoutine(
    __in PDEVICE_OBJECT Reserved,
    __in PIRP Irp,
    __in PVOID Context
    )
{    
    PKEVENT CompEvent = (PKEVENT)Context;
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    KLOG(LInfo, "completion");
    KeSetEvent(CompEvent, 2, FALSE);    
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
    MWskSend(PMSOCKET Socket, ULONG Flags, PVOID Buffer, ULONG Length, ULONG *BytesSent)
{
    WSK_BUF WskBuf;
    KEVENT CompEvent;
    PIRP Irp = NULL;
    PMDL Mdl = NULL;
    NTSTATUS Status;

    *BytesSent = 0;
    KeInitializeEvent(&CompEvent, SynchronizationEvent, FALSE);
    
    Irp = IoAllocateIrp(1, FALSE);
    if (Irp == NULL) {
        KLog(LError, "insufficient resources\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    IoSetCompletionRoutine(Irp, 
            MWskSendIrpCompletionRoutine,
            &CompEvent, TRUE, TRUE, TRUE);
            
    Mdl = IoAllocateMdl(Buffer, Length, FALSE, FALSE, NULL);
    if (Mdl == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    MmBuildMdlForNonPagedPool(Mdl);

    WskBuf.Offset = 0;
    WskBuf.Length = Length;
    WskBuf.Mdl = Mdl;

    Status = Socket->Dispatch->WskSend(Socket->Socket, &WskBuf, Flags, Irp);
    KLOG(LInfo, "WskSend status %x", Status);
    
    KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, NULL);
    
    Status = Irp->IoStatus.Status;
    
    if (!NT_SUCCESS(Status))
        KLog(LError, "send status %x", Status);
        
    if (NT_SUCCESS(Status)) {
        *BytesSent = (ULONG)Irp->IoStatus.Information;
    } 

cleanup:
    if (Irp != NULL)
        IoFreeIrp(Irp);
    if (Mdl != NULL)
        IoFreeMdl(Mdl);

    return Status;
}

NTSTATUS
    MWskSendAll(PMSOCKET Socket, PVOID Buffer, ULONG Length)
{
    ULONG BytesSent;
    ULONG Offset;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    Offset = 0;
    while (Offset < Length) {
        Status = MWskSend(Socket, 0, (PVOID)((ULONG_PTR)Buffer + Offset), Length - Offset, &BytesSent);
        if (!NT_SUCCESS(Status)) {
            break;
        }
        Offset+= BytesSent;
    }    

    return Status;
}

NTSTATUS
    MWskReceiveIrpCompletionRoutine(
    __in PDEVICE_OBJECT Reserved,
    __in PIRP Irp,
    __in PVOID Context
    )
{    
    PKEVENT CompEvent = (PKEVENT)Context;
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    KLOG(LInfo, "completion");
    KeSetEvent(CompEvent, 2, FALSE);    
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
    MWskReceive(PMSOCKET Socket, ULONG Flags, PVOID Buffer, ULONG Length, ULONG *BytesReceived)
{
    WSK_BUF WskBuf;
    KEVENT CompEvent;
    PIRP Irp = NULL;
    PMDL Mdl = NULL;
    NTSTATUS Status;

    *BytesReceived = 0;
    KeInitializeEvent(&CompEvent, SynchronizationEvent, FALSE);
    
    Irp = IoAllocateIrp(1, FALSE);
    if (Irp == NULL) {
        KLog(LError, "insufficient resources\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoSetCompletionRoutine(Irp, 
            MWskReceiveIrpCompletionRoutine,
            &CompEvent, TRUE, TRUE, TRUE);
 
    Mdl = IoAllocateMdl(Buffer, Length, FALSE, FALSE, NULL);
    if (Mdl == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    MmBuildMdlForNonPagedPool(Mdl);

    WskBuf.Offset = 0;
    WskBuf.Length = Length;
    WskBuf.Mdl = Mdl;

    Status = Socket->Dispatch->WskReceive(Socket->Socket, &WskBuf, Flags, Irp);
    KLOG(LInfo, "WskReceive status %x", Status);
    
    KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, NULL);
    Status = Irp->IoStatus.Status;

    if (!NT_SUCCESS(Status))
        KLog(LError, "receive status %x", Status);

    if (NT_SUCCESS(Status)) {
        *BytesReceived = (ULONG)Irp->IoStatus.Information;
    } 

cleanup:
    if (Irp != NULL)
        IoFreeIrp(Irp);
    if (Mdl != NULL)
        IoFreeMdl(Mdl);

    return Status;
}


NTSTATUS
    MWskReceiveAll(PMSOCKET Socket, PVOID Buffer, ULONG Length)
{
    ULONG BytesRcv;
    ULONG Offset;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    Offset = 0;
    while (Offset < Length) {
        Status = MWskReceive(Socket, 0, (PVOID)((ULONG_PTR)Buffer + Offset), Length - Offset, &BytesRcv);
        if (!NT_SUCCESS(Status)) {
            break;
        }
        
        if (BytesRcv == 0) {
            KLog(LError, "received 0 bytes");
            Status = STATUS_UNSUCCESSFUL;
            break;
        }
        Offset+= BytesRcv;
    }    

    return Status;
}

NTSTATUS
MWskDisconnectIrpCompletionRoutine(
    __in PDEVICE_OBJECT Reserved,
    __in PIRP Irp,
    __in PVOID Context
    )
{    
    PKEVENT CompEvent = (PKEVENT)Context;
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    KLOG(LInfo, "completion");
    KeSetEvent(CompEvent, 2, FALSE);    
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
    MWskDisconnect(PMSOCKET Socket, ULONG Flags)
{
    KEVENT CompEvent;
    NTSTATUS Status;
    PIRP Irp;

    if (0 != InterlockedCompareExchange(&Socket->Disconnected, 1, 0)) {
        KLOG(LInfo, "socket %p already disconnected", Socket);
        return STATUS_SUCCESS;
    }

    KeInitializeEvent(&CompEvent, SynchronizationEvent, FALSE);

    Irp = IoAllocateIrp(1, FALSE);
    if (Irp == NULL) {
        KLog(LError, "insufficient resources\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoSetCompletionRoutine(Irp, 
            MWskDisconnectIrpCompletionRoutine,
            &CompEvent, TRUE, TRUE, TRUE);
            
    Status = Socket->Dispatch->WskDisconnect(Socket->Socket, NULL, Flags, Irp);
    KLOG(LInfo, "WskDisconnect status %x", Status);
    
    KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, NULL);

    Status = Irp->IoStatus.Status;

    if (!NT_SUCCESS(Status)) 
        KLog(LError, "disconnect status %x", Status);

    IoFreeIrp(Irp);

    return Status;

}

NTSTATUS
MWskCloseIrpCompletionRoutine(
    __in PDEVICE_OBJECT Reserved,
    __in PIRP Irp,
    __in PVOID Context
    )
{    
    PKEVENT CompEvent = (PKEVENT)Context;
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    KLOG(LInfo, "completion");
    KeSetEvent(CompEvent, 2, FALSE);    
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
    MWskClose(PMSOCKET Socket)
{
    KEVENT CompEvent;
    NTSTATUS Status;
    PIRP Irp;
    
    if (0 != InterlockedCompareExchange(&Socket->Closed, 1, 0)) {
        KLOG(LInfo, "socket %p already closed", Socket);
        return STATUS_SUCCESS;
    }
    
    KeInitializeEvent(&CompEvent, SynchronizationEvent, FALSE);
    
    Irp = IoAllocateIrp(1, FALSE);
    if (Irp == NULL) {
        KLog(LError, "insufficient resources\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoSetCompletionRoutine(Irp, 
            MWskCloseIrpCompletionRoutine,
            &CompEvent, TRUE, TRUE, TRUE);
            
    Status = Socket->Dispatch->WskCloseSocket(Socket->Socket, Irp);
    KLOG(LInfo, "WskCloseSocket status %x", Status);
     
    KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, NULL);
    Status = Irp->IoStatus.Status;
    
    if (!NT_SUCCESS(Status)) 
        KLog(LError, "close status %x", Status);

    IoFreeIrp(Irp);

    return Status;
}