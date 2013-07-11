#ifndef __MWSK_H__
#define __MWSK_H__

#include <inc/drvmain.h>

// Driver entry routine
NTSTATUS
WskDriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    );


// Driver unload routine
VOID
WskDriverUnload(
    __in PDRIVER_OBJECT DriverObject
    );

typedef struct _MWSK_CONTEXT {
    WSK_CLIENT_DISPATCH ClientDispatch;
    WSK_REGISTRATION    Registration;
    WSK_PROVIDER_NPI    ProviderNpi;
    LIST_ENTRY          SocketsList;
    KSPIN_LOCK          Lock;
    BOOLEAN             Shutdown;
} MWSK_CONTEXT, *PMWSK_CONTEXT;

typedef struct _MSOCKET {
    LIST_ENTRY ListEntry;
    PWSK_SOCKET Socket;
    PWSK_PROVIDER_CONNECTION_DISPATCH Dispatch;
    PMWSK_CONTEXT WskContext;
    LONG          Closed;
    LONG          Disconnected;
    LONG          Queued;
} MSOCKET, *PMSOCKET;

PMWSK_CONTEXT
    MWskCreate();

VOID
    MWskRelease(PMWSK_CONTEXT WskContext);

NTSTATUS
    MWskSocketConnect(
        PMWSK_CONTEXT WskContext,
        USHORT SocketType, 
        ULONG Protocol, 
        PSOCKADDR LocalAddress, 
        PSOCKADDR RemoteAddress,
        PMSOCKET *pSocket
        );

NTSTATUS
    MWskSend(PMSOCKET Socket, ULONG Flags, PVOID Buffer, ULONG Length, ULONG *BytesSent);
    
NTSTATUS
    MWskReceive(PMSOCKET Socket, ULONG Flags, PVOID Buffer, ULONG Length, ULONG *BytesReceived);

NTSTATUS
    MWskDisconnect(PMSOCKET Socket, ULONG Flags);
    
NTSTATUS
    MWskClose(PMSOCKET Socket);

NTSTATUS
    MWskSendAll(PMSOCKET Socket, PVOID Buffer, ULONG Length);
    
VOID
    MWskSocketRelease(PMSOCKET Socket);

NTSTATUS
    MWskReceiveAll(PMSOCKET Socket, PVOID Buffer, ULONG Length);
    
NTSTATUS
    MWskSockAddrIp4Make(const char *ip, USHORT port, PSOCKADDR_IN sock_addr);

NTSTATUS 
    MWskSockAddrToStr(
        PSOCKADDR_IN        addr,
        PUNICODE_STRING     addr_s     
    );
    
NTSTATUS
    MWskResolveName(
        PMWSK_CONTEXT WskContext,
        __in PUNICODE_STRING NodeName,
        __in_opt PUNICODE_STRING ServiceName,
        __in_opt PADDRINFOEXW Hints,
        PSOCKADDR_IN ResolvedAddress
    );
#define htons(x)    _byteswap_ushort((USHORT)(x))
#define ntohs(x)    _byteswap_ushort((USHORT)(x))
#define htonl(x)    _byteswap_ulong((ULONG)(x))
#define ntohl(x)    _byteswap_ulong((ULONG)(x))
#endif
