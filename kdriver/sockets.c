#include <inc/sockets.h>
#include <inc/mwsk.h>
#include <inc/htable.h>
#include <inc/monitor.h>
#include <inc/klogger.h>

#define __SUBCOMPONENT__ "sockets"

HTABLE SocketsTable;
#define SOCKETS_MAX_HANDLES 64

int sock_init()
{
	NTSTATUS Status;
	Status = HTableInit(&SocketsTable, SOCKETS_MAX_HANDLES);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "HTableInit failed %x", Status);
		return -1;
	}

	return 0;
}

void sock_release()
{
	HTableRelease(&SocketsTable);
}

int sock_recv(void *ctx, unsigned char *buf, size_t size)
{
	int sock_fd = *((int *)ctx);
	PMSOCKET Socket = HTableRefByHandle(&SocketsTable, sock_fd);
	ULONG bytesRcv = 0;
	NTSTATUS Status;

	if (Socket == NULL) {
		KLog(LError, "socket not found by h=%d", sock_fd);
		return -1;
	}

	Status = MWskReceiveAll(Socket, buf, size, &bytesRcv);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "MWskReceiveAll failed %x", Status);
		return -1;
	}

	return bytesRcv;
}

int sock_send(void *ctx, const unsigned char *buf, size_t size)
{
	int sock_fd = *((int *)ctx);
	PMSOCKET Socket = HTableRefByHandle(&SocketsTable, sock_fd);
	ULONG sentBytes = 0;
	NTSTATUS Status;

	if (Socket == NULL){
		KLog(LError, "socket not found by h=%d", sock_fd);
		return -1;
	}
	
	Status = MWskSendAll(Socket, (char *)buf, size, &sentBytes);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "MWskSendAll failed %x", Status);
		return -1;
	}

	return sentBytes;
}

int sock_connect(int *socket_fd, const WCHAR *host, const WCHAR *port)
{
	NTSTATUS Status;
	SOCKADDR_IN LocalAddress;
	SOCKADDR_IN RemoteAddress;
	PMSOCKET Socket = NULL;
	UNICODE_STRING NodeName = { 0, 0, NULL };
	UNICODE_STRING ServiceName = { 0, 0, NULL };
	UNICODE_STRING RemoteName = { 0, 0, NULL };
	int handle = -1;
	int ret = -1;

	IN4ADDR_SETANY(&LocalAddress);
	
	RtlInitUnicodeString(&NodeName, host);
	RtlInitUnicodeString(&ServiceName, port);

	Status = MWskResolveName(
		MonitorGetInstance()->WskContext,
		&NodeName,
		&ServiceName,
		NULL,
		&RemoteAddress
		);

	if (!NT_SUCCESS(Status)) {
		KLog(LError, "MWskResolveName error %x for name %wZ %wZ", Status, &NodeName, &ServiceName);
		goto cleanup;
	}

	Status = MWskSockAddrToStr(&RemoteAddress, &RemoteName);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "MWskSockAddrToStr failure %x", Status);
		goto cleanup;
	}

	KLog(LInfo, "RemoteName=%wZ", RemoteName);

	Status = MWskSocketConnect(MonitorGetInstance()->WskContext, SOCK_STREAM, IPPROTO_TCP, (PSOCKADDR)&LocalAddress, (PSOCKADDR)&RemoteAddress, &Socket);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "MWskSocketConnect error %x", Status);
		goto cleanup;
	}

	handle = HTableCreateHandle(&SocketsTable, Socket);
	if (handle >= 0) {
		*socket_fd = handle;
		ret = 0;
	}

cleanup:
	if (RemoteName.Buffer != NULL) {
		ExFreePool(RemoteName.Buffer);
	}
	
	if (ret != 0) {
		if (Socket != NULL)
			MWskSocketRelease(Socket);
	}

	return ret;
}

void sock_close(int socket_fd)
{
	PMSOCKET Socket = HTableRefByHandle(&SocketsTable, socket_fd);
	if (Socket == NULL) {
		KLog(LError, "socket not found by h=%d", socket_fd);
		return;
	}

	HTableCloseHandle(&SocketsTable, socket_fd);
	MWskSocketRelease(Socket);	
}
