#include <inc/servercon.h>
#include <inc/klogger.h>

#define __SUBCOMPONENT__ "servercon"

#define MODULE_TAG 'srcn'

#define DEBUG_LEVEL 1

static void ssl_cli_debug(void *ctx, int level, const char *str)
{
	if (level < DEBUG_LEVEL)
	{
		KLog(LInfo, "%s", str);
	}
}

void *ssl_cli_malloc(size_t len)
{
	return ExAllocatePoolWithTag(NonPagedPool, len, MODULE_TAG);
}

void ssl_cli_free(void *ptr)
{
	if (ptr == NULL)
		return;

	ExFreePoolWithTag(ptr, MODULE_TAG);
}

typedef
NTSTATUS
(NTAPI *PBCRYPT_GEN_RANDOM)(
_Inout_  HANDLE hAlgorithm,
_Inout_  PUCHAR pbBuffer,
_In_     ULONG cbBuffer,
_In_     ULONG dwFlags
);

PBCRYPT_GEN_RANDOM BCryptGenRandom = NULL;

#define BCRYPT_USE_SYSTEM_PREFERRED_RNG		2
#define BCRYPT_RNG_USE_ENTROPY_IN_BUFFER	1

PBCRYPT_GEN_RANDOM
GetBCryptGenRandomAddress()
{
	BCryptGenRandom = PeGetModuleExportByName("cng.sys", "BCryptGenRandom");
	if (BCryptGenRandom == NULL) {
		KLog(LError, "no found any export BCryptGenRandom in cng.sys");
		return NULL;
	}

	return BCryptGenRandom;
}

int ssl_cli_gen_rnd_bytes(unsigned char *output, size_t len)
{
	NTSTATUS Status;

	Status = BCryptGenRandom(NULL, output, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!NT_SUCCESS(Status)) {
		KLog(LError, "BCryptGenRandom failed for len=%x, err=%x", len, Status);
		return -1;
	}

	return 0;
}

int ssl_client_init()
{
	SSL_KERNEL_CALLBACKS Callbacks;

	if (NULL == GetBCryptGenRandomAddress())
		return -1;

	Callbacks.malloc = ssl_cli_malloc;
	Callbacks.free = ssl_cli_free;
	Callbacks.genRndBytes = ssl_cli_gen_rnd_bytes;

	SslInitKernelCallbacks(&Callbacks);

	return 0;
}

NTSTATUS
ServerConDisconnectWorker(PSERVER_CON Con)
{
	KLog(LInfo, "disconnect con=%p", Con);

	if (1 == InterlockedCompareExchange(&Con->Connected, 0, 1))
		ssl_close_notify(&Con->ssl);

	if (Con->server_fd >= 0)
		sock_close(Con->server_fd);

	Con->server_fd = -1;

	if (0 == InterlockedCompareExchange(&Con->SslReleased, 1, 0)) {
		ssl_free(&Con->ssl);
		x509_crt_free(&Con->cacert);
		entropy_free(&Con->entropy);
		memset(&Con->ssl, 0, sizeof(Con->ssl));
	}

	return STATUS_SUCCESS;
}

NTSTATUS
	ServerConConnectWorker(PSERVER_CON Con)
{
	const char *pers = "ssl_client1";

	/*
	* 0. Initialize the RNG and the session data
	*/
	memset(&Con->ssl, 0, sizeof(ssl_context));
	x509_crt_init(&Con->cacert);

	KLog(LInfo, "  . Seeding the random number generator...");

	entropy_init(&Con->entropy);
	Con->ssl_ret = ctr_drbg_init(&Con->ctr_drbg, entropy_func, &Con->entropy,
		(const unsigned char *)pers, strlen(pers));

	if (Con->ssl_ret != 0) {
		KLog(LError, " failed  ! ctr_drbg_init returned %d", Con->ssl_ret);
		goto connect_failed;
	}

	KLog(LInfo, "ctr_drbg_init ok");

	/*
	* 0. Initialize certificates
	*/
	KLog(LInfo, "  . Loading the CA root certificate ...");

	Con->ssl_ret = x509_crt_parse(&Con->cacert, CA_Cert,
		strlen(CA_Cert));

	if (Con->ssl_ret < 0) {
		KLog(LError, " failed  !  x509_crt_parse(CA_Cert) returned -0x%x", -Con->ssl_ret);
		goto connect_failed;
	}

	Con->ssl_ret = x509_crt_parse(&Con->cacert, Client_Cert,
		strlen(Client_Cert));
	if (Con->ssl_ret < 0)
	{
		KLog(LError, " failed  !  x509_crt_parse(Client_Cert) returned -0x%x", -Con->ssl_ret);
		goto connect_failed;
	}

	/*
	* 1. Start the connection
	*/
	KLog(LInfo, "  . Connecting to tcp %ws:%ws...", SERVER_NAME,
		SERVER_PORT);

	Con->ssl_ret = sock_connect(&Con->server_fd, SERVER_NAME,SERVER_PORT);

	if (Con->ssl_ret != 0)
	{
		KLog(LError, " failed  ! net_connect returned %d", Con->ssl_ret);
		goto connect_failed;
	}

	KLog(LInfo, "sock_connect ok");

	/*
	* 2. Setup stuff
	*/
	KLog(LInfo, "  . Setting up the SSL/TLS structure...");
	Con->ssl_ret = ssl_init(&Con->ssl);
	if (Con->ssl_ret != 0)
	{
		KLog(LError, " failed  ! ssl_init returned %d", Con->ssl_ret);
		goto connect_failed;
	}

	KLog(LInfo, "ssl_init ok");

	ssl_set_min_version(&Con->ssl, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_3);
	ssl_set_max_version(&Con->ssl, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_3);

	ssl_set_endpoint(&Con->ssl, SSL_IS_CLIENT);
	ssl_set_authmode(&Con->ssl, SSL_VERIFY_REQUIRED);
	ssl_set_ca_chain(&Con->ssl, &Con->cacert, NULL, "sd");

	ssl_set_rng(&Con->ssl, ctr_drbg_random, &Con->ctr_drbg);
	ssl_set_dbg(&Con->ssl, ssl_cli_debug, NULL);
	ssl_set_bio(&Con->ssl, sock_recv, &Con->server_fd, sock_send, &Con->server_fd);

	/*
	* 4. Handshake
	*/
	KLog(LInfo, "  . Performing the SSL/TLS handshake...");
	Con->ssl_ret = ssl_handshake(&Con->ssl);
	if (Con->ssl_ret != 0)
	{
		KLog(LError, " failed  ! ssl_handshake returned -0x%x", -Con->ssl_ret);
		goto connect_failed;
	}

	KLog(LInfo, "ssl_handshake ok");

	/*
	* 5. Verify the server certificate
	*/
	KLog(LInfo, "  . Verifying peer X.509 certificate...");
	Con->ssl_ret = ssl_get_verify_result(&Con->ssl);

	if (Con->ssl_ret != 0)
	{
		KLog(LError, "Verifying peer X.509 certificate failed");

		if ((Con->ssl_ret & BADCERT_EXPIRED) != 0)
			KLog(LError, "  ! server certificate has expired");

		if ((Con->ssl_ret & BADCERT_REVOKED) != 0)
			KLog(LError, "  ! server certificate has been revoked");

		if ((Con->ssl_ret & BADCERT_CN_MISMATCH) != 0)
			KLog(LError, "  ! CN mismatch (expected CN=%s)", "PolarSSL Server 1");

		if ((Con->ssl_ret & BADCERT_NOT_TRUSTED) != 0)
			KLog(LError, "  ! self-signed or not signed by a trusted CA");

		goto connect_failed;
	}
	KLog(LInfo, "verify peer X.509 certificate ok");

	Con->Connected = 1;
	KLog(LInfo, "con=%p connected", Con);

	return STATUS_SUCCESS;

connect_failed:
	if (Con->ssl_ret != 0)
	{
		char error_buf[100];
		polarssl_strerror(Con->ssl_ret, error_buf, 100);
		KLog(LError, "Last error was: %d - %s", Con->ssl_ret, error_buf);
	}

	ServerConDisconnectWorker(Con);

	return STATUS_UNSUCCESSFUL;
}

int ServerConWrite(PSERVER_CON Con, const unsigned char *buf, int bufLen) {
	int ret;
	int offset = 0;

	while (offset < bufLen) {
		ret = ssl_write(&Con->ssl, buf + offset, bufLen - offset);
		if (ret <= 0) {
			KLog(LError, "ssl_write failed err=%x\n", ret);
			break;
		}
		offset += ret;
	}

	return offset;
}

int ServerConRead(PSERVER_CON Con, unsigned char *buf, int bufLen) {
	int ret;
	int offset = 0;

	while (offset < bufLen) {
		ret = ssl_read(&Con->ssl, buf + offset, bufLen - offset);
		if (ret <= 0) {
			KLog(LError, "ssl_read failed err=%x\n", ret);
			break;
		}
		offset += ret;
	}

	return offset;
}

NTSTATUS
	ServerConStart(PSERVER_CON Con)
{
	NTSTATUS Status;
	PSYS_WRK_ITEM WrkItem = NULL;

	RtlZeroMemory(Con, sizeof(SERVER_CON));
	Con->server_fd = -1;
	Con->RefCount = 1;
	Status = SysWorkerInitStart(&Con->Worker);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	
	WrkItem = SysWorkerAddWorkRef(&Con->Worker, ServerConConnectWorker, Con);
	if (WrkItem == NULL) {
		goto start_failed;
	}
	
	KeWaitForSingleObject(&WrkItem->CompletionEvent, Executive, KernelMode, FALSE, NULL);
	Status = WrkItem->Status;
	SYS_WRK_ITEM_DEREF(WrkItem);

	if (!NT_SUCCESS(Status)) {
		goto start_failed;
	}
	
	return STATUS_SUCCESS;

start_failed:
	SysWorkerStop(&Con->Worker);

	return Status;
}

VOID
	ServerConStop(PSERVER_CON Con)
{
	PSYS_WRK_ITEM WrkItem = NULL;
	
	Con->Stopping = 1;
	WrkItem = SysWorkerAddWorkRef(&Con->Worker, ServerConDisconnectWorker, Con);
	if (WrkItem == NULL) {
		goto wrk_item_failed;
	}
	KeWaitForSingleObject(&WrkItem->CompletionEvent, Executive, KernelMode, FALSE, NULL);
	SYS_WRK_ITEM_DEREF(WrkItem);

wrk_item_failed:
	SysWorkerStop(&Con->Worker);
	ServerConDisconnectWorker(Con);
}

VOID
	ServerConRef(PSERVER_CON Con)
{
	InterlockedIncrement(&Con->RefCount);
}

VOID
	ServerConDeref(PSERVER_CON Con)
{
	LONG RefCount = -1;
	RefCount = InterlockedDecrement(&Con->RefCount);
	if (RefCount < 0)
		__debugbreak();

	if (RefCount == 0) {
		ServerConStop(Con);
		RtlZeroMemory(Con, sizeof(SERVER_CON));
		ExFreePoolWithTag(Con, MODULE_TAG);
	}
}

NTSTATUS ServerConPoolOpenConsWorker(PSERVER_CON_POOL ConPool)
{
	NTSTATUS Status;
	PLIST_ENTRY ListEntry = NULL;
	PSERVER_CON Con = NULL;

	if (ConPool->Stopping)
		return STATUS_TOO_LATE;

	KeAcquireGuardedMutex(&ConPool->Lock);
	if (ConPool->Stopping) {
		Status = STATUS_TOO_LATE;
		goto unlock;
	}

rescan:
	for (ListEntry = ConPool->ConListHead.Flink; ListEntry != &ConPool->ConListHead; ListEntry = ListEntry->Flink) {
		Con = CONTAINING_RECORD(ListEntry, SERVER_CON, ListEntry);
		if (Con->Deleting) {
			RemoveEntryList(&Con->ListEntry);
			ServerConDeref(Con);
			ConPool->ConListCount--;
			goto rescan;
		}
	}

	if (ConPool->ConListCount < ConPool->MaxCons) {
		Con = ExAllocatePool(NonPagedPool, sizeof(SERVER_CON));
		if (Con == NULL) {
			KLog(LError, "cant alloc memory for connection");
			Status = STATUS_NO_MEMORY;
			goto unlock;
		}
		Status = ServerConStart(Con);
		if (!NT_SUCCESS(Status)) {
			KLog(LError, "ServerConStart failed with err=%x", Status);
			ServerConDeref(Con);
			goto unlock;
		}
		InsertHeadList(&ConPool->ConListHead, &Con->ListEntry);
		ConPool->ConListCount++;
	}
unlock:

	if (ConPool->ConListCount > 0)
		KeSetEvent(&ConPool->ActiveEvent, 0, FALSE);
	else
		KeResetEvent(&ConPool->ActiveEvent);

	KeReleaseGuardedMutex(&ConPool->Lock);

	return Status;
}

VOID NTAPI
ConPoolTimerDpcRoutine(
_In_      struct _KDPC *Dpc,
_In_opt_  PVOID DeferredContext,
_In_opt_  PVOID SystemArgument1,
_In_opt_  PVOID SystemArgument2
)
{
	PSERVER_CON_POOL ConPool = (PSERVER_CON_POOL)DeferredContext;
	if (!ConPool->Stopping)
		SysWorkerAddWork(&ConPool->Worker, ServerConPoolOpenConsWorker, ConPool);
}

NTSTATUS
ServerConPoolStart(PSERVER_CON_POOL ConPool, ULONG MaxCons)
{
	NTSTATUS Status;
	LARGE_INTEGER TimerDueTime;

	if (0 != ssl_client_init()) {
		KLog(LError, "ssl_client_init failed");
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(ConPool, sizeof(SERVER_CON_POOL));
	KeInitializeGuardedMutex(&ConPool->Lock);
	KeInitializeEvent(&ConPool->ActiveEvent, NotificationEvent, FALSE);

	InitializeListHead(&ConPool->ConListHead);
	ConPool->MaxCons = MaxCons;

	KeInitializeTimer(&ConPool->Timer);
	KeInitializeDpc(&ConPool->TimerDpc, ConPoolTimerDpcRoutine, ConPool);

	Status = SysWorkerInitStart(&ConPool->Worker);
	if (!NT_SUCCESS(Status)) {
		goto start_failed;
	}

	TimerDueTime.QuadPart = 0;
	KeSetTimerEx(&ConPool->Timer, TimerDueTime, 5000, &ConPool->TimerDpc);
	return STATUS_SUCCESS;
start_failed:

	return Status;
}

VOID
	ServerConPoolStop(PSERVER_CON_POOL ConPool)
{
	PLIST_ENTRY ListEntry = NULL;
	PSERVER_CON Con = NULL;

	ConPool->Stopping = 1;

	KeCancelTimer(&ConPool->Timer);
	KeFlushQueuedDpcs();
	SysWorkerStop(&ConPool->Worker);

	KeSetEvent(&ConPool->ActiveEvent, 0, FALSE);

	KeAcquireGuardedMutex(&ConPool->Lock);
	while (!IsListEmpty(&ConPool->ConListHead)) {
		ListEntry = RemoveHeadList(&ConPool->ConListHead);
		Con = CONTAINING_RECORD(ListEntry, SERVER_CON, ListEntry);
		ServerConDeref(Con);
	}
	KeReleaseGuardedMutex(&ConPool->Lock);
}


PSERVER_CON 
	ServerConPoolSelectCon(PSERVER_CON_POOL ConPool)
{
	PLIST_ENTRY ListEntry = NULL;
	ULONG CurrPos, SelPos;
	PSERVER_CON Con = NULL;

	if (ConPool->Stopping)
		return NULL;

	KeAcquireGuardedMutex(&ConPool->Lock);
	if (ConPool->Stopping)
		goto unlock;

rescan:
	Con = NULL;
	CurrPos = 0;
	if (ConPool->ConListCount == 0)
		goto unlock;

	SelPos = (ConPool->selectCount++)%ConPool->ConListCount;
	for (ListEntry = ConPool->ConListHead.Flink; ListEntry != &ConPool->ConListHead; ListEntry = ListEntry->Flink) {
		if (SelPos == CurrPos) {
			Con = CONTAINING_RECORD(ListEntry, SERVER_CON, ListEntry);
			if (!Con->Deleting) {
				ServerConRef(Con);
				break;
			} else {
				RemoveEntryList(&Con->ListEntry);
				ServerConDeref(Con);
				ConPool->ConListCount--;
				goto rescan;
			}
		}
		CurrPos++;
	}
unlock:
	KeReleaseGuardedMutex(&ConPool->Lock);

	return Con;
}


typedef struct _CON_SEND_RECV_DATA {
	PSERVER_CON Con;
	char		*request;
	char		*response;
} CON_SEND_RECV_DATA, *PCON_SEND_RECV_DATA;

NTSTATUS
	ServerConSendReceive(PCON_SEND_RECV_DATA Ctx)
{
	int ret = -1;
	PSERVER_CON Con = Ctx->Con;
	SREQUEST_HEADER request_header, response_header;
	char *response = NULL, *request = Ctx->request;
	int reqSize = strlen(request);

	SRequestHeaderInitAndHtoN(&request_header, reqSize);
	ret = ServerConWrite(Con, (const unsigned char *)&request_header, sizeof(request_header));
	if (ret != sizeof(request_header)) {
		KLog(LError, "ServerConWrite failed, ret=%x", ret);
		goto failed;
	}

	ret = ServerConWrite(Con, (const unsigned char *)request, reqSize);
	if (ret != reqSize) {
		KLog(LError, "ServerConWrite failed, ret=%x", ret);
		goto failed;
	}

	ret = ServerConRead(Con, (unsigned char *)&response_header, sizeof(response_header));
	if (ret != sizeof(response_header)) {
		KLog(LError, "ServerConRead(header) failed, ret=%x", ret);
		goto failed;
	}
	SRequestHeaderNtoH(&response_header);

	if (!SRequestHeaderValid(&response_header)) {
		KLog(LError, "header invalid");
		goto failed;
	}

	response = ExAllocatePoolWithTag(NonPagedPool, response_header.size + 1, MODULE_TAG);
	if (response == NULL) {
		KLog(LError, "ExAllocatePoolWithTag failed for sz=%x", response_header.size);
		goto failed;
	}

	ret = ServerConRead(Con, (unsigned char *)(response), response_header.size);
	if (ret != response_header.size) {
		KLog(LError, "ServerConRead(body) failed");
		goto failed;
	}
	response[response_header.size] = '\0';

failed:
	Ctx->response = response;

	return STATUS_SUCCESS;
}

char *
	ServerConPoolSendReceive(PSERVER_CON_POOL ConPool, char *request)
{
	PSERVER_CON Con = NULL;
	LARGE_INTEGER Timeout;
	CON_SEND_RECV_DATA Ctx;
	PSYS_WRK_ITEM WrkItem = NULL;
	char *response = NULL;

	if (ConPool->Stopping) {
		KLog(LError, "SREQ_STATUS_CLIENT_SHUTDOWN");
		goto failed;
	}

	Timeout.QuadPart = -3000 * 1000 * 10; // wait 3 secs
	KeWaitForSingleObject(&ConPool->ActiveEvent, Executive, KernelMode, FALSE, &Timeout);
	if (ConPool->Stopping) {
		KLog(LError, "SREQ_STATUS_CLIENT_SHUTDOWN");
		goto failed;
	}

	Con = ServerConPoolSelectCon(ConPool);
	if (Con == NULL) {
		KLog(LError, "ServerConPoolSelectCon failed");
		goto failed;
	}
	RtlZeroMemory(&Ctx, sizeof(Ctx));
	Ctx.request = request;
	Ctx.Con = Con;

	WrkItem = SysWorkerAddWorkRef(&Con->Worker, ServerConSendReceive, &Ctx);
	if (WrkItem == NULL) {
		KLog(LError, "cant queue task");
		goto failed;
	}

	KeWaitForSingleObject(&WrkItem->CompletionEvent, Executive, KernelMode, FALSE, NULL);
	SYS_WRK_ITEM_DEREF(WrkItem);

	response = Ctx.response;

failed:
	if (Con != NULL) {
		if (response == NULL) {
			KLog(LInfo, "no response, mark Con=%p as deleting", Con);
			Con->Deleting = 1;
		}
		ServerConDeref(Con);
	}

	return response;
}
