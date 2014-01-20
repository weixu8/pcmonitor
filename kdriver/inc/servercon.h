#pragma once
#include <inc/drvmain.h>
#include <inc/sysworker.h>
#include <inc/sockets.h>
#include <inc/keys.h>
#include <inc/pe.h>
#include <inc/srequest_header.h>

#include <polarssl2/polarssl/config.h>
#include <polarssl2/polarssl/ssl.h>
#include <polarssl2/polarssl/entropy.h>
#include <polarssl2/polarssl/ctr_drbg.h>
#include <polarssl2/polarssl/error.h>
#include <polarssl2/polarssl/certs.h>

#define SERVER_PORT L"9111"
#define SERVER_NAME L"10.30.16.93"

typedef struct _SERVER_CON {
	KGUARDED_MUTEX		Lock;
	volatile LONG		RefCount;
	LIST_ENTRY			ListEntry;
	volatile LONG		Stopping;
	volatile LONG		Connected;
	volatile LONG		SslReleased;
	volatile LONG		Deleting;
	SYSWORKER			Worker;
	int					server_fd;
	entropy_context		entropy;
	ctr_drbg_context	ctr_drbg;
	ssl_context			ssl;
	x509_crt			cacert;
	int					ssl_ret;
} SERVER_CON, *PSERVER_CON;

typedef struct _SERVER_CON_POOL {
	KGUARDED_MUTEX		Lock;
	LIST_ENTRY			ConListHead;
	ULONG				ConListCount;
	ULONG				MaxCons;
	KTIMER				Timer;
	KDPC				TimerDpc;
	SYSWORKER			Worker;
	LONG				selectCount;
	volatile LONG		Stopping;
	KEVENT				ActiveEvent;
} SERVER_CON_POOL, *PSERVER_CON_POOL;

VOID
	ServerConInit();

NTSTATUS
	ServerConPoolStart(PSERVER_CON_POOL ConPool, ULONG MaxCons);

VOID
	ServerConPoolStop(PSERVER_CON_POOL ConPool);

char *
	ServerConPoolSendReceive(PSERVER_CON_POOL ConPool, char *request);