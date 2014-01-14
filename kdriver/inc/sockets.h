#pragma once
#include <inc/drvmain.h>

int sock_init();

int sock_recv(void *ctx, unsigned char *buf, size_t size);

int sock_send(void *ctx, const unsigned char *buf, size_t size);

int sock_connect(int *socket_fd, const WCHAR *host, const WCHAR *port);

void sock_close(int socket_fd);

void sock_release();