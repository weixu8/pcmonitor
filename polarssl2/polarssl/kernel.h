#ifndef __POLARSSL_KERNEL_H__
#define __POLARSSL_KERNEL_H__

#include <ntifs.h>

typedef
void *
(*PMALLOC)(size_t len);

typedef
void
(*PFREE)(void *ptr);

typedef
int
(*PGEN_RND_BYTES)(unsigned char *output, size_t len);

typedef struct _SSL_KERNEL_CALLBACKS {
	PMALLOC malloc;
	PFREE free;
	PGEN_RND_BYTES genRndBytes;
} SSL_KERNEL_CALLBACKS, *PSSL_KERNEL_CALLBACKS;

extern SSL_KERNEL_CALLBACKS g_KernelCallbacks;

void SslInitKernelCallbacks(PSSL_KERNEL_CALLBACKS Callbacks);


time_t
get_unix_time();


void SslGetLocalTimeFields(PTIME_FIELDS pTimeFields);

#endif
