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

typedef struct _KERNEL_CALLBACKS {
	PMALLOC malloc;
	PFREE free;
	PGEN_RND_BYTES genRndBytes;
} KERNEL_CALLBACKS, *PKERNEL_CALLBACKS;

extern KERNEL_CALLBACKS g_KernelCallbacks;

void InitKernelCallbacks(PKERNEL_CALLBACKS Callbacks);

#endif
