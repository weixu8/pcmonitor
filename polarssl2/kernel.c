#include "polarssl\kernel.h"

KERNEL_CALLBACKS g_KernelCallbacks;

void InitKernelCallbacks(PKERNEL_CALLBACKS Callbacks)
{
	memcpy(&g_KernelCallbacks, Callbacks, sizeof(KERNEL_CALLBACKS));
}

BOOLEAN
DllMain(
	PVOID hinstDLL,
	ULONG fdwReason,    
	PVOID lpvReserved)
{
	return TRUE;
}