#include "polarssl\kernel.h"

KERNEL_CALLBACKS g_KernelCallbacks;

void InitKernelCallbacks(PKERNEL_CALLBACKS Callbacks)
{
	RtlCopyMemory(&g_KernelCallbacks, Callbacks, sizeof(KERNEL_CALLBACKS));
}
