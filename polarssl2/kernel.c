#include "polarssl\kernel.h"

SSL_KERNEL_CALLBACKS g_KernelCallbacks;

void SslInitKernelCallbacks(PSSL_KERNEL_CALLBACKS Callbacks)
{
	RtlCopyMemory(&g_KernelCallbacks, Callbacks, sizeof(SSL_KERNEL_CALLBACKS));
}



void SslGetLocalTimeFields(PTIME_FIELDS pTimeFields)
{
	LARGE_INTEGER time;
	KeQuerySystemTime(&time);
	ExSystemTimeToLocalTime(&time, &time);
	RtlTimeToTimeFields(&time, pTimeFields);
}

time_t
	get_unix_time()
{
	LARGE_INTEGER time;
	time_t unixTime;

	KeQuerySystemTime(&time);
	ExSystemTimeToLocalTime(&time, &time);

	unixTime = time.QuadPart / 10000000 - 11644473600;
	return unixTime;
}