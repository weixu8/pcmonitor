#include "project.h"
#include "time.h"

time_t
get_unix_time()
{
	FILETIME fTime;
	ULARGE_INTEGER uTime;
	time_t unixTime;

	GetSystemTimeAsFileTime(&fTime);
	uTime.LowPart = fTime.dwLowDateTime;
	uTime.HighPart = fTime.dwHighDateTime;

	
	unixTime = uTime.QuadPart / 10000000 - 11644473600;
	return unixTime;
}