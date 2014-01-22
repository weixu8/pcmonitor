#include <inc/time.h>
#include <inc/klogger.h>

#define MODULE_TAG 'time'
#define __SUBCOMPONENT__ "time"

char *
TimepQuerySystemTime(PTIME_FIELDS pTimeFields)
{
	TIME_FIELDS timeFields;
	size_t remains = TIMEP_SYSTIME_CHARS;
	NTSTATUS Status;
	char *timeStampEnd = NULL;

	char *timeStamp = ExAllocatePoolWithTag(NonPagedPool, remains, MODULE_TAG);
	if (timeStamp == NULL) {
		return NULL;
	}

	if (pTimeFields == NULL) {
		GetLocalTimeFields(&timeFields);
		pTimeFields = &timeFields;
	}

	Status = RtlStringCchPrintfExA(timeStamp, remains, &timeStampEnd, &remains, 0, "%04d-%02d-%02d %02d:%02d:%02d,%03d",
		pTimeFields->Year,
		pTimeFields->Month,
		pTimeFields->Day,
		pTimeFields->Hour, pTimeFields->Minute,
		pTimeFields->Second, pTimeFields->Milliseconds);

	if (!NT_SUCCESS(Status)) {
		KLog(LError, "RtlStringCchPrintfExA err %x", Status);
		ExFreePoolWithTag(timeStamp, MODULE_TAG);
		timeStamp = NULL;
	} else {
		timeStamp[TIMEP_SYSTIME_CHARS - 1] = '\0';
	}

	return timeStamp;
}