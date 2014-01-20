#include <inc\srequest_header.h>
#include <inc\klogger.h>

#define __SUBCOMPONENT__ "srequest"
#define MODULE_TAG 'sreq'

VOID
SRequestHeaderInit(PSREQUEST_HEADER header, int size)
{
	header->sign = SREQUEST_HEADER_SIGN;
	header->size = size;
}

VOID
SRequestHeaderHtoN(PSREQUEST_HEADER header)
{
	header->sign = htonl(header->sign);
	header->size = htonl(header->size);
}

VOID
SRequestHeaderInitAndHtoN(PSREQUEST_HEADER header, int size)
{
	SRequestHeaderInit(header, size);
	SRequestHeaderHtoN(header);
}


VOID
SRequestHeaderNtoH(PSREQUEST_HEADER header)
{
	header->sign = ntohl(header->sign);
	header->size = ntohl(header->size);
}

BOOLEAN
	SRequestHeaderValid(PSREQUEST_HEADER header)
{
	if (header->sign != SREQUEST_HEADER_SIGN)
		return FALSE;

	if (header->size < 0)
		return FALSE;

	if (header->size > MAX_SREQUEST_BODY_SIZE)
		return FALSE;

	return TRUE;
}
