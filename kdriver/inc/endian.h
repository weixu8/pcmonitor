#pragma once

#define ntohs(x) RtlUshortByteSwap(x)
#define htons(x) RtlUshortByteSwap(x)

#define ntohl(x) RtlUlongByteSwap(x)
#define htonl(x) RtlUlongByteSwap(x)

#define ntohll(x) RtlUlonglongByteSwap(x)
#define htonll(x) RtlUlonglongByteSwap(x)
