#include "packet.h"

#include <stdlibrary.h>
#ifdef __KERNEL_MODE__
#include <Ntstrsafe.h>
#endif

PTXPKT TxPacketCreate(unsigned long type, unsigned long extra, char *data, unsigned long size)
{
    PTXPKT pkt = NULL;
    pkt = (PTXPKT)malloc(sizeof(TXPKT) + size);
    if (pkt == NULL)
        return NULL;

    pkt->sign = TXPKT_SIGN;
    pkt->type = type;
    pkt->extra = extra;
    pkt->size = size;
    pkt->bytes = NULL;

    if (data != NULL)
        memcpy(pkt->data, data, size);
    else
        memset(pkt->data, 0, size);

    return pkt;
}

void TxPacketDelete(PTXPKT pkt)
{
    if (pkt->bytes != NULL)
        free(pkt->bytes);
    free(pkt);
}

void TxPacketToBytes(PTXPKT pkt)
{
    char *buff = NULL;
    unsigned long header_size = 8*4;
    unsigned long size_required = header_size + pkt->size;
    char field_s[9];
    
    if (pkt->bytes != NULL) {
        free(pkt->bytes);
        pkt->bytes = NULL;
    }

    pkt->bytes = (char *)malloc(size_required);
    if (pkt->bytes == NULL)
        return;

    #ifdef __KERNEL_MODE__
    RtlStringCbPrintfA(field_s, 9, "%08x", pkt->sign);
    memcpy(pkt->bytes + 0*8, field_s, 8);
    RtlStringCbPrintfA(field_s, 9, "%08x", pkt->type);
    memcpy(pkt->bytes + 1*8, field_s, 8);
    RtlStringCbPrintfA(field_s, 9, "%08x", pkt->extra);
    memcpy(pkt->bytes + 2*8, field_s, 8);
    RtlStringCbPrintfA(field_s, 9, "%08x", pkt->size);
    memcpy(pkt->bytes + 3*8, field_s, 8);
    #else
    //TODO: it's incorrect => snprintf(pkt->bytes, header_size, "%08x%08x%08x%08x", pkt->sign, pkt->type, pkt->extra, pkt->size);
    #endif

    memcpy(pkt->bytes + header_size, pkt->data, pkt->size);
    
    pkt->bytes_count = size_required;
    return;
}

int char2integer(char *s, int base, unsigned long *presult)
{
    #ifdef __KERNEL_MODE__
    {
        NTSTATUS Status;
        Status = RtlCharToInteger(s, base, presult);
        if (!NT_SUCCESS(Status))
            return -1;
        else
            return 0;
    }
    #else
    //todo process errors here
    *presult = strtoul (s,NULL,16);
    return 0;
    #endif
}

int TxPacketRcv(void *socket, PTXPKT_RCV_FUNCTION rcv_func, PTXPKT *ppkt)
{
    char field[9];
    int rc;
    unsigned long sign;
    unsigned long type;
    unsigned long extra;
    unsigned long size;
    PTXPKT pkt = NULL;

    field[8] = '\0';    
    rc = rcv_func(socket, 8, field);
    if (rc != 0)
        return rc;

    rc = char2integer(field, 16, &sign);
    if (rc != 0)
        return rc;

    if (sign != TXPKT_SIGN)
        return -1;

    rc = rcv_func(socket, 8, field);
    if (rc != 0)
        return rc;
    rc = char2integer(field, 16, &type);
    if (rc != 0)
        return rc;


    rc = rcv_func(socket, 8, field);
    if (rc != 0)
        return rc;

    rc = char2integer(field, 16, &extra);
    if (rc != 0)
        return rc;
    
    rc = rcv_func(socket, 8, field);
    if (rc != 0)
        return rc;

    rc = char2integer(field, 16, &size);
    if (rc != 0)
        return rc;
    
    pkt = TxPacketCreate(type, extra, NULL, size);
    if (pkt == NULL)
        return -1;

    if (size != 0) {
        rc = rcv_func(socket, size, pkt->data);
        if (rc != 0) {
            TxPacketDelete(pkt);
            return rc;
        }
    }

    *ppkt = pkt;
    
    return 0;
}