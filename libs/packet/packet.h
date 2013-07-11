#ifndef __PACKET_H__
#define __PACKET_H__

#include <transport_config.h>

#define TXPKT_SIGN 111231427

#define TX_PKT_UNK  0
#define TX_PKT_AES_KEY 1
#define TX_PKT_AES_DATA 2
#define TX_PKT_RSA_PUB_KEY 3

#define RSA_KEY_BITS 2048
#define AES_KEY_BYTES 32

typedef struct _TXPKT {
    unsigned int    sign;
    unsigned int    type;
    unsigned int    extra;
    unsigned int    size;
    char            *bytes;
    unsigned int    bytes_count;
    char            data[1];
} TXPKT, *PTXPKT;

typedef
int (*PTXPKT_RCV_FUNCTION)(void *socket, unsigned long cbytes, char *buffer);

PTXPKT TxPacketCreate(unsigned long type, unsigned long extra, char *data, unsigned long size);
void TxPacketToBytes(PTXPKT pkt);

int TxPacketRcv(void *socket, PTXPKT_RCV_FUNCTION rcv_func, PTXPKT *ppkt);
void TxPacketDelete(PTXPKT pkt);


#endif
