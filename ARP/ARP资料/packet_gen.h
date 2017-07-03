#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#undef __FAVOR_BSD
#include <errno.h>


enum
{
    PACKET_OK = 0,
    ERR_GENERR,
    ERR_IP_CRCC_WRONG,
    ERR_UDP_CRC_WRONG,
    ERR_UDP_DPORT,
    ERR_PACKET_SEND,
    ERR_NO_INTERNEL_CHIP,
    ERR_EXTERNEL_SEND_ERR
};
enum
{
    PACKET_SEND_OK = 1,


};


#define UDP_HDR_LEN   sizeof(struct udphdr)
#define ETH_HDR_LEN   sizeof(struct ethhdr)
#define IP_HDR_LEN    sizeof(struct ip)
#define UDP_ALEN ((2*sizeof(struct in_addr))/sizeof(unsigned short))


extern void IpHdrGen(struct ip *ipHdr, unsigned char *sdaddr, unsigned char *ssaddr, unsigned int msglen, unsigned char proto)
;
extern void ethHdrGen();
extern void ethHdrGen(struct ethhdr *ethhdr, unsigned char *cdmac, unsigned char *csmac);
extern unsigned short udpcksum(struct ip *pIp, struct udphdr *pUdp);
extern void UdpHdrGen(struct udphdr *udpHdr, unsigned short int idport, unsigned short int isport, unsigned short int msglen);
extern unsigned short checksum(unsigned short *buffer, int size);
extern int getMac(unsigned char *ipaddr, unsigned char *Mac);