#define _CRT_SECURE_NO_WARNINGS
#include <pcap/pcap.h>
#include <sys/types.h>
#include <pcap-bpf.h>
#define WIN32
#define HAVE_REMOTE
#include "pcap.h"
#include "Win32-Extensions.h"
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <pcap.h>
#include <winsock.h>
#include <time.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#include<iostream.h>
#define IPVER   4           //IP协议预定
#define MAX_BUFF_LEN 65500  //发送缓冲区最大值
#define DEST_PORT 520    //目的端口号
#define SOUR_PORT 520   //源端口号

typedef struct   _ETHER_HEADER{
    u_char   et_dhost[6];
    u_char   et_shost[6];
    u_short   et_type;  //如果上一层为IP协议。则ether_type的值就是0x0800
} ETHER_HEADER;

typedef struct _IP_HEADER
{
    unsigned char   h_verlen;
    unsigned char   tos; //type of service
    unsigned short  total_len;
    unsigned short  ident;
    unsigned short  frag_and_flags;
    unsigned char   ttl;
    unsigned char   proto;
    unsigned short  checksum;
    unsigned int    sourceIP;
    unsigned int    destIP;
} IP_HEADER;

typedef struct _UDP_HEADER
{
  USHORT source;         /* source port */
  USHORT dest;           /* destination port */
  unsigned short len;            /* udp length */
  USHORT checkl;         /* udp checksum */
} UDP_HEADER;

typedef struct _psdhdr
{
    unsigned long saddr;           //Source IP address; 32 bits
    unsigned long daddr;           //Destination IP address; 32 bits
    unsigned char mbz;           //padding
    unsigned char ptcl;           //Protocol; 8 bits
    unsigned short udpl;           //TCP length; 16 bits
}PSDUDP_HEADER ;


typedef struct _RIP_header /*RIP数据包的头部*/
{
    unsigned char command;/*命令只能是REQUEST或者RESONSE*/
    unsigned char version;/*版本号，1或者2*/
    unsigned short pad0;/*置零*/
} RIP_header;
typedef struct _RIP_data/*RIP数据包*/
{
    unsigned short addrfamily;/*地址族，必须为2*/
    unsigned short routetag;/*路由标记*/
    unsigned int ipaddr;/*IP地址*/
    unsigned int netmask;/*掩码*/
    unsigned int nexthop;/*下一跳*/
    unsigned int metric;/*跳数*/
} RIP_data;
/////////////////////////////////////////////////////////////////////
USHORT CheckSum(USHORT *buffer, int size)
{
    unsigned long cksum = 0;

    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }

    if (size)
    {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);

    return (USHORT)(~cksum);
}
///////////////////////////////////////////////////////////////////
int packet_number;   //指定发送的数据包数量
void genUDPPacket(pcap_t *_adhandle,int packetNumber);


pcap_t *adhandle;

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
//  pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret=-1;
//以下为打开某个网卡
/* Retrieve the device list from the local machine */
if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL,
&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
 /* Print the list */

    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }


    printf("Enter the interface number (1-%d):",i);

    int input_NetInterface_number;
    scanf("%d", &input_NetInterface_number);

    if(input_NetInterface_number < 1 || input_NetInterface_number > i)
    {
        printf("\nInterface number out of range.\n");

        pcap_freealldevs(alldevs);
        return -1;
    }


    for(d=alldevs, i=0; i< input_NetInterface_number-1 ;d=d->next, i++);
//adhandle is a adaptor handler
/* Open the output device */
if ( (adhandle= pcap_open(d->name, 65536,
PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL,errbuf) )
== NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);

        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);
//以上为打开某个网卡
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
       printf("input the number of packets\n");
       scanf("%d",&packet_number);

       genUDPPacket(adhandle,packet_number);

    pcap_close(adhandle);
    pcap_freealldevs(alldevs);

    return 0;
}

void genUDPPacket(pcap_t *_adhandle,int packetNumber)
{
    IP_HEADER ipHeader;
    UDP_HEADER udpHeader;
    PSDUDP_HEADER psdHeader;
    ETHER_HEADER etherHeader;
    char scanf_szSrcIp[16] = "222.20.40.25";
    char scanf_szDstIp[16] = "222.20.40.25";
    char szSrcIp[16];
    char szDstIp[16];


    strcpy(szSrcIp,scanf_szSrcIp);
    strcpy(szDstIp,scanf_szDstIp);
    char *g_BehindString = "just a test";

    memset( &ipHeader, 0, sizeof ipHeader );
    memset( &udpHeader, 0, sizeof udpHeader );
    memset( &psdHeader, 0, sizeof psdHeader );
    memset( &etherHeader, 0, sizeof etherHeader );

    ipHeader.h_verlen = (IPVER<<4 | sizeof ipHeader / sizeof(unsigned long));//高四位IP版本号，低四位首部长度
    ipHeader.tos = 0;
    ipHeader.total_len = htons( sizeof ipHeader + sizeof udpHeader + strlen( g_BehindString ) );//16位总长度（字节）
    ipHeader.ident = 0x14BB;//16位标识
    ipHeader.frag_and_flags = 0x0040;//3位标志位
    ipHeader.ttl = 128;//8位生存时间TTL
    ipHeader.proto = IPPROTO_UDP;//8位协议(TCP,UDP…)
    ipHeader.checksum = 0;//16位IP首部校验和
    ipHeader.sourceIP = inet_addr( szSrcIp );//32位源IP地址
    ipHeader.destIP = inet_addr( szDstIp );//32位目的IP地址

    //填充UDP
    udpHeader.source = htons(SOUR_PORT); //16位目的端口号
    udpHeader.dest = htons(DEST_PORT); //16位目的端口号
    udpHeader.len  = 
    udpHeader.checkl = 0;
    //填充UDP伪首部（用于计算校验和，并不真正发送）
    psdHeader.saddr = ipHeader.sourceIP;
    psdHeader.daddr = ipHeader.destIP; //目的地址
    psdHeader.mbz = 0;
    psdHeader.ptcl = IPPROTO_UDP; //协议类型
    psdHeader.udpl = htons( sizeof udpHeader ); //UDP首部长度

    unsigned char ucSrcMac[6]= { 0x80,0xFA ,0x5B ,0x00, 0xFC  ,0xD1 };
    unsigned char ucDstMac[6]= { 0x80 ,0xFA ,0x5B, 0x00 ,0xFC , 0xD1 };


    memcpy( etherHeader.et_dhost, &ucDstMac, sizeof ucDstMac );
    memcpy( etherHeader.et_shost, &ucSrcMac, sizeof ucSrcMac );
    etherHeader.et_type = 0x0008;

    char ucSend[1600];
    int datasize;
    //----------------Send SYN Packet----------------
    //计算UDP校验和
    memset( ucSend, 0, sizeof ucSend);
    memcpy( ucSend, &psdHeader,sizeof psdHeader );
    memcpy( ucSend + sizeof psdHeader, &udpHeader, sizeof udpHeader );
    memcpy( ucSend + sizeof psdHeader + sizeof udpHeader, g_BehindString, strlen( g_BehindString ) );
    udpHeader.checkl = CheckSum((USHORT *)ucSend, sizeof psdHeader + sizeof udpHeader + strlen( g_BehindString ) );
    udpHeader.checkl = htons( ntohs( udpHeader.checkl ) - (USHORT)strlen(g_BehindString));

    //计算IP校验和
    memset( ucSend, 0, sizeof ucSend );
    memcpy( ucSend, &ipHeader,sizeof  ipHeader);
    memcpy( ucSend + sizeof ipHeader, &udpHeader, sizeof udpHeader );
    memset( ucSend + sizeof ipHeader +sizeof udpHeader, 0, 4 );
    ipHeader.checksum = CheckSum((USHORT *)ucSend,sizeof ipHeader );

    //填充发送缓冲区
    memset( ucSend, 0, sizeof ucSend );
    memcpy( ucSend, &etherHeader ,sizeof etherHeader );
    memcpy( ucSend + sizeof etherHeader, &ipHeader, sizeof ipHeader );
    memcpy( ucSend + sizeof etherHeader + sizeof ipHeader, &udpHeader, sizeof udpHeader );
    memcpy( ucSend + sizeof etherHeader + sizeof ipHeader + sizeof udpHeader, g_BehindString, strlen(g_BehindString) );
    datasize = sizeof ipHeader + sizeof udpHeader + sizeof etherHeader + strlen( g_BehindString );
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
   
    for(int k = 0; k < packetNumber; k++)
    if ( 0 != pcap_sendpacket(_adhandle, (const unsigned char *)ucSend, datasize ) )
    {
        printf("send failed.\n");
    }
    else
    {
        printf("send successfully\n");
    }
    system("pause");
    return ;
}
