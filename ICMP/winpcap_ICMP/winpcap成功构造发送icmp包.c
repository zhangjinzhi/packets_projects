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
#define DEST_PORT 5050    //目的端口号
#define SOUR_PORT 8080    //源端口号
#define LINE_LEN 16

#define ICMP_ECHOREPLY  0
#define ICMP_ECHOREQ    8
#define REQ_DATASIZE 32

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

// ICMP Header - RFC 792
typedef struct ICMPHDR
{
u_char Type; // Type
u_char Code; // Code
u_short Checksum; // Checksum
u_short ID; // Identification
u_short Seq; // Sequence
u_short Data; // Data
}ICMPHDR;

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


void genICMPPacket(pcap_t *_adhandle,int packetNumber);

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    pcap_t *adhandle;
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

      printf("input the number of packets\n");
       int packet_number;
       scanf("%d",&packet_number);

      genICMPPacket(adhandle,packet_number);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    pcap_close(adhandle);
    pcap_freealldevs(alldevs);

    return 0;
}

void genICMPPacket(pcap_t *_adhandle,int packetNumber)
{
    ETHER_HEADER etherHeader;
    IP_HEADER ipHeader;
    ICMPHDR icmpHeader;

    static int nId = 6;
    static int nSeq = 6;
    static int ipid=6;

    char scanf_szSrcIp[16] = "192.168.4.90";
    char scanf_szDstIp[16] = "192.168.4.90";
    char szSrcIp[16];
    char szDstIp[16];

    strcpy(szSrcIp,scanf_szSrcIp);
    strcpy(szDstIp,scanf_szDstIp);

    memset( &ipHeader, 0, sizeof ipHeader );
    memset( &icmpHeader, 0, sizeof icmpHeader );
    memset( &etherHeader, 0, sizeof etherHeader );

    ipHeader.h_verlen = (IPVER<<4 | sizeof ipHeader / sizeof(unsigned long));//高四位IP版本号，低四位首部长度
    ipHeader.tos = 0;
    ipHeader.total_len = htons( sizeof ipHeader + sizeof icmpHeader);//16位总长度（字节）
    ipHeader.ident = 0x14BB;//16位标识
    ipHeader.frag_and_flags = 0x0000;//3位标志位
    ipHeader.ttl = 128;//8位生存时间TTL
    ipHeader.proto = IPPROTO_ICMP;//8位协议(TCP,UDP,ICMP)
    ipHeader.checksum = 0;//16位IP首部校验和
    ipHeader.sourceIP = inet_addr( szSrcIp );//32位源IP地址
    ipHeader.destIP = inet_addr( szDstIp );//32位目的IP地址

    icmpHeader.Type       = ICMP_ECHOREQ;  //类型8是于ping的请求回显报文！！！！！type code不能写死，不同用途的icmp报文的不一样
    icmpHeader.Code       = 0;             //代码0
    icmpHeader.Checksum   = 0;             //校验和0，后面填充
    icmpHeader.ID         = nId++;         //标识
    icmpHeader.Seq        = nSeq++;        //序号


    unsigned char ucSrcMac[6]= { 0x80,0xFA ,0x5B ,0x00, 0xFC  ,0xD1 };
    unsigned char ucDstMac[6]= { 0x80 ,0xFA ,0x5B, 0x00 ,0xFC , 0xD1 };


    memcpy( etherHeader.et_dhost, &ucDstMac, sizeof ucDstMac );
    memcpy( etherHeader.et_shost, &ucSrcMac, sizeof ucSrcMac );
    etherHeader.et_type = 0x0008;

    char ucSend[1600];
    int datasize;
    //计算IP校验和
    memset( ucSend, 0, sizeof ucSend );
    memcpy( ucSend, &ipHeader,sizeof  ipHeader);
    memcpy( ucSend + sizeof ipHeader, &icmpHeader, sizeof icmpHeader );
    memset( ucSend + sizeof ipHeader +sizeof icmpHeader, 0, 4 );
    ipHeader.checksum = CheckSum((USHORT *)ucSend,sizeof ipHeader );

    //填充发送缓冲区
    memset( ucSend, 0, sizeof ucSend );
    memcpy( ucSend, &etherHeader ,sizeof etherHeader );
    memcpy( ucSend + sizeof etherHeader, &ipHeader, sizeof ipHeader );
    memcpy( ucSend + sizeof etherHeader + sizeof ipHeader, &icmpHeader, sizeof icmpHeader );
  //memcpy( ucSend + sizeof etherHeader + sizeof ipHeader + sizeof icmpHeader, g_BehindString, strlen(g_BehindString) );
    datasize = (sizeof ipHeader + sizeof icmpHeader + sizeof etherHeader);

    printf("datasize=%d\n",datasize);
    int l=0;
    for(;l<485;l++)
    {
    Sleep(400);
    if(pcap_sendpacket(_adhandle, ucSend, datasize) == 0)
    {
    printf("\nSend the first part\n");
    };

    } ;
    getchar();
    getchar();
    return ;
}
