#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <pcap.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#define IPVER   4           //IP协议预定
#define MAX_BUFF_LEN 65500  //发送缓冲区最大值
#define DEST_PORT 5050    //目的端口号
#define SOUR_PORT 8080    //源端口号
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

typedef struct _TCP_HEADER 
{
    USHORT th_sport;
    USHORT th_dport;
    unsigned int th_seq;
    unsigned int th_ack;
    unsigned char th_lenres;
    unsigned char th_flag;
    USHORT th_win;
    USHORT th_sum;
    USHORT th_urp;
} TCP_HEADER;

typedef struct _psdhdr
{ 
    unsigned long saddr;           //Source IP address; 32 bits
    unsigned long daddr;           //Destination IP address; 32 bits 
    unsigned char mbz;           //padding
    unsigned char ptcl;           //Protocol; 8 bits
    unsigned short tcpl;           //TCP length; 16 bits
}PSDTCP_HEADER ;

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

int main( )
{
    IP_HEADER ipHeader;
    TCP_HEADER tcpHeader;
    PSDTCP_HEADER psdHeader;
    ETHER_HEADER etherHeader;

    char szSrcIp[] = "222.20.95.17";   //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    char szDstIp[] = "222.20.95.17";
    char *g_BehindString = "just a test";

    memset( &ipHeader, 0, sizeof ipHeader );
    memset( &tcpHeader, 0, sizeof tcpHeader );
    memset( &psdHeader, 0, sizeof psdHeader );
    memset( &etherHeader, 0, sizeof etherHeader );

    ipHeader.h_verlen = (IPVER<<4 | sizeof ipHeader / sizeof(unsigned long));//高四位IP版本号，低四位首部长度 
    IpHeader.tos = 0;
    ipHeader.total_len = htons( sizeof ipHeader + sizeof tcpHeader + strlen( g_BehindString ) );//16位总长度（字节） 
    ipHeader.ident = 0x14BB;//16位标识 
    ipHeader.frag_and_flags = 0x0040;//3位标志位 
    ipHeader.ttl = 128;//8位生存时间TTL 
    ipHeader.proto = IPPROTO_TCP;//8位协议(TCP,UDP…) 
    ipHeader.checksum = 0;//16位IP首部校验和 
    ipHeader.sourceIP = inet_addr( szSrcIp );//32位源IP地址 
    ipHeader.destIP = inet_addr( szDstIp );//32位目的IP地址
    //填充TCP
   // tcpHeader.th_sport = htons( rand()%60000 + 1024 );
    //tcpHeader.th_dport = htons( atoi(argv[2]) );
    tcpHeader.th_dport=htons(DEST_PORT); //16位目的端口号
    tcpHeader.th_sport=htons(SOUR_PORT); //16位源端口号 
    tcpHeader.th_seq = htonl( rand()%900000000 + 100000 );
    tcpHeader.th_ack = 0;
    tcpHeader.th_lenres = (sizeof(tcpHeader)/4<<4|0);
    tcpHeader.th_flag = 2; ///////////////////////////////////修改这里来实现不同的标志位探测，2是SYN，1是//FIN，16是ACK探测 等等 
    tcpHeader.th_win = htons((unsigned short)512);
    tcpHeader.th_sum = 0;
    tcpHeader.th_urp = 0;
    //填充TCP伪首部（用于计算校验和，并不真正发送） 
    psdHeader.saddr = ipHeader.sourceIP; 
    psdHeader.daddr = ipHeader.destIP; //目的地址 
    psdHeader.mbz = 0; 
    psdHeader.ptcl = IPPROTO_TCP; //协议类型 
    psdHeader.tcpl = htons( sizeof tcpHeader ); //TCP首部长度

    unsigned char ucSrcMac[6] = { 0x64, 0x27, 0x37, 0x7D, 0XF7, 0X72 };
    unsigned char ucDstMac[6] = { 0x88, 0x9F, 0xFA, 0xFD, 0xF4, 0XF2 };
    memcpy( etherHeader.et_dhost, &ucDstMac, sizeof ucDstMac );
    memcpy( etherHeader.et_shost, &ucSrcMac, sizeof ucSrcMac );
    etherHeader.et_type = 0x0008;

    char ucSend[MAX_BUFF_LEN];
    int datasize;    
    //----------------Send SYN Packet----------------
    //计算TCP校验和
    memset( ucSend, 0, sizeof ucSend);
    memcpy( ucSend, &psdHeader,sizeof psdHeader ); 
    memcpy( ucSend + sizeof psdHeader, &tcpHeader, sizeof tcpHeader ); 
    memcpy( ucSend + sizeof psdHeader + sizeof tcpHeader, g_BehindString, strlen( g_BehindString ) ); 
    tcpHeader.th_sum = CheckSum((USHORT *)ucSend, sizeof psdHeader + sizeof tcpHeader + strlen( g_BehindString ) );
    tcpHeader.th_sum = htons( ntohs( tcpHeader.th_sum ) - (USHORT)strlen(g_BehindString));

    //计算IP校验和
    memset( ucSend, 0, sizeof ucSend );
    memcpy( ucSend, &ipHeader,sizeof  ipHeader); 
    memcpy( ucSend + sizeof ipHeader, &tcpHeader, sizeof tcpHeader );
    memset( ucSend + sizeof ipHeader +sizeof tcpHeader, 0, 4 ); 
    ipHeader.checksum = CheckSum((USHORT *)ucSend,sizeof ipHeader );

    //填充发送缓冲区    
    memset( ucSend, 0, sizeof ucSend );
    memcpy( ucSend, &etherHeader ,sizeof etherHeader );
    memcpy( ucSend + sizeof etherHeader, &ipHeader, sizeof ipHeader );
    memcpy( ucSend + sizeof etherHeader + sizeof ipHeader, &tcpHeader, sizeof tcpHeader );
    memcpy( ucSend + sizeof etherHeader + sizeof ipHeader + sizeof tcpHeader, g_BehindString, strlen(g_BehindString) );
    datasize = sizeof ipHeader + sizeof tcpHeader + sizeof etherHeader + strlen( g_BehindString );
    
    char *device = "//Device//NPF_{2BA6CC28-7C8E-42AA-BE7F-A513BD5E50DC}";
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    pcap_t *adhandle = pcap_open( device, 0x10000, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf  );
    if ( NULL == adhandle )
    {
        printf("[pcap_open error] : %s/n", errbuf);
        return 0;
    }

    while(1)
    if ( 0 != pcap_sendpacket(adhandle, (const unsigned char *)ucSend, datasize ) )
    {
        printf("send failed.\n");
    }
    else
    {
        printf("send success.\n");
    }
    system("pause");
    return 0;
}